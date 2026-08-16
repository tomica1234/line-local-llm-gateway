from __future__ import annotations

import mimetypes
import shutil
from pathlib import Path
from uuid import uuid4

_SECRET_NAMES = {
    ".env",
    ".netrc",
    "credentials.json",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
}
_SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".kdbx"}


class FileService:
    def __init__(self, roots: tuple[Path, ...], trash_root: Path):
        self.roots = tuple(root.resolve() for root in roots)
        self.trash_root = trash_root.resolve()

    def search(self, query: str, *, limit: int = 100) -> list[dict[str, object]]:
        normalized = query.casefold().strip()
        if not normalized or not self.roots:
            return []
        results: list[dict[str, object]] = []
        for root in self.roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if len(results) >= limit:
                    return results
                if not path.is_file() or self._is_secret(path):
                    continue
                if normalized in path.name.casefold():
                    results.append(self.metadata(path))
        return results

    def read(self, value: str, *, max_bytes: int = 1_000_000) -> dict[str, object]:
        path = self._resolve(value, must_exist=True)
        self._deny_secret(path)
        if not path.is_file():
            raise ValueError("Path is not a regular file")
        if path.stat().st_size > max_bytes:
            raise ValueError("File exceeds the bounded read size")
        media_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if not (
            media_type.startswith("text/")
            or path.suffix.lower() in {".json", ".md", ".csv", ".yaml", ".yml"}
        ):
            raise ValueError("Binary file extraction is not enabled for this type")
        content = path.read_text(encoding="utf-8", errors="replace")
        return {**self.metadata(path), "content": content, "trust_level": "untrusted"}

    def copy(self, source: str, destination: str) -> dict[str, object]:
        source_path = self._resolve(source, must_exist=True)
        destination_path = self._resolve(destination, must_exist=False)
        self._deny_secret(source_path)
        self._prepare_destination(destination_path)
        shutil.copy2(source_path, destination_path)
        return self.metadata(destination_path)

    def move(self, source: str, destination: str) -> dict[str, object]:
        source_path = self._resolve(source, must_exist=True)
        destination_path = self._resolve(destination, must_exist=False)
        self._deny_secret(source_path)
        self._prepare_destination(destination_path)
        shutil.move(str(source_path), str(destination_path))
        return self.metadata(destination_path)

    def rename(self, source: str, name: str) -> dict[str, object]:
        if Path(name).name != name or name in {".", ".."}:
            raise ValueError("Rename accepts a filename, not a path")
        source_path = self._resolve(source, must_exist=True)
        return self.move(str(source_path), str(source_path.with_name(name)))

    def delete_to_trash(self, value: str) -> dict[str, object]:
        path = self._resolve(value, must_exist=True)
        self._deny_secret(path)
        self.trash_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self.trash_root / f"{uuid4()}-{path.name}"
        shutil.move(str(path), str(target))
        return {
            "original_path": str(path),
            "trash_path": str(target),
            "recoverable": True,
        }

    def metadata(self, path: Path) -> dict[str, object]:
        resolved = path.resolve(strict=True)
        self._assert_allowed(resolved)
        stat = resolved.stat()
        return {
            "path": str(resolved),
            "name": resolved.name,
            "size": stat.st_size,
            "modified_at": stat.st_mtime,
            "media_type": mimetypes.guess_type(resolved.name)[0],
        }

    def _resolve(self, value: str, *, must_exist: bool) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            if len(self.roots) != 1:
                raise ValueError("Relative paths require exactly one configured file root")
            candidate = self.roots[0] / candidate
        resolved = candidate.resolve(strict=False)
        self._assert_allowed(resolved)
        if must_exist and not resolved.exists():
            raise FileNotFoundError(resolved)
        return resolved

    def _assert_allowed(self, path: Path) -> None:
        if not self.roots or not any(
            path == root or path.is_relative_to(root) for root in self.roots
        ):
            raise PermissionError("Path is outside configured file roots")

    @staticmethod
    def _prepare_destination(path: Path) -> None:
        if path.exists():
            raise FileExistsError("Destination already exists")
        path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _is_secret(path: Path) -> bool:
        lowered_parts = {part.casefold() for part in path.parts}
        return (
            path.name.casefold() in _SECRET_NAMES
            or path.suffix.casefold() in _SECRET_SUFFIXES
            or ".ssh" in lowered_parts
            or ".gnupg" in lowered_parts
        )

    @classmethod
    def _deny_secret(cls, path: Path) -> None:
        if cls._is_secret(path):
            raise PermissionError("Secret/key files are excluded from agent file access")
