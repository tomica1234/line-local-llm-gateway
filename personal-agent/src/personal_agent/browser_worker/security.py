from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from .models import BrowserProfile

_SAFE_SUFFIX = re.compile(r"^\.[A-Za-z0-9]{1,10}$")
_DANGEROUS_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".dll",
    ".exe",
    ".hta",
    ".js",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbs",
}
_SECRET_NAMES = {".env", ".netrc", "id_rsa", "id_ed25519", "credentials.json"}
_SECRET_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".kdbx"}


def normalize_hostname(hostname: str) -> str:
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL hostname is invalid") from exc


def host_is_allowed(hostname: str, allowlist: tuple[str, ...]) -> bool:
    normalized = normalize_hostname(hostname)
    for allowed in allowlist:
        candidate = normalize_hostname(allowed)
        if normalized == candidate or normalized.endswith(f".{candidate}"):
            return True
    return False


def validate_navigation_url(
    url: str,
    *,
    profile: BrowserProfile,
    finance_allowlist: tuple[str, ...],
    allow_private_navigation: bool = False,
) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https navigation is allowed")
    if parsed.username or parsed.password:
        raise ValueError("Credentials embedded in URLs are forbidden")
    if not parsed.hostname:
        raise ValueError("Navigation URL must include a hostname")
    hostname = normalize_hostname(parsed.hostname)
    if not allow_private_navigation:
        _reject_private_hostname(hostname)
    if profile is BrowserProfile.FINANCE:
        if not finance_allowlist:
            raise ValueError("Finance profile is locked until an allowlist is configured")
        if not host_is_allowed(hostname, finance_allowlist):
            raise ValueError("Finance profile navigation denied by domain allowlist")
    return url


def validate_resolved_hostname(hostname: str) -> None:
    normalized = normalize_hostname(hostname)
    _reject_private_hostname(normalized)
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError("Navigation hostname could not be resolved") from exc
    if not addresses:
        raise ValueError("Navigation hostname has no resolved address")
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("Navigation to private or special-use networks is forbidden")


def validate_upload_path(value: str, roots: tuple[Path, ...]) -> Path:
    if not roots:
        raise PermissionError("Browser uploads are disabled until upload roots are configured")
    path = Path(value).resolve(strict=True)
    allowed_roots = tuple(root.resolve(strict=True) for root in roots)
    if not any(path.is_relative_to(root) for root in allowed_roots):
        raise PermissionError("Upload path is outside configured upload roots")
    lowered_parts = {part.casefold() for part in path.parts}
    if (
        path.name.casefold() in _SECRET_NAMES
        or path.suffix.casefold() in _SECRET_SUFFIXES
        or ".ssh" in lowered_parts
        or ".gnupg" in lowered_parts
    ):
        raise PermissionError("Secret and key files cannot be uploaded")
    if not path.is_file():
        raise ValueError("Upload path must be a regular file")
    return path


def _reject_private_hostname(hostname: str) -> None:
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".lan", ".internal")):
        raise ValueError("Navigation to local network names is forbidden")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("Navigation to private or special-use networks is forbidden")


def quarantine_path(root: Path, profile: BrowserProfile, suggested_filename: str) -> Path:
    suffix = Path(suggested_filename).suffix
    normalized_suffix = suffix.lower()
    safe_suffix = (
        normalized_suffix
        if _SAFE_SUFFIX.fullmatch(suffix) and normalized_suffix not in _DANGEROUS_SUFFIXES
        else ".bin"
    )
    directory = root / profile.value
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory / f"{uuid4()}{safe_suffix}"
