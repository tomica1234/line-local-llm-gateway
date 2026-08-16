from __future__ import annotations

import argparse
import json
from pathlib import Path

from .backup import EncryptedBackupService
from .browser_worker.config import BrowserWorkerSettings
from .config import Settings
from .secret.protection import protector_from_environment


def _database_path(kind: str) -> Path:
    if kind == "core":
        return Settings.from_env().db_path
    return BrowserWorkerSettings.from_env().secret_db_path


def run() -> None:
    parser = argparse.ArgumentParser(
        prog="personal-agent-backup",
        description="Create, inspect, or restore a user-bound encrypted SQLite backup.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("destination", type=Path)
    create.add_argument("--database", choices=("core", "secret"), default="core")
    inspect_command = commands.add_parser("inspect")
    inspect_command.add_argument("backup", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--database", choices=("core", "secret"), default="core")
    restore.add_argument("--replace", action="store_true")
    restore.add_argument("--confirm-replace", default="")
    args = parser.parse_args()
    service = EncryptedBackupService(protector_from_environment())
    if args.command == "create":
        result = service.create(_database_path(args.database), args.destination)
    elif args.command == "inspect":
        result = service.inspect(args.backup)
    else:
        if args.replace and args.confirm_replace != "RESTORE":
            raise SystemExit("--replace requires --confirm-replace RESTORE")
        result = service.restore(
            args.backup,
            _database_path(args.database),
            replace=args.replace,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
