from __future__ import annotations

import argparse
import getpass
import json

from ..browser_worker.config import BrowserWorkerSettings
from .models import SecretAction, SecretCreate, SecretKind
from .protection import protector_from_environment
from .store import SecretStore


def _store() -> SecretStore:
    settings = BrowserWorkerSettings.from_env()
    store = SecretStore(settings.secret_db_path, protector_from_environment())
    store.initialize()
    return store


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="personal-agent-secret",
        description=(
            "Manage encrypted Browser Worker credentials without exposing values to a model."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    put = commands.add_parser("put")
    put.add_argument("credential_id")
    put.add_argument("--kind", required=True, choices=[item.value for item in SecretKind])
    put.add_argument("--account-label", required=True)
    put.add_argument("--origin", action="append", required=True)
    put.add_argument(
        "--action",
        action="append",
        required=True,
        choices=[item.value for item in SecretAction],
    )
    commands.add_parser("list")
    disable = commands.add_parser("disable")
    disable.add_argument("credential_id")
    usage = commands.add_parser("usage")
    usage.add_argument("--limit", type=int, default=50)
    return parser


def run() -> None:
    args = _parser().parse_args()
    store = _store()
    if args.command == "put":
        value = getpass.getpass("Secret value (input is hidden): ")
        confirmation = getpass.getpass("Confirm secret value: ")
        if value != confirmation:
            raise SystemExit("Values did not match")
        metadata = store.put(
            SecretCreate(
                credential_id=args.credential_id,
                kind=SecretKind(args.kind),
                account_label=args.account_label,
                allowed_origins=args.origin,
                allowed_actions=[SecretAction(item) for item in args.action],
            ),
            value,
        )
        del value, confirmation
        print(json.dumps(metadata.model_dump(mode="json"), ensure_ascii=False, indent=2))
        return
    if args.command == "list":
        print(
            json.dumps(
                [item.model_dump(mode="json") for item in store.list_metadata()],
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if args.command == "disable":
        store.disable(args.credential_id)
        print(json.dumps({"status": "disabled", "credential_id": args.credential_id}))
        return
    print(json.dumps(store.usage(limit=max(1, min(args.limit, 1_000))), indent=2))


if __name__ == "__main__":
    run()
