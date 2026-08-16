from __future__ import annotations

import argparse
import json
from decimal import Decimal
from pathlib import Path

from ..config import Settings
from ..memory import MemoryStore
from ..storage import Storage
from .models import BudgetUpdate, PayeeCreate
from .store import EconomicStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="personal-agent-sandbox")
    commands = parser.add_subparsers(dest="command", required=True)
    balance = commands.add_parser("set-balance")
    balance.add_argument("amount", type=Decimal)
    balance.add_argument("--currency", default="JPY")
    budget = commands.add_parser("set-budget")
    budget.add_argument("category")
    budget.add_argument("--currency", default="JPY")
    budget.add_argument("--per-action", required=True, type=Decimal)
    budget.add_argument("--daily", required=True, type=Decimal)
    budget.add_argument("--monthly", required=True, type=Decimal)
    payee = commands.add_parser("add-payee")
    payee.add_argument("payee_id")
    payee.add_argument("--display-name", required=True)
    payee.add_argument("--entity-id", required=True)
    payee.add_argument("--route-ref", required=True)
    payee.add_argument("--per-transfer", required=True, type=Decimal)
    payee.add_argument("--daily", required=True, type=Decimal)
    payee.add_argument("--monthly", required=True, type=Decimal)
    payee.add_argument("--trusted", action="store_true")
    return parser


def run() -> None:
    args = _parser().parse_args()
    settings = Settings.from_env()
    storage = Storage(Path(settings.db_path))
    storage.initialize()
    MemoryStore(storage).initialize()
    store = EconomicStore(storage)
    store.initialize()
    confirmation = input("This changes the sandbox only. Type SANDBOX to continue: ")
    if confirmation != "SANDBOX":
        raise SystemExit("Cancelled")
    if args.command == "set-balance":
        store.set_sandbox_balance(currency=args.currency, balance=args.amount)
        result = {"status": "ok", "sandbox": True}
    elif args.command == "set-budget":
        result = store.upsert_budget(
            BudgetUpdate(
                category=args.category,
                currency=args.currency,
                per_action_limit=args.per_action,
                daily_limit=args.daily,
                monthly_limit=args.monthly,
            )
        )
    else:
        result = store.create_payee(
            PayeeCreate(
                payee_id=args.payee_id,
                display_name=args.display_name,
                entity_id=args.entity_id,
                trusted=args.trusted,
                payment_route_ref=args.route_ref,
                per_transfer_limit=args.per_transfer,
                daily_limit=args.daily,
                monthly_limit=args.monthly,
            )
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    run()
