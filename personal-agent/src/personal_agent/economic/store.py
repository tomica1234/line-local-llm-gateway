from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from ..memory.sanitizer import sanitize_payload, sanitize_text
from ..storage import Storage, utc_now
from ..types import RiskLevel
from .models import (
    BudgetUpdate,
    EconomicIntentCreate,
    ExecutionState,
    FinalQuote,
    PayeeCreate,
    TransferIntentCreate,
)

ECONOMIC_SCHEMA = """
CREATE TABLE IF NOT EXISTS economic_intents (
    economic_intent_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    provider TEXT NOT NULL,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    budget TEXT NOT NULL,
    conditions_json TEXT NOT NULL,
    cancellation_policy TEXT NOT NULL,
    payment_method_ref TEXT,
    risk_level TEXT NOT NULL,
    approval_state TEXT NOT NULL,
    execution_state TEXT NOT NULL,
    final_quote_json TEXT,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS budgets (
    category TEXT NOT NULL,
    currency TEXT NOT NULL,
    per_action_limit TEXT NOT NULL,
    daily_limit TEXT NOT NULL,
    monthly_limit TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(category, currency)
);
CREATE TABLE IF NOT EXISTS payees (
    payee_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    aliases_json TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    trusted INTEGER NOT NULL,
    payment_route_ref TEXT NOT NULL,
    per_transfer_limit TEXT NOT NULL,
    daily_limit TEXT NOT NULL,
    monthly_limit TEXT NOT NULL,
    last_verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    economic_intent_id TEXT,
    transaction_type TEXT NOT NULL,
    payee_id TEXT,
    amount TEXT NOT NULL,
    currency TEXT NOT NULL,
    state TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    external_id TEXT,
    evidence_json TEXT NOT NULL,
    submitted_at TEXT,
    confirmed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transactions_period
ON transactions(state, currency, created_at);
CREATE TABLE IF NOT EXISTS sandbox_accounts (
    account_id TEXT PRIMARY KEY,
    currency TEXT NOT NULL,
    balance TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class EconomicStore:
    def __init__(self, storage: Storage):
        self.storage = storage

    def initialize(self) -> None:
        with self.storage.transaction() as connection:
            connection.executescript(ECONOMIC_SCHEMA)
            connection.execute(
                "INSERT OR IGNORE INTO sandbox_accounts(account_id, currency, balance, updated_at) "
                "VALUES ('dedicated', 'JPY', '0', ?)",
                (utc_now(),),
            )

    def create_intent(self, *, task_id: str, intent: EconomicIntentCreate) -> dict[str, Any]:
        safe_target, _ = sanitize_text(intent.target)
        safe_conditions, _ = sanitize_payload(intent.conditions)
        safe_cancellation, _ = sanitize_text(intent.cancellation_policy)
        intent_id = str(uuid.uuid4())
        now = utc_now()
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO economic_intents "
                "(economic_intent_id, task_id, action_type, target, provider, amount, currency, "
                "budget, conditions_json, cancellation_policy, payment_method_ref, risk_level, "
                "approval_state, execution_state, evidence_json, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'CREATED', '{}', ?, ?)",
                (
                    intent_id,
                    task_id,
                    intent.action_type.value,
                    safe_target,
                    intent.provider,
                    str(intent.amount),
                    intent.currency,
                    intent.budget,
                    json.dumps(safe_conditions, ensure_ascii=False),
                    safe_cancellation,
                    intent.payment_method_ref,
                    intent.risk_level.value,
                    now,
                    now,
                ),
            )
        return self.intent(intent_id)

    def intent(self, intent_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM economic_intents WHERE economic_intent_id = ?", (intent_id,)
            ).fetchone()
        if row is None:
            raise KeyError(intent_id)
        return self._intent(row)

    def set_final_quote(self, intent_id: str, quote: FinalQuote) -> dict[str, Any]:
        current = self.intent(intent_id)
        if current["execution_state"] not in {"CREATED", "RESOLVED", "POLICY_CHECKED"}:
            raise ValueError("Economic intent cannot accept a final quote in its current state")
        if quote.currency != current["currency"] or quote.total != Decimal(current["amount"]):
            raise ValueError("Final quote must exactly match intent amount and currency")
        self.assert_budget(category=current["budget"], currency=quote.currency, amount=quote.total)
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE economic_intents SET final_quote_json=?, cancellation_policy=?, "
                "execution_state='POLICY_CHECKED', updated_at=? WHERE economic_intent_id=?",
                (
                    json.dumps(quote.model_dump(mode="json"), ensure_ascii=False),
                    quote.cancellation_policy,
                    utc_now(),
                    intent_id,
                ),
            )
        return self.intent(intent_id)

    def execute_sandbox(
        self, *, task_id: str, intent_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        intent = self.intent(intent_id)
        if intent["task_id"] != task_id:
            raise PermissionError("Intent is owned by another task")
        if intent["execution_state"] == ExecutionState.CONFIRMED.value:
            return intent
        if intent["execution_state"] != ExecutionState.POLICY_CHECKED.value:
            raise ValueError("Final quote and budget policy must be checked before execution")
        if intent["action_type"] in {"purchase", "subscribe"}:
            self._assert_no_duplicate_purchase(intent)
        transaction_id = str(uuid.uuid4())
        external_id = f"sandbox-{intent['action_type']}-{uuid.uuid4()}"
        now = utc_now()
        evidence = {
            "provider": "sandbox",
            "external_id": external_id,
            "confirmation": "sandbox_completion_record",
            "verified": True,
            "final_quote": intent["final_quote"],
        }
        with self.storage.transaction() as connection:
            account = connection.execute(
                "SELECT balance FROM sandbox_accounts WHERE account_id='dedicated' AND currency=?",
                (intent["currency"],),
            ).fetchone()
            amount = Decimal(intent["amount"])
            if account is None or Decimal(account["balance"]) < amount:
                raise PermissionError("Dedicated sandbox balance is insufficient")
            connection.execute(
                "UPDATE sandbox_accounts SET balance=?, updated_at=? "
                "WHERE account_id='dedicated' AND currency=?",
                (str(Decimal(account["balance"]) - amount), now, intent["currency"]),
            )
            connection.execute(
                "INSERT INTO transactions "
                "(transaction_id, task_id, economic_intent_id, transaction_type, amount, "
                "currency, state, idempotency_key, external_id, evidence_json, submitted_at, "
                "confirmed_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'CONFIRMED', ?, ?, ?, ?, ?, ?, ?)",
                (
                    transaction_id,
                    task_id,
                    intent_id,
                    intent["action_type"],
                    intent["amount"],
                    intent["currency"],
                    idempotency_key,
                    external_id,
                    json.dumps(evidence, ensure_ascii=False),
                    now,
                    now,
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE economic_intents SET approval_state='approved', "
                "execution_state='CONFIRMED', evidence_json=?, updated_at=? "
                "WHERE economic_intent_id=?",
                (json.dumps(evidence, ensure_ascii=False), now, intent_id),
            )
        return self.intent(intent_id)

    def upsert_budget(self, budget: BudgetUpdate) -> dict[str, Any]:
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO budgets(category, currency, per_action_limit, daily_limit, "
                "monthly_limit, updated_at) VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(category, currency) DO UPDATE SET "
                "per_action_limit=excluded.per_action_limit, daily_limit=excluded.daily_limit, "
                "monthly_limit=excluded.monthly_limit, updated_at=excluded.updated_at",
                (
                    budget.category,
                    budget.currency,
                    str(budget.per_action_limit),
                    str(budget.daily_limit),
                    str(budget.monthly_limit),
                    utc_now(),
                ),
            )
        return self.budget(budget.category, budget.currency)

    def budget(self, category: str, currency: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM budgets WHERE category=? AND currency=?", (category, currency)
            ).fetchone()
        if row is None:
            raise PermissionError("No budget is configured; economic action is denied")
        return dict(row)

    def assert_budget(self, *, category: str, currency: str, amount: Decimal) -> None:
        budget = self.budget(category, currency)
        if amount > Decimal(budget["per_action_limit"]):
            raise PermissionError("Per-action budget exceeded")
        now = datetime.now(UTC)
        day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT amount, created_at FROM transactions WHERE state='CONFIRMED' "
                "AND currency=? AND created_at>=?",
                (currency, month_start.isoformat()),
            ).fetchall()
        monthly = sum((Decimal(row["amount"]) for row in rows), Decimal("0"))
        daily = sum(
            (Decimal(row["amount"]) for row in rows if row["created_at"] >= day_start.isoformat()),
            Decimal("0"),
        )
        if daily + amount > Decimal(budget["daily_limit"]):
            raise PermissionError("Daily budget exceeded")
        if monthly + amount > Decimal(budget["monthly_limit"]):
            raise PermissionError("Monthly budget exceeded")

    def list_budgets(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM budgets ORDER BY category, currency"
            ).fetchall()
        return [dict(row) for row in rows]

    def create_payee(self, payee: PayeeCreate) -> dict[str, Any]:
        now = utc_now()
        with self.storage.transaction() as connection:
            entity = connection.execute(
                "SELECT entity_id FROM entities WHERE entity_id=?", (payee.entity_id,)
            ).fetchone()
            if entity is None:
                raise ValueError("Payee must reference an existing resolved entity")
            connection.execute(
                "INSERT INTO payees(payee_id, display_name, aliases_json, entity_id, trusted, "
                "payment_route_ref, per_transfer_limit, daily_limit, monthly_limit, "
                "last_verified_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    payee.payee_id,
                    payee.display_name,
                    json.dumps(payee.aliases, ensure_ascii=False),
                    payee.entity_id,
                    int(payee.trusted),
                    payee.payment_route_ref,
                    str(payee.per_transfer_limit),
                    str(payee.daily_limit),
                    str(payee.monthly_limit),
                    now if payee.trusted else None,
                    now,
                    now,
                ),
            )
        return self.payee(payee.payee_id)

    def payee(self, payee_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT payee_id, display_name, aliases_json, entity_id, trusted, "
                "per_transfer_limit, daily_limit, monthly_limit, last_verified_at, created_at, "
                "updated_at FROM payees WHERE payee_id=?",
                (payee_id,),
            ).fetchone()
        if row is None:
            raise KeyError(payee_id)
        result = dict(row)
        result["aliases"] = json.loads(result.pop("aliases_json"))
        result["trusted"] = bool(result["trusted"])
        return result

    def list_payees(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT payee_id FROM payees ORDER BY display_name"
            ).fetchall()
        return [self.payee(row["payee_id"]) for row in rows]

    def create_transfer_intent(
        self, *, task_id: str, transfer: TransferIntentCreate
    ) -> dict[str, Any]:
        payee = self.payee(transfer.payee_id)
        if not payee["trusted"]:
            raise PermissionError("New or untrusted payee requires strong approval")
        self._assert_payee_limits(payee, transfer.amount, transfer.currency)
        self.assert_budget(category="money", currency=transfer.currency, amount=transfer.amount)
        intent = EconomicIntentCreate(
            action_type="transfer",
            target=transfer.payee_id,
            provider="money-sandbox",
            amount=transfer.amount,
            currency=transfer.currency,
            budget="money",
            conditions={"purpose": transfer.purpose},
            cancellation_policy="Transfer is irreversible after submission",
            risk_level=RiskLevel.R3,
        )
        result = self.create_intent(task_id=task_id, intent=intent)
        with self.storage.transaction() as connection:
            connection.execute(
                "UPDATE economic_intents SET execution_state='POLICY_CHECKED', "
                "final_quote_json=? WHERE economic_intent_id=?",
                (
                    json.dumps(
                        {
                            "payee_id": transfer.payee_id,
                            "amount": str(transfer.amount),
                            "currency": transfer.currency,
                            "fee": "0",
                            "purpose": transfer.purpose,
                            "provider": "money-sandbox",
                        },
                        ensure_ascii=False,
                    ),
                    result["economic_intent_id"],
                ),
            )
        return self.intent(result["economic_intent_id"])

    def execute_transfer_sandbox(
        self, *, task_id: str, intent_id: str, idempotency_key: str
    ) -> dict[str, Any]:
        intent = self.intent(intent_id)
        if intent["action_type"] != "transfer" or intent["task_id"] != task_id:
            raise PermissionError("Invalid transfer intent")
        payee = self.payee(intent["target"])
        amount = Decimal(intent["amount"])
        self._assert_payee_limits(payee, amount, intent["currency"])
        with self.storage.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM transactions WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                return self._transaction(existing)
            account = connection.execute(
                "SELECT balance FROM sandbox_accounts WHERE account_id='dedicated' AND currency=?",
                (intent["currency"],),
            ).fetchone()
            if account is None or Decimal(account["balance"]) < amount:
                raise PermissionError("Dedicated sandbox account balance is insufficient")
            now = utc_now()
            transaction_id = str(uuid.uuid4())
            external_id = f"sandbox-transfer-{uuid.uuid4()}"
            evidence = {
                "provider": "money-sandbox",
                "payee_id": payee["payee_id"],
                "amount": str(amount),
                "currency": intent["currency"],
                "fee": "0",
                "external_id": external_id,
                "verified": True,
            }
            connection.execute(
                "UPDATE sandbox_accounts SET balance=?, updated_at=? "
                "WHERE account_id='dedicated' AND currency=?",
                (str(Decimal(account["balance"]) - amount), now, intent["currency"]),
            )
            connection.execute(
                "INSERT INTO transactions(transaction_id, task_id, economic_intent_id, "
                "transaction_type, payee_id, amount, currency, state, idempotency_key, "
                "external_id, evidence_json, submitted_at, confirmed_at, created_at, updated_at) "
                "VALUES (?, ?, ?, 'transfer', ?, ?, ?, 'CONFIRMED', ?, ?, ?, ?, ?, ?, ?)",
                (
                    transaction_id,
                    task_id,
                    intent_id,
                    payee["payee_id"],
                    str(amount),
                    intent["currency"],
                    idempotency_key,
                    external_id,
                    json.dumps(evidence, ensure_ascii=False),
                    now,
                    now,
                    now,
                    now,
                ),
            )
            connection.execute(
                "UPDATE economic_intents SET approval_state='approved', "
                "execution_state='CONFIRMED', evidence_json=?, updated_at=? "
                "WHERE economic_intent_id=?",
                (json.dumps(evidence), now, intent_id),
            )
            row = connection.execute(
                "SELECT * FROM transactions WHERE transaction_id=?", (transaction_id,)
            ).fetchone()
        return self._transaction(row)

    def reconcile(self, transaction_id: str) -> dict[str, Any]:
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM transactions WHERE transaction_id=?", (transaction_id,)
            ).fetchone()
        if row is None:
            raise KeyError(transaction_id)
        transaction = self._transaction(row)
        evidence = transaction["evidence"]
        matched = all(
            (
                evidence.get("external_id") == transaction["external_id"],
                evidence.get("amount") == transaction["amount"],
                evidence.get("currency") == transaction["currency"],
                evidence.get("payee_id") == transaction["payee_id"],
            )
        )
        return {"matched": matched, "transaction": transaction, "resent": False}

    def list_intents(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM economic_intents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._intent(row) for row in rows]

    def list_transactions(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM transactions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._transaction(row) for row in rows]

    def sandbox_accounts(self) -> list[dict[str, Any]]:
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM sandbox_accounts ORDER BY account_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def set_sandbox_balance(self, *, currency: str, balance: Decimal) -> None:
        if balance < 0:
            raise ValueError("Sandbox balance cannot be negative")
        with self.storage.transaction() as connection:
            connection.execute(
                "INSERT INTO sandbox_accounts(account_id, currency, balance, updated_at) "
                "VALUES ('dedicated', ?, ?, ?) ON CONFLICT(account_id) DO UPDATE SET "
                "currency=excluded.currency, balance=excluded.balance, "
                "updated_at=excluded.updated_at",
                (currency, str(balance), utc_now()),
            )

    def _assert_no_duplicate_purchase(self, intent: dict[str, Any]) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        with self.storage.read_connection() as connection:
            row = connection.execute(
                "SELECT economic_intent_id FROM economic_intents WHERE target=? "
                "AND action_type=? AND execution_state='CONFIRMED' AND created_at>=? LIMIT 1",
                (intent["target"], intent["action_type"], cutoff),
            ).fetchone()
        if row:
            raise PermissionError("Potential duplicate purchase detected")

    def _assert_payee_limits(self, payee: dict[str, Any], amount: Decimal, currency: str) -> None:
        if currency != "JPY":
            raise PermissionError("Overseas/non-JPY transfers are denied")
        if amount > Decimal(payee["per_transfer_limit"]):
            raise PermissionError("Payee per-transfer limit exceeded")
        now = datetime.now(UTC)
        day = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat()
        with self.storage.read_connection() as connection:
            rows = connection.execute(
                "SELECT amount, created_at FROM transactions WHERE payee_id=? "
                "AND state='CONFIRMED' AND created_at>=?",
                (payee["payee_id"], month),
            ).fetchall()
        monthly = sum((Decimal(row["amount"]) for row in rows), Decimal("0"))
        daily = sum(
            (Decimal(row["amount"]) for row in rows if row["created_at"] >= day),
            Decimal("0"),
        )
        if daily + amount > Decimal(payee["daily_limit"]):
            raise PermissionError("Payee daily limit exceeded")
        if monthly + amount > Decimal(payee["monthly_limit"]):
            raise PermissionError("Payee monthly limit exceeded")

    @staticmethod
    def _intent(row: Any) -> dict[str, Any]:
        result = dict(row)
        result["conditions"] = json.loads(result.pop("conditions_json"))
        final_quote = result.pop("final_quote_json")
        result["final_quote"] = json.loads(final_quote) if final_quote else None
        result["evidence"] = json.loads(result.pop("evidence_json"))
        return result

    @staticmethod
    def _transaction(row: Any) -> dict[str, Any]:
        result = dict(row)
        result["evidence"] = json.loads(result.pop("evidence_json"))
        return result
