from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from personal_agent.audit import AuditLogger
from personal_agent.economic.models import (
    BudgetUpdate,
    EconomicIntentCreate,
    FinalQuote,
    PayeeCreate,
    TransferIntentCreate,
)
from personal_agent.economic.store import EconomicStore
from personal_agent.economic.tools import economic_tools
from personal_agent.memory.models import EntityCreate
from personal_agent.memory.store import MemoryStore
from personal_agent.policy.engine import PolicyEngine
from personal_agent.storage import Storage
from personal_agent.tool_broker.broker import ToolBroker
from personal_agent.types import Channel


def _store(tmp_path: Path) -> tuple[EconomicStore, Storage, MemoryStore]:
    storage = Storage(tmp_path / "economic.sqlite3")
    storage.initialize()
    memory = MemoryStore(storage)
    memory.initialize()
    economic = EconomicStore(storage)
    economic.initialize()
    return economic, storage, memory


def _budget(store: EconomicStore, category: str, amount: str = "100000") -> None:
    store.upsert_budget(
        BudgetUpdate(
            category=category,
            per_action_limit=Decimal(amount),
            daily_limit=Decimal(amount),
            monthly_limit=Decimal(amount),
        )
    )


def test_purchase_requires_exact_quote_budget_balance_and_duplicate_check(
    tmp_path: Path,
) -> None:
    store, storage, _ = _store(tmp_path)
    _budget(store, "personal", "10000")
    store.set_sandbox_balance(currency="JPY", balance=Decimal("10000"))
    task = storage.create_task(
        user_id="primary",
        goal="purchase",
        source=Channel.WEB,
        conversation_id="economic",
    )
    intent = store.create_intent(
        task_id=task.task_id,
        intent=EconomicIntentCreate(
            action_type="purchase",
            target="product:coffee-filter:100",
            provider="shop-sandbox",
            amount=Decimal("1280"),
            conditions={"quantity": 1},
            cancellation_policy="30日返品可",
        ),
    )

    with pytest.raises(ValueError, match="exactly match"):
        store.set_final_quote(
            intent["economic_intent_id"],
            FinalQuote(
                item="Coffee filter 100",
                quantity=1,
                unit_price=Decimal("1000"),
                shipping=Decimal("280"),
                total=Decimal("1280"),
                seller="Sandbox Shop",
                cancellation_policy="30日返品可",
                cancellable=True,
                currency="USD",
                source_reference="sandbox://quote/invalid-currency",
            ),
        )

    quoted = store.set_final_quote(
        intent["economic_intent_id"],
        FinalQuote(
            item="Coffee filter 100",
            quantity=1,
            unit_price=Decimal("1000"),
            shipping=Decimal("280"),
            total=Decimal("1280"),
            seller="Sandbox Shop",
            delivery_at="2026-08-20",
            cancellation_policy="30日返品可",
            cancellable=True,
            source_reference="sandbox://quote/1",
        ),
    )
    assert quoted["execution_state"] == "POLICY_CHECKED"
    assert quoted["final_quote"]["seller"] == "Sandbox Shop"

    completed = store.execute_sandbox(
        task_id=task.task_id,
        intent_id=intent["economic_intent_id"],
        idempotency_key="purchase-idempotency-key",
    )
    assert completed["execution_state"] == "CONFIRMED"
    assert completed["evidence"]["verified"] is True
    assert store.sandbox_accounts()[0]["balance"] == "8720"

    duplicate_intent = store.create_intent(
        task_id=task.task_id,
        intent=EconomicIntentCreate(
            action_type="purchase",
            target="product:coffee-filter:100",
            provider="shop-sandbox",
            amount=Decimal("1280"),
        ),
    )
    store.set_final_quote(
        duplicate_intent["economic_intent_id"],
        FinalQuote(
            item="Coffee filter 100",
            unit_price=Decimal("1280"),
            total=Decimal("1280"),
            seller="Sandbox Shop",
            cancellation_policy="30日返品可",
            cancellable=True,
            source_reference="sandbox://quote/2",
        ),
    )
    with pytest.raises(PermissionError, match="duplicate"):
        store.execute_sandbox(
            task_id=task.task_id,
            intent_id=duplicate_intent["economic_intent_id"],
            idempotency_key="duplicate-purchase-key",
        )


def test_transfer_uses_exact_payee_limits_balance_idempotency_and_reconciliation(
    tmp_path: Path,
) -> None:
    store, storage, memory = _store(tmp_path)
    _budget(store, "money", "50000")
    store.set_sandbox_balance(currency="JPY", balance=Decimal("50000"))
    entity = memory.create_entity(
        user_id="primary",
        entity=EntityCreate(entity_type="person", canonical_name="山田太郎"),
    )
    payee = store.create_payee(
        PayeeCreate(
            payee_id="payee_yamada",
            display_name="山田太郎",
            aliases=["山田さん"],
            entity_id=entity["entity_id"],
            trusted=True,
            payment_route_ref="secret://money/yamada/route",
            per_transfer_limit=Decimal("10000"),
            daily_limit=Decimal("20000"),
            monthly_limit=Decimal("30000"),
        )
    )
    assert "payment_route_ref" not in payee
    task = storage.create_task(
        user_id="primary",
        goal="transfer",
        source=Channel.WEB,
        conversation_id="money",
    )
    intent = store.create_transfer_intent(
        task_id=task.task_id,
        transfer=TransferIntentCreate(
            payee_id="payee_yamada",
            amount=Decimal("3200"),
            purpose="立替精算",
        ),
    )
    transaction = store.execute_transfer_sandbox(
        task_id=task.task_id,
        intent_id=intent["economic_intent_id"],
        idempotency_key="transfer-idempotency-key",
    )
    duplicate = store.execute_transfer_sandbox(
        task_id=task.task_id,
        intent_id=intent["economic_intent_id"],
        idempotency_key="transfer-idempotency-key",
    )

    assert transaction["state"] == "CONFIRMED"
    assert duplicate["transaction_id"] == transaction["transaction_id"]
    assert store.sandbox_accounts()[0]["balance"] == "46800"
    reconciled = store.reconcile(transaction["transaction_id"])
    assert reconciled["matched"] is True
    assert reconciled["resent"] is False
    assert "payment_route_ref" not in str(transaction)

    with pytest.raises(PermissionError, match="non-JPY"):
        store.create_transfer_intent(
            task_id=task.task_id,
            transfer=TransferIntentCreate(
                payee_id="payee_yamada",
                amount=Decimal("100"),
                currency="USD",
                purpose="overseas denied",
            ),
        )


@pytest.mark.asyncio
async def test_finance_lock_blocks_all_economic_execution_before_store(tmp_path: Path) -> None:
    store, storage, _ = _store(tmp_path)
    task = storage.create_task(
        user_id="primary",
        goal="sandbox purchase",
        source=Channel.WEB,
        conversation_id="policy",
    )
    broker = ToolBroker(storage, PolicyEngine(storage), AuditLogger(storage))
    for definition in economic_tools(store):
        broker.register(definition)

    denied = await broker.execute(
        tool_name="economic.create_intent",
        arguments={
            "action_type": "purchase",
            "target": "item",
            "provider": "sandbox",
            "amount": "1000",
        },
        task_id=task.task_id,
        idempotency_key="finance-lock-test-key",
        dry_run=False,
        reason="verify finance lock",
        allowed_names={"economic.create_intent"},
        granted_permissions={"economic.prepare"},
    )

    assert denied.status == "denied"
    assert denied.evidence["reason_code"] == "FINANCE_LOCK_ENABLED"
    assert store.list_intents() == []
