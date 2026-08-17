from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

MigrationHandler = Callable[[sqlite3.Connection], None]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: MigrationHandler


def column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def add_column(connection: sqlite3.Connection, table: str, declaration: str) -> None:
    name = declaration.split(maxsplit=1)[0]
    if name not in column_names(connection, table):
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {declaration}")


def apply_migrations(
    connection: sqlite3.Connection,
    *,
    component: str,
    migrations: Sequence[Migration],
) -> None:
    """Apply ordered, idempotent SQLite migrations for one bounded component."""

    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "component TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, "
        "applied_at TEXT NOT NULL, PRIMARY KEY(component, version))"
    )
    applied = {
        int(row["version"])
        for row in connection.execute(
            "SELECT version FROM schema_migrations WHERE component=?", (component,)
        ).fetchall()
    }
    previous = 0
    for migration in sorted(migrations, key=lambda item: item.version):
        if migration.version <= previous:
            raise ValueError(f"Migration versions must increase for {component}")
        previous = migration.version
        if migration.version in applied:
            continue
        migration.apply(connection)
        connection.execute(
            "INSERT INTO schema_migrations(component, version, name, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (component, migration.version, migration.name, _now()),
        )
