"""Explicit, repeatable database migrations.

Run with ``python -m app.db.migrate`` after configuring DATABASE_URL.
Migrations are intentionally not run during application startup.
"""

from __future__ import annotations

from sqlalchemy import Connection, inspect, text

TRACEABILITY_REVISION = "20261016_execution_traceability"


def _column_definitions(dialect: str) -> dict[str, str]:
    json_type = "JSONB" if dialect == "postgresql" else "TEXT"
    return {
        "test_case_id": "VARCHAR(100)",
        "error_type": "VARCHAR(50)",
        "outcome": "VARCHAR(30) NOT NULL DEFAULT 'COMPLETED'",
        "completion_metadata": f"{json_type} NOT NULL DEFAULT '{{}}'",
        "test_metadata": f"{json_type} NOT NULL DEFAULT '{{}}'",
    }


def apply_traceability_migration(connection: Connection) -> bool:
    """Apply the execution traceability revision and return whether it changed schema."""
    inspector = inspect(connection)
    if "schema_migrations" not in inspector.get_table_names():
        connection.execute(
            text(
                "CREATE TABLE schema_migrations "
                "(revision VARCHAR(100) PRIMARY KEY, applied_at TIMESTAMP NOT NULL)"
            )
        )

    applied = connection.execute(
        text("SELECT 1 FROM schema_migrations WHERE revision = :revision"),
        {"revision": TRACEABILITY_REVISION},
    ).scalar_one_or_none()
    if applied:
        return False

    tables = set(inspect(connection).get_table_names())
    if "attack_responses" not in tables:
        raise RuntimeError(
            "Cannot apply execution traceability migration: attack_responses does not exist"
        )

    existing_columns = {
        column["name"] for column in inspect(connection).get_columns("attack_responses")
    }
    for name, definition in _column_definitions(connection.dialect.name).items():
        if name not in existing_columns:
            connection.execute(
                text(f"ALTER TABLE attack_responses ADD COLUMN {name} {definition}")
            )

    connection.execute(
        text(
            "INSERT INTO schema_migrations (revision, applied_at) "
            "VALUES (:revision, CURRENT_TIMESTAMP)"
        ),
        {"revision": TRACEABILITY_REVISION},
    )
    return True


def rollback_traceability_migration(connection: Connection) -> None:
    """Rollback is manual and destructive to only the added columns.

    Take a database backup first. Existing attack response rows are preserved,
    but values stored in these five columns are removed.
    """
    if connection.dialect.name not in {"postgresql", "sqlite"}:
        raise RuntimeError(f"Unsupported rollback dialect: {connection.dialect.name}")
    columns = _column_definitions(connection.dialect.name)
    for name in reversed(tuple(columns)):
        connection.execute(text(f"ALTER TABLE attack_responses DROP COLUMN {name}"))
    connection.execute(
        text("DELETE FROM schema_migrations WHERE revision = :revision"),
        {"revision": TRACEABILITY_REVISION},
    )
