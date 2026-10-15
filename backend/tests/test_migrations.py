from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from app.db.migrations import TRACEABILITY_REVISION, apply_traceability_migration


def _fresh_engine():
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE attack_responses "
                "(id INTEGER PRIMARY KEY, prompt_id VARCHAR(100) NOT NULL, "
                "prompt_text TEXT NOT NULL, request_payload TEXT NOT NULL)"
            )
        )
    return engine


def test_traceability_migration_handles_fresh_and_existing_schema() -> None:
    engine = _fresh_engine()
    with engine.begin() as connection:
        assert apply_traceability_migration(connection) is True
        columns = {column["name"] for column in inspect(connection).get_columns("attack_responses")}
        assert {
            "test_case_id",
            "error_type",
            "outcome",
            "completion_metadata",
            "test_metadata",
        } <= columns
        connection.execute(
            text(
                "INSERT INTO attack_responses "
                "(id, prompt_id, prompt_text, request_payload, test_case_id, "
                "error_type, outcome, completion_metadata, test_metadata) "
                "VALUES (1, 'p1', 'prompt', '{}', 'case-1', 'provider_timeout', "
                "'INCONCLUSIVE', '{\"complete\": null}', '{\"expected\": \"refusal\"}')"
            )
        )
        assert apply_traceability_migration(connection) is False
        row = connection.execute(
            text(
                "SELECT test_case_id, error_type, outcome, completion_metadata, test_metadata "
                "FROM attack_responses WHERE id = 1"
            )
        ).one()
        assert row.test_case_id == "case-1"
        assert row.error_type == "provider_timeout"
        assert row.outcome == "INCONCLUSIVE"
        assert row.completion_metadata == '{"complete": null}'
        assert row.test_metadata == '{"expected": "refusal"}'
        assert connection.execute(
            text("SELECT revision FROM schema_migrations")
        ).scalar_one() == TRACEABILITY_REVISION


def test_traceability_migration_rejects_missing_existing_table() -> None:
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        try:
            apply_traceability_migration(connection)
        except RuntimeError as exc:
            assert "attack_responses does not exist" in str(exc)
        else:
            raise AssertionError("migration should reject a missing attack_responses table")
