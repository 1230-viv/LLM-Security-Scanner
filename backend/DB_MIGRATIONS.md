# Database migrations

The application does not modify the database schema during startup. Run the
explicit migration command after deploying code that adds schema fields.

## Execution traceability migration

Configure `DATABASE_URL` in `backend/.env`, then run:

```bash
cd backend
/home/zoro/miniconda3/bin/python -m app.db.migrate
```

The command creates the base tables on a fresh database, adds the execution
traceability fields to an existing `attack_responses` table, and records the
revision in `schema_migrations`. It is safe to run repeatedly; an already
applied revision is reported and makes no changes.

Added fields:

- `test_case_id`
- `outcome`
- `error_type`
- `completion_metadata`
- `test_metadata`

Existing rows are preserved. New non-null fields use empty metadata objects
and `COMPLETED` as the compatibility default for existing successful records.

## Recovery and rollback

Back up the database before applying the migration. For PostgreSQL:

```bash
pg_dump "$DATABASE_URL" > before-traceability-migration.sql
```

Rollback is deliberately explicit because it removes only the five added
columns and their values:

```bash
cd backend
/home/zoro/miniconda3/bin/python - <<'PY'
import asyncio

from app.db.migrations import rollback_traceability_migration
from app.db.session import engine

async def rollback():
    async with engine.begin() as connection:
        await connection.run_sync(rollback_traceability_migration)

asyncio.run(rollback())
PY
```

Restore the backup instead if the migration must be fully reverted. The
repository migration tests cover an empty/fresh `attack_responses` schema,
existing rows, idempotent re-execution, and rejection when the required table
is absent:

```bash
cd backend
/home/zoro/miniconda3/bin/python -m pytest tests/test_migrations.py -q
```
