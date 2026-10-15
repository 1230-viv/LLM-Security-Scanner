from __future__ import annotations

import asyncio

from app.db.base import Base
from app.db.migrations import apply_traceability_migration
from app.db.session import engine


async def main() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        changed = await connection.run_sync(apply_traceability_migration)
    print("execution traceability migration applied" if changed else "migration already applied")


if __name__ == "__main__":
    asyncio.run(main())
