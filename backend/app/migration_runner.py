from __future__ import annotations

from pathlib import Path
import hashlib
import logging
from typing import Dict, List

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.db import engine

logger = logging.getLogger(__name__)

_MIGRATIONS_TABLE = "schema_migrations"
_MIGRATION_LOCK_KEY = 84543123


def _discover_migrations() -> List[Path]:
    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    if not migrations_dir.exists():
        logger.info("No migrations directory found, skipping migrations.")
        return []

    migration_files = sorted(migrations_dir.glob("*.sql"))
    if not migration_files:
        logger.info("No migration files found.")
    return migration_files


def _ensure_migrations_table(conn: Connection) -> None:
    conn.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS {_MIGRATIONS_TABLE} (
                version VARCHAR(255) PRIMARY KEY,
                checksum VARCHAR(64) NOT NULL,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
    )


def _load_applied_migrations(conn: Connection) -> Dict[str, str]:
    rows = conn.execute(
        text(f"SELECT version, checksum FROM {_MIGRATIONS_TABLE}")
    ).all()
    return {str(version): str(checksum) for version, checksum in rows}


def _checksum(sql: str) -> str:
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def _split_sql_statements(sql: str) -> List[str]:
    """
    Split SQL into executable statements while respecting quoted sections.

    Supports:
    - single-quoted strings (including escaped '')
    - double-quoted identifiers (including escaped "")
    - line comments and block comments
    - PostgreSQL dollar-quoted blocks (e.g. DO $$ ... $$;)
    """
    statements: List[str] = []
    buffer: List[str] = []
    length = len(sql)
    i = 0

    in_single_quote = False
    in_double_quote = False
    in_line_comment = False
    in_block_comment = False
    dollar_tag: str | None = None

    while i < length:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < length else ""

        if in_line_comment:
            buffer.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            buffer.append(ch)
            if ch == "*" and nxt == "/":
                buffer.append(nxt)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue

        if dollar_tag:
            if sql.startswith(dollar_tag, i):
                buffer.append(dollar_tag)
                i += len(dollar_tag)
                dollar_tag = None
                continue
            buffer.append(ch)
            i += 1
            continue

        if in_single_quote:
            buffer.append(ch)
            if ch == "'" and nxt == "'":
                buffer.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single_quote = False
            i += 1
            continue

        if in_double_quote:
            buffer.append(ch)
            if ch == '"' and nxt == '"':
                buffer.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double_quote = False
            i += 1
            continue

        if ch == "-" and nxt == "-":
            buffer.append(ch)
            buffer.append(nxt)
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            buffer.append(ch)
            buffer.append(nxt)
            in_block_comment = True
            i += 2
            continue

        if ch == "$":
            tag_end = i + 1
            while tag_end < length and (sql[tag_end].isalnum() or sql[tag_end] == "_"):
                tag_end += 1
            if tag_end < length and sql[tag_end] == "$":
                tag = sql[i : tag_end + 1]
                dollar_tag = tag
                buffer.append(tag)
                i = tag_end + 1
                continue

        if ch == "'":
            in_single_quote = True
            buffer.append(ch)
            i += 1
            continue

        if ch == '"':
            in_double_quote = True
            buffer.append(ch)
            i += 1
            continue

        if ch == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            i += 1
            continue

        buffer.append(ch)
        i += 1

    trailing = "".join(buffer).strip()
    if trailing:
        statements.append(trailing)

    return statements


def _apply_migration_file(mig_file: Path, checksum: str) -> None:
    sql = mig_file.read_text(encoding="utf-8")
    statements = _split_sql_statements(sql)
    if not statements:
        logger.info("Skipping empty migration file: %s", mig_file.name)
        return

    with engine.begin() as conn:
        _ensure_migrations_table(conn)
        for statement in statements:
            conn.execute(text(statement))

        conn.execute(
            text(
                f"INSERT INTO {_MIGRATIONS_TABLE} (version, checksum) "
                "VALUES (:version, :checksum)"
            ),
            {"version": mig_file.name, "checksum": checksum},
        )


def _acquire_migration_lock(conn: Connection) -> None:
    if conn.dialect.name != "postgresql":
        return
    conn.execute(
        text("SELECT pg_advisory_lock(:lock_key)"),
        {"lock_key": _MIGRATION_LOCK_KEY},
    )


def _release_migration_lock(conn: Connection) -> None:
    if conn.dialect.name != "postgresql":
        return
    conn.execute(
        text("SELECT pg_advisory_unlock(:lock_key)"),
        {"lock_key": _MIGRATION_LOCK_KEY},
    )


def run_migrations() -> None:
    """Run SQL migration files in order with strict, fail-fast behavior."""
    migration_files = _discover_migrations()
    if not migration_files:
        return

    with engine.connect() as lock_conn:
        _acquire_migration_lock(lock_conn)
        try:
            with engine.begin() as conn:
                _ensure_migrations_table(conn)
                applied = _load_applied_migrations(conn)

            for mig_file in migration_files:
                sql = mig_file.read_text(encoding="utf-8")
                file_checksum = _checksum(sql)
                existing_checksum = applied.get(mig_file.name)

                if existing_checksum:
                    if existing_checksum != file_checksum:
                        raise RuntimeError(
                            "Migration checksum mismatch for "
                            f"{mig_file.name}. Applied={existing_checksum}, current={file_checksum}."
                        )
                    logger.info("Skipping already applied migration: %s", mig_file.name)
                    continue

                logger.info("Applying migration: %s", mig_file.name)
                _apply_migration_file(mig_file, file_checksum)
                applied[mig_file.name] = file_checksum

            logger.info("Database migrations are up to date.")
        finally:
            _release_migration_lock(lock_conn)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run_migrations()
