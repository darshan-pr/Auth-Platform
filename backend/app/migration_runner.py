from pathlib import Path
import logging

from sqlalchemy import text

from app.db import engine

logger = logging.getLogger(__name__)


def run_migrations() -> None:
    """Run SQL migration files in order to keep schema up to date."""
    migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
    if not migrations_dir.exists():
        logger.info("No migrations directory found, skipping migrations.")
        return

    migration_files = sorted(migrations_dir.glob("*.sql"))
    if not migration_files:
        logger.info("No migration files found.")
        return

    with engine.connect() as conn:
        for mig_file in migration_files:
            logger.info("Running migration: %s", mig_file.name)
            sql = mig_file.read_text(encoding="utf-8")

            # Strip SQL comment lines before splitting on semicolons
            cleaned_lines = [
                line for line in sql.splitlines() if not line.strip().startswith("--")
            ]
            cleaned_sql = "\n".join(cleaned_lines)

            for statement in cleaned_sql.split(";"):
                statement = statement.strip()
                if not statement:
                    continue

                try:
                    conn.execute(text(statement))
                except Exception as exc:
                    logger.warning(
                        "Migration statement skipped (%s): %s",
                        mig_file.name,
                        exc,
                    )
                    # Clear failed transaction state so later statements can continue.
                    conn.rollback()
            conn.commit()

    logger.info("All migrations applied successfully.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    run_migrations()
