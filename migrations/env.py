from logging.config import fileConfig
import os
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import URL

from models import METADATA


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = METADATA


def include_schema_object(_object, _name, object_type, reflected, compare_to):
    # Karte keeps a few proven operational indexes outside model metadata.
    # Alembic should not propose dropping those indexes during drift checks.
    if object_type == "index" and reflected and compare_to is None:
        return False
    return True


def load_env_file() -> None:
    path = Path(__file__).resolve().parents[1] / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def database_url() -> str:
    load_env_file()
    return URL.create(
        "mysql+pymysql",
        username=os.environ.get("MYSQL_USER", "voucher_app"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        host=os.environ.get("MYSQL_HOST", "127.0.0.1"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        database=os.environ.get("MYSQL_DATABASE", "mikrotik_vouchers"),
        query={"charset": "utf8mb4"},
    ).render_as_string(hide_password=False)


def run_migrations_offline() -> None:
    context.configure(
        url=database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=False,
        include_object=include_schema_object,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    supplied_connection = config.attributes.get("connection")
    if supplied_connection is not None:
        context.configure(
            connection=supplied_connection,
            target_metadata=target_metadata,
            compare_type=False,
            include_object=include_schema_object,
        )
        with context.begin_transaction():
            context.run_migrations()
        return

    config.set_main_option("sqlalchemy.url", database_url().replace("%", "%%"))
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=False,
            include_object=include_schema_object,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
