import os
from pathlib import Path
import secrets
import subprocess
import sys
import unittest


RUN_MYSQL_TESTS = os.environ.get("KARTE_TEST_MYSQL") == "1"


def load_project_env() -> dict[str, str]:
    values = dict(os.environ)
    path = Path(__file__).resolve().parents[1] / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    return values


@unittest.skipUnless(RUN_MYSQL_TESTS, "set KARTE_TEST_MYSQL=1 to run disposable MySQL integration tests")
class MySqlMigrationTests(unittest.TestCase):
    def test_clean_migration_and_lifecycle_probe(self):
        import pymysql
        from alembic import command
        from alembic.config import Config
        from sqlalchemy import create_engine, inspect
        from sqlalchemy.engine import URL

        project_root = Path(__file__).resolve().parents[1]
        env = load_project_env()
        database = f"karte_migration_test_{secrets.token_hex(4)}"
        host = env.get("MYSQL_HOST", "127.0.0.1")
        port = int(env.get("MYSQL_PORT", "3306"))
        user = env.get("MYSQL_TEST_ADMIN_USER") or env.get("MYSQL_USER", "voucher_app")
        password = env.get("MYSQL_TEST_ADMIN_PASSWORD") or env.get("MYSQL_PASSWORD", "")

        server = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            charset="utf8mb4",
            autocommit=True,
        )
        engine = None
        database_created = False
        try:
            try:
                with server.cursor() as cursor:
                    cursor.execute(f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                database_created = True
            except pymysql.err.OperationalError as exc:
                if exc.args and exc.args[0] == 1044:
                    self.skipTest("set MYSQL_TEST_ADMIN_USER and MYSQL_TEST_ADMIN_PASSWORD for disposable database privileges")
                raise

            url = URL.create(
                "mysql+pymysql",
                username=user,
                password=password,
                host=host,
                port=port,
                database=database,
                query={"charset": "utf8mb4"},
            )
            engine = create_engine(url, pool_pre_ping=True)
            config = Config(str(project_root / "alembic.ini"))
            with engine.begin() as connection:
                config.attributes["connection"] = connection
                command.upgrade(config, "head")

            inspector = inspect(engine)
            expected_tables = {
                "alembic_version",
                "users",
                "routers",
                "packages",
                "voucher_batches",
                "vouchers",
                "sales",
                "audit_logs",
                "reconciliation_issues",
                "wireguard_interfaces",
                "router_sessions",
                "router_login_attempts",
            }
            self.assertTrue(expected_tables.issubset(set(inspector.get_table_names())))
            voucher_columns = {column["name"] for column in inspector.get_columns("vouchers")}
            self.assertTrue({"last_error", "retry_count"}.issubset(voucher_columns))
            login_columns = {
                column["name"]
                for column in inspector.get_columns("router_login_attempts")
            }
            self.assertIn("scope", login_columns)
            self.assertNotIn("app_users", inspector.get_table_names())

            child_env = dict(env)
            child_env.update(
                {
                    "APP_ENV": "testing",
                    "DB_ENGINE": "mysql",
                    "MYSQL_DATABASE": database,
                    "ENABLE_BACKGROUND_SYNC": "0",
                    "SECRET_KEY": "mysql-integration-secret-key-at-least-32-characters",
                    "KARTE_ADMIN_PASSWORD": "",
                }
            )
            completed = subprocess.run(
                [sys.executable, str(project_root / "tests" / "mysql_lifecycle_probe.py")],
                cwd=project_root,
                env=child_env,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        finally:
            if engine is not None:
                engine.dispose()
            if database_created:
                with server.cursor() as cursor:
                    cursor.execute(f"DROP DATABASE IF EXISTS `{database}`")
            server.close()
