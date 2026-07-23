"""Remove legacy SaaS schema and harden login tracking.

Revision ID: 20260723_02
Revises: 20260723_01
Create Date: 2026-07-23
"""

from __future__ import annotations

from datetime import datetime
import re

from alembic import op
from sqlalchemy import Column, String, inspect, text


revision = "20260723_02"
down_revision = "20260723_01"
branch_labels = None
depends_on = None


def _table_names(bind) -> set[str]:
    return set(inspect(bind).get_table_names())


def _column_names(bind, table: str) -> set[str]:
    return {column["name"] for column in inspect(bind).get_columns(table)}


def _index_names(bind, table: str) -> set[str]:
    return {
        index["name"]
        for index in inspect(bind).get_indexes(table)
        if index.get("name")
    }


def _timestamp(value) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text_value = str(value or "").strip()
    return text_value[:19] or datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _migrate_legacy_users(bind) -> None:
    if "app_users" not in _table_names(bind):
        return

    columns = _column_names(bind, "app_users")
    required = {"id", "password_hash"}
    if not required.issubset(columns):
        raise RuntimeError("Legacy app_users table has an unknown shape; migrate it manually before deployment.")

    selected = [
        name
        for name in ("id", "name", "email", "password_hash", "is_admin", "role", "created_at", "updated_at")
        if name in columns
    ]
    rows = bind.execute(text(f"SELECT {', '.join(selected)} FROM app_users ORDER BY id")).mappings().all()
    taken = {
        str(row[0]).lower()
        for row in bind.execute(text("SELECT username FROM users")).all()
    }

    for row in rows:
        source = str(row.get("name") or "").strip() or str(row.get("email") or "").split("@", 1)[0]
        base = re.sub(r"[^A-Za-z0-9_.-]", "-", source).strip(".-_")
        if len(base) < 3:
            base = f"legacy-{row['id']}"
        base = base[:64]
        username = base
        suffix = 1
        while username.lower() in taken:
            tail = f"-{suffix}"
            username = f"{base[:64 - len(tail)]}{tail}"
            suffix += 1
        taken.add(username.lower())

        role = str(row.get("role") or "").strip().lower()
        is_admin = str(row.get("is_admin") or "0").strip().lower() in {"1", "true", "yes"}
        role = "admin" if role == "admin" or is_admin else "cashier"
        created_at = _timestamp(row.get("created_at"))
        updated_at = _timestamp(row.get("updated_at") or created_at)
        bind.execute(
            text(
                """
                INSERT INTO users
                    (username, password_hash, role, active, last_login_at, created_at, updated_at)
                VALUES
                    (:username, :password_hash, :role, 1, '', :created_at, :updated_at)
                """
            ),
            {
                "username": username,
                "password_hash": str(row.get("password_hash") or ""),
                "role": role,
                "created_at": created_at,
                "updated_at": updated_at,
            },
        )


def _drop_owner_column(bind, table: str) -> None:
    if table not in _table_names(bind) or "owner_user_id" not in _column_names(bind, table):
        return

    inspector = inspect(bind)
    for foreign_key in inspector.get_foreign_keys(table):
        if "owner_user_id" in (foreign_key.get("constrained_columns") or []) and foreign_key.get("name"):
            op.drop_constraint(foreign_key["name"], table, type_="foreignkey")
    for index in inspector.get_indexes(table):
        if "owner_user_id" in (index.get("column_names") or []) and index.get("name"):
            op.drop_index(index["name"], table_name=table)
    op.drop_column(table, "owner_user_id")


def upgrade() -> None:
    bind = op.get_bind()
    tables = _table_names(bind)

    if "router_login_attempts" in tables:
        columns = _column_names(bind, "router_login_attempts")
        if "scope" not in columns:
            op.add_column(
                "router_login_attempts",
                Column(
                    "scope",
                    String(32),
                    nullable=False,
                    server_default="router",
                ),
            )
        indexes = _index_names(bind, "router_login_attempts")
        if "idx_router_login_attempts_client_time" in indexes:
            op.drop_index("idx_router_login_attempts_client_time", table_name="router_login_attempts")
        if "idx_router_login_attempts_scope_client_time" not in indexes:
            op.create_index(
                "idx_router_login_attempts_scope_client_time",
                "router_login_attempts",
                ["scope", "client_key", "attempted_at"],
            )

    _migrate_legacy_users(bind)
    _drop_owner_column(bind, "routers")
    _drop_owner_column(bind, "wireguard_interfaces")

    if "wireguard_interfaces" in _table_names(bind):
        columns = {
            column["name"]: column
            for column in inspect(bind).get_columns("wireguard_interfaces")
        }
        created_at = columns.get("created_at")
        if created_at:
            bind.execute(
                text(
                    """
                    UPDATE wireguard_interfaces
                    SET created_at = DATE_FORMAT(
                        COALESCE(created_at, CURRENT_TIMESTAMP),
                        '%Y-%m-%d %H:%i:%s'
                    )
                    """
                )
            )
            op.alter_column(
                "wireguard_interfaces",
                "created_at",
                existing_type=created_at["type"],
                type_=String(19),
                nullable=False,
            )

    if "app_users" in _table_names(bind):
        op.drop_table("app_users")

    if "router_sessions" in _table_names(bind):
        bind.execute(
            text("DELETE FROM router_sessions WHERE expires_at <= :now"),
            {"now": datetime.now().timestamp()},
        )


def downgrade() -> None:
    raise RuntimeError("20260723_02 is intentionally irreversible because it removes legacy SaaS tables.")
