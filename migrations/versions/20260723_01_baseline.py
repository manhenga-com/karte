"""Create the Karte MySQL schema.

Revision ID: 20260723_01
Revises:
Create Date: 2026-07-23
"""

from alembic import op
from sqlalchemy import inspect

from models import METADATA


revision = "20260723_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())

    for table in METADATA.sorted_tables:
        if table.name not in existing_tables:
            table.create(bind=bind)
            existing_tables.add(table.name)
            continue

        existing_columns = {
            column["name"]
            for column in inspect(bind).get_columns(table.name)
        }
        for column in table.columns:
            if column.name not in existing_columns:
                op.add_column(table.name, column.copy())

    for table in METADATA.sorted_tables:
        inspector = inspect(bind)
        existing_indexes = {
            index["name"]
            for index in inspector.get_indexes(table.name)
            if index.get("name")
        }
        existing_unique = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints(table.name)
            if constraint.get("name")
        }
        for index in table.indexes:
            if index.name not in existing_indexes:
                op.create_index(
                    index.name,
                    table.name,
                    [column.name for column in index.columns],
                    unique=index.unique,
                )
        for constraint in table.constraints:
            if (
                constraint.__class__.__name__ == "UniqueConstraint"
                and constraint.name
                and constraint.name not in existing_unique
                and constraint.name not in existing_indexes
            ):
                op.create_unique_constraint(
                    constraint.name,
                    table.name,
                    [column.name for column in constraint.columns],
                )


def downgrade() -> None:
    bind = op.get_bind()
    for table in reversed(METADATA.sorted_tables):
        table.drop(bind=bind, checkfirst=True)
