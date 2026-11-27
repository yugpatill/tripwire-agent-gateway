"""playground runs

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-27

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "playground_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scenario_id", sa.String(length=100), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_playground_runs_created", "playground_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_playground_runs_created", table_name="playground_runs")
    op.drop_table("playground_runs")
