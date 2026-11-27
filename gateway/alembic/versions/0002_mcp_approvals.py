"""mcp proxy: approval kinds and details, operator keys

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-27

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "approvals", sa.Column("kind", sa.String(length=32), server_default="call", nullable=False)
    )
    op.add_column(
        "approvals",
        sa.Column(
            "detail", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
    )
    op.alter_column("approvals", "event_id", existing_type=sa.UUID(), nullable=True)
    op.alter_column("approvals", "session_id", existing_type=sa.UUID(), nullable=True)
    op.create_index("ix_approvals_kind_tool", "approvals", ["kind", "tool"])
    op.add_column(
        "api_keys", sa.Column("role", sa.String(length=16), server_default="agent", nullable=False)
    )


def downgrade() -> None:
    op.drop_column("api_keys", "role")
    op.drop_index("ix_approvals_kind_tool", table_name="approvals")
    op.execute("DELETE FROM approvals WHERE event_id IS NULL OR session_id IS NULL")
    op.alter_column("approvals", "session_id", existing_type=sa.UUID(), nullable=False)
    op.alter_column("approvals", "event_id", existing_type=sa.UUID(), nullable=False)
    op.drop_column("approvals", "detail")
    op.drop_column("approvals", "kind")
