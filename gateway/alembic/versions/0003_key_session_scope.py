"""per-key MCP session scope

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-27

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("session_scope", sa.String(length=16), server_default="key", nullable=False),
    )
    op.add_column(
        "api_keys",
        sa.Column(
            "session_scope_forced", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_column("api_keys", "session_scope_forced")
    op.drop_column("api_keys", "session_scope")
