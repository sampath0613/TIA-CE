"""add score history and ioc graph tables

Revision ID: f9d2b3d4e5f6
Revises: abcf27a8eb3f
Create Date: 2026-04-01 19:00:00.000000

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "f9d2b3d4e5f6"
down_revision = "abcf27a8eb3f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Apply schema upgrades."""
    op.create_table(
        "ioc_score_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ioc_id", sa.Uuid(), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_ioc_score_history_ioc_id"),
        "ioc_score_history",
        ["ioc_id"],
        unique=False,
    )

    op.create_table(
        "alert_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_alert_id", sa.String(length=255), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alert_events_external_alert_id"),
        "alert_events",
        ["external_alert_id"],
        unique=True,
    )

    op.create_table(
        "ioc_graph_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ioc_left_id", sa.Uuid(), nullable=False),
        sa.Column("ioc_right_id", sa.Uuid(), nullable=False),
        sa.Column("cooccurrence_count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["ioc_left_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ioc_right_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("ioc_left_id", "ioc_right_id", name="uq_ioc_graph_edge_pair"),
    )
    op.create_index("ix_ioc_graph_edges_left", "ioc_graph_edges", ["ioc_left_id"], unique=False)
    op.create_index("ix_ioc_graph_edges_right", "ioc_graph_edges", ["ioc_right_id"], unique=False)


def downgrade() -> None:
    """Revert schema upgrades."""
    op.drop_index("ix_ioc_graph_edges_right", table_name="ioc_graph_edges")
    op.drop_index("ix_ioc_graph_edges_left", table_name="ioc_graph_edges")
    op.drop_table("ioc_graph_edges")

    op.drop_index(op.f("ix_alert_events_external_alert_id"), table_name="alert_events")
    op.drop_table("alert_events")

    op.drop_index(op.f("ix_ioc_score_history_ioc_id"), table_name="ioc_score_history")
    op.drop_table("ioc_score_history")
