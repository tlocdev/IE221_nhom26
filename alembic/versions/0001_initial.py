"""Initial schema — create_all on startup covers SQLite demo; Alembic for Postgres evolutions."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("normalized_url", sa.Text(), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("risk_level", sa.String(32), nullable=True),
        sa.Column("ml_probability", sa.Float(), nullable=True),
        sa.Column("rule_score", sa.Integer(), nullable=True),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
    )
    op.create_table(
        "scan_features",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), unique=True),
        sa.Column("schema_version", sa.String(16)),
        sa.Column("features", sa.JSON()),
    )
    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id")),
        sa.Column("type", sa.String(64)),
        sa.Column("severity", sa.String(16)),
        sa.Column("description", sa.Text()),
        sa.Column("source", sa.String(32)),
    )
    op.create_table(
        "blacklist_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("source", sa.String(64)),
        sa.Column("detected_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("blacklist_entries")
    op.drop_table("scan_findings")
    op.drop_table("scan_features")
    op.drop_table("scans")
