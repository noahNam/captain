"""alter_timezone_tables

Revision ID: a64605ed513c
Revises: 85df9ead7edc
Create Date: 2021-11-22 15:21:34.085183

"""
from alembic import op
import sqlalchemy as sa

from app.extensions.utils.time_helper import (
    get_jwt_access_expired_timestamp,
    get_jwt_refresh_expired_timestamp,
)

revision = "a64605ed513c"
down_revision = "85df9ead7edc"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "users",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        nullable=False,
        onupdate=sa.func.now(),
    )
    op.alter_column(
        "users",
        "current_connection_time",
        existing_type=sa.DateTime(timezone=True),
        nullable=True,
        onupdate=sa.func.now(),
    )


def downgrade():
    op.alter_column(
        "users",
        "updated_at",
        existing_type=sa.DateTime,
        nullable=False,
        server_default=sa.func.now(),
    )
    op.alter_column(
        "users", "current_connection_time", existing_type=sa.DateTime, nullable=True
    )
