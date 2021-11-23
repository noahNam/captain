"""alter_timezone_tables

Revision ID: 01b8d3489c53
Revises: 85df9ead7edc
Create Date: 2021-11-23 15:22:45.798172

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '01b8d3489c53'
down_revision = '85df9ead7edc'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "users",
        "created_at",
        existing_type=sa.DateTime(),
        type_=postgresql.TIMESTAMP(timezone=True),
    )
    op.alter_column(
        "users",
        "updated_at",
        existing_type=sa.DateTime(),
        type_=postgresql.TIMESTAMP(timezone=True),
        onupdate=sa.func.now(),
    )
    op.alter_column(
        "users",
        "current_connection_time",
        existing_type=sa.DateTime(),
        type_=postgresql.TIMESTAMP(timezone=True),
        server_default=sa.text('now()'),
        nullable=False,
        onupdate=sa.func.now(),
    )


def downgrade():
    op.alter_column(
        "users",
        "updated_at",
        existing_type=postgresql.TIMESTAMP(timezone=True),
        type_=sa.DateTime(),
    )
    op.alter_column(
        "users",
        "updated_at",
        existing_type=postgresql.TIMESTAMP(timezone=True),
        type_=sa.DateTime(),
    )
    op.alter_column(
        "users",
        "current_connection_time",
        existing_type=postgresql.TIMESTAMP(timezone=True),
        type_=sa.DateTime(),
        nullable=True
    )

