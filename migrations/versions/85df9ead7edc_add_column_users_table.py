"""add column users table

Revision ID: 85df9ead7edc
Revises: e6c843f8a7a4
Create Date: 2021-10-28 13:47:04.521153

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "85df9ead7edc"
down_revision = "e6c843f8a7a4"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users", sa.Column("current_connection_time", sa.DateTime(), nullable=True)
    )
    op.alter_column(
        "users", "uuid", existing_type=sa.VARCHAR(length=36), nullable=False
    )


def downgrade():
    op.alter_column("users", "uuid", existing_type=sa.VARCHAR(length=36), nullable=True)
    op.drop_column("users", "current_connection_time")
