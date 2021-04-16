"""create post table

Revision ID: 2309b4b4411e
Revises: 2d92ec9d3c66
Create Date: 2020-12-24 19:45:32.279097

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "2309b4b4411e"
down_revision = "2d92ec9d3c66"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "posts",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("title", sa.String(), nullable=True),
        sa.Column("body", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], onupdate="CASCADE", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("posts")
