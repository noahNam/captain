"""create_users_jwts_blacklists_tables

Revision ID: e6c843f8a7a4
Revises: 
Create Date: 2021-06-29 11:38:33.492492

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "e6c843f8a7a4"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("uuid", sa.String(length=36), nullable=True),
        sa.Column("provider", sa.String(length=10), nullable=False),
        sa.Column("provider_id", sa.String(length=256), nullable=False),
        sa.Column("group", sa.SmallInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "blacklists",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("access_token", sa.String(length=280), nullable=False),
        sa.Column("expired_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "jwts",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("access_token", sa.String(length=280), nullable=False),
        sa.Column("refresh_token", sa.String(length=280), nullable=False),
        sa.Column("access_expired_at", sa.DateTime(), nullable=False),
        sa.Column("refresh_expired_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"],),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("jwts")
    op.drop_table("blacklists")
    op.drop_table("users")
