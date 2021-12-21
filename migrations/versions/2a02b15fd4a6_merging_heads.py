"""merging heads

Revision ID: 2a02b15fd4a6
Revises: a64605ed513c, 01b8d3489c53
Create Date: 2021-12-21 12:36:19.652269

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "2a02b15fd4a6"
down_revision = ("a64605ed513c", "01b8d3489c53")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
