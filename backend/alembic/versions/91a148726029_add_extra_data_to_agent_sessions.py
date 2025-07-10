"""add extra_data to agent_sessions

Revision ID: 91a148726029
Revises: f3dad24474e0
Create Date: 2024-03-21 10:57:23.123456

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '91a148726029'
down_revision: Union[str, None] = 'f3dad24474e0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add extra_data column to ai.agent_sessions table
    op.add_column('agent_sessions', 
        sa.Column('extra_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        schema='ai'
    )


def downgrade() -> None:
    # Drop extra_data column from ai.agent_sessions table
    op.drop_column('agent_sessions', 'extra_data', schema='ai')
