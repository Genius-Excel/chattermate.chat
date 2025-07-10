"""add_teamid_to_agent_sessions

Revision ID: 0cf5fa1db0cb
Revises: 91a148726029
Create Date: 2025-03-21 13:57:55.161703

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0cf5fa1db0cb'
down_revision: Union[str, None] = '91a148726029'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add extra_data column to ai.agent_sessions table
    op.add_column('agent_sessions', 
        sa.Column('team_id', sa.UUID(), nullable=True),
        schema='ai'
    )


def downgrade() -> None:
    # Drop extra_data column from ai.agent_sessions table
    op.drop_column('agent_sessions', 'team_id', schema='ai')
