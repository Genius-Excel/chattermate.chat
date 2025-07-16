"""add_default_permissions

Revision ID: b40e850ee735
Revises: 48147d01fb43
Create Date: 2025-07-16 17:34:47.484348

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b40e850ee735'
down_revision: Union[str, None] = '48147d01fb43'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Insert default permissions into the permissions table"""
    # Create a connection to execute raw SQL
    connection = op.get_bind()
    
    # Define default permissions
    default_permissions = [
        ("view_all", "Can view all resources"),
        ("manage_users", "Can manage users"),
        ("manage_roles", "Can manage roles"),
        ("manage_agents", "Can manage chat agents"),
        ("view_agents", "Can view chat agents"),
        ("view_analytics", "Can view analytics"),
        ("view_assigned_chats", "Can view assigned chats only"),
        ("manage_assigned_chats", "Can manage assigned chats"),
        ("manage_knowledge", "Can manage knowledge base"),
        ("view_knowledge", "Can view knowledge base"),
        ("manage_ai_config", "Can manage AI configuration"),
        ("view_ai_config", "Can view AI configuration"),
        ("view_all_chats", "Can view all chat history"),
        ("manage_all_chats", "Can manage all chat sessions"),
        ("manage_organization", "Can manage organization settings"),
        ("view_organization", "Can view organization details"),
        ("manage_subscription", "Can manage subscription plans and billing"),
        ("view_subscription", "Can view subscription details"),
        ("super_admin", "Has all permissions")
    ]
    
    # Insert permissions only if they don't already exist
    for name, description in default_permissions:
        # Check if permission already exists
        result = connection.execute(
            sa.text("SELECT COUNT(*) FROM permissions WHERE name = :name"),
            {"name": name}
        ).scalar()
        
        if result == 0:
            # Insert the permission
            connection.execute(
                sa.text("INSERT INTO permissions (name, description) VALUES (:name, :description)"),
                {"name": name, "description": description}
            )
            print(f"Inserted permission: {name}")
        else:
            print(f"Permission already exists: {name}")


def downgrade() -> None:
    """Remove default permissions from the permissions table"""
    # Create a connection to execute raw SQL
    connection = op.get_bind()
    
    # Define default permissions to remove
    default_permission_names = [
        "view_all", "manage_users", "manage_roles", "manage_agents", "view_agents",
        "view_analytics", "view_assigned_chats", "manage_assigned_chats", 
        "manage_knowledge", "view_knowledge", "manage_ai_config", "view_ai_config",
        "view_all_chats", "manage_all_chats", "manage_organization", "view_organization",
        "manage_subscription", "view_subscription", "super_admin"
    ]
    
    # Remove permissions
    for name in default_permission_names:
        connection.execute(
            sa.text("DELETE FROM permissions WHERE name = :name"),
            {"name": name}
        )
        print(f"Removed permission: {name}")
