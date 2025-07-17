"""
Database initialization utilities
"""

from sqlalchemy.orm import Session
from app.models.permission import Permission
from app.core.logger import get_logger

logger = get_logger(__name__)


def initialize_database(db: Session) -> bool:
    """
    Initialize the database with default data.
    This function should be called during application startup.
    
    Args:
        db: Database session
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info("Initializing database with default data...")
        
        # Initialize default permissions
        Permission.create_default_permissions(db)
        
        logger.info("Database initialization completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        db.rollback()
        return False


def ensure_permissions_exist(db: Session) -> bool:
    """
    Ensure all default permissions exist in the database.
    This is a lightweight check that can be called frequently.
    
    Args:
        db: Database session
        
    Returns:
        bool: True if all permissions exist, False otherwise
    """
    try:
        default_perms = Permission.default_permissions()
        existing_count = db.query(Permission).count()
        
        if existing_count < len(default_perms):
            logger.info("Some permissions are missing, creating them...")
            Permission.create_default_permissions(db)
            return True
        
        return True
        
    except Exception as e:
        logger.error(f"Error checking permissions: {str(e)}")
        return False
