#!/usr/bin/env python3
"""
Initialize default permissions in the database.
This script can be run independently to ensure all default permissions exist.
"""

import sys
import os

# Add the backend directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import SessionLocal
from app.models.permission import Permission


def main():
    """Initialize default permissions"""
    print("Initializing default permissions...")
    
    # Create database session
    db = SessionLocal()
    
    try:
        # Create default permissions
        success = Permission.create_default_permissions(db)
        
        if success:
            print("✅ Default permissions initialized successfully!")
        else:
            print("❌ Failed to initialize default permissions")
            return 1
            
    except Exception as e:
        print(f"❌ Error initializing permissions: {str(e)}")
        db.rollback()
        return 1
    finally:
        db.close()
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
