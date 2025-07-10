"""
ChatterMate - Cors
Copyright (C) 2024 ChatterMate

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

import json
import os
import time
import asyncio
from typing import Set, List
from functools import lru_cache
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logger import get_logger

logger = get_logger(__name__)

# Base CORS origins that are always allowed
BASE_CORS_ORIGINS: list = settings.CORS_ORIGINS

@lru_cache(maxsize=1)
def get_cors_origins() -> Set[str]:
    """
    Get all allowed CORS origins including organization domains.
    This function is cached to improve performance.
    """
    from app.repositories.organization import OrganizationRepository
    from app.database import SessionLocal

    # Start with base origins
    all_origins = set(BASE_CORS_ORIGINS)

    # Add organization domains
    try:
        db = SessionLocal()
        org_repo = OrganizationRepository(db)
        orgs = org_repo.get_active_organizations()
        
        for org in orgs:
            # Add both http and https variants
            all_origins.add(f"https://{org.domain}")
            all_origins.add(f"http://{org.domain}")
            # Add www subdomain variants
            all_origins.add(f"https://www.{org.domain}")
            all_origins.add(f"http://www.{org.domain}")
    except Exception as e:
        logger.error(f"Error fetching organization domains: {e}")
    finally:
        if 'db' in locals():
            db.close()

    return all_origins

def refresh_cors_origins() -> None:
    """
    Clear the CORS origins cache to force a refresh
    """
    get_cors_origins.cache_clear()

def update_local_cors(app: FastAPI, new_origins: List[str]) -> bool:
    """
    Update local CORS middleware with new origins
    
    Args:
        app: FastAPI application instance
        new_origins: List of CORS origins to set
        
    Returns:
        bool: True if CORS middleware was found and updated, False otherwise
    """
    middleware_found = False
    
    # First try standard FastAPI middleware structure
    if hasattr(app, 'user_middleware'):
        for middleware in app.user_middleware:
            logger.debug(f"Middleware: {middleware}")
            if isinstance(middleware.cls, CORSMiddleware):
                logger.debug(f"Updating CORS origins: {new_origins}")
                middleware.cls.options['allow_origins'] = new_origins
                logger.info(f"Updated FastAPI CORS origins: {new_origins}")
                middleware_found = True
                break
    
    # If middleware not found, try rebuilding the middleware stack
    if not middleware_found:
        logger.warning("Could not find CORS middleware in app.user_middleware, applying global update")
        try:
            # Force FastAPI to rebuild the middleware stack
            app.middleware_stack = None
            # Re-add the middleware with updated origins
            app.add_middleware(
                CORSMiddleware,
                allow_origins=new_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
            logger.info(f"Added new CORS middleware with origins: {new_origins}")
            middleware_found = True
        except Exception as e:
            logger.error(f"Failed to rebuild middleware stack: {str(e)}")
    
    # Update Socket.IO CORS settings
    try:
        from app.core.socketio import sio
        sio.eio.cors_allowed_origins = new_origins
        logger.info(f"Updated Socket.IO CORS origins: {new_origins}")
    except Exception as e:
        logger.error(f"Failed to update Socket.IO CORS origins: {str(e)}")
    
    return middleware_found

def update_cors_middleware(app: FastAPI) -> None:
    """
    Update the CORS middleware with new origins and notify all workers
    """
    logger.info("Refreshing CORS origins")
    
    # Get fresh CORS origins
    refresh_cors_origins()
    new_origins = list(get_cors_origins())
    
    # Update local instance
    update_local_cors(app, new_origins)
    
    # Store updated origins in Redis with timestamp for other workers
    try:
        from app.core.redis import get_redis
        redis_client = get_redis()
        
        if redis_client:
            # Store CORS origins with timestamp in Redis
            redis_client.set(
                "cors:origins", 
                json.dumps({"origins": new_origins, "updated_at": time.time()})
            )
            
            # Publish event to notify other workers
            redis_client.publish("cors:update", "refresh")
            logger.info("Published CORS update to other workers via Redis")
        else:
            logger.warning("Redis not available, CORS update will only apply to this worker")
    except Exception as e:
        logger.error(f"Failed to publish CORS update to Redis: {str(e)}")

async def listen_for_cors_updates(app: FastAPI):
    """
    Listen for CORS update notifications from Redis using an efficient pattern
    """
    from app.core.redis import get_redis
    redis_client = get_redis()
    
    if not redis_client:
        logger.warning("Redis not available, skipping CORS update listener")
        return
    
    # Use a dedicated Redis connection for PubSub to avoid blocking other operations
    try:
        pubsub = redis_client.pubsub()
        pubsub.subscribe("cors:update")
        logger.info("Started CORS update listener")
        
        # Use an event-driven approach instead of continuous polling
        for message in pubsub.listen():
            # Skip subscription confirmation messages
            if message["type"] != "message":
                continue
                
            try:
                # Get updated origins from Redis
                origins_data = redis_client.get("cors:origins")
                if not origins_data:
                    continue
                    
                origins_data = json.loads(origins_data)
                if origins_data and "origins" in origins_data:
                    logger.info("Received CORS update notification")
                    update_local_cors(app, origins_data["origins"])
            except Exception as e:
                logger.error(f"Error processing CORS update: {str(e)}")
                
    except Exception as e:
        logger.error(f"Error in CORS update listener: {str(e)}")
        # Try to clean up subscription
        try:
            pubsub.unsubscribe("cors:update")
            pubsub.close()
        except:
            pass

def start_cors_listener(app: FastAPI):
    """
    Start background task to listen for CORS updates
    """
    try:
        # Check if Redis is available before starting listener
        from app.core.redis import get_redis
        redis_client = get_redis()
        
        if redis_client:
            # Create background task with proper error handling
            background_task = asyncio.create_task(listen_for_cors_updates(app))
            
            # Add exception handler to restart if it fails
            def handle_exception(task):
                if not task.cancelled() and task.exception():
                    logger.error(f"CORS listener crashed: {task.exception()}")
                    # Wait a moment before restarting
                    asyncio.create_task(restart_listener(app))
                    
            async def restart_listener(app):
                await asyncio.sleep(5)  # Wait before restarting
                logger.info("Restarting CORS listener")
                new_task = asyncio.create_task(listen_for_cors_updates(app))
                new_task.add_done_callback(handle_exception)
                
            background_task.add_done_callback(handle_exception)
            logger.info("Started CORS update listener task")
        else:
            logger.warning("Redis not available, CORS synchronization between workers disabled")
    except Exception as e:
        logger.error(f"Failed to start CORS listener: {str(e)}") 