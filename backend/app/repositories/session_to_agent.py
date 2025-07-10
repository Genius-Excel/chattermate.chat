"""
ChatterMate - Session To Agent
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

from sqlalchemy.orm import Session
from typing import List, Optional
from app.models.session_to_agent import SessionToAgent, SessionStatus
from uuid import UUID
from datetime import datetime
from app.core.logger import get_logger
from sqlalchemy import or_

from app.models.user import User

logger = get_logger(__name__)

class SessionToAgentRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_session(self, session_id: UUID | str, agent_id: UUID | str, customer_id: UUID | str = None, user_id: UUID | str = None, organization_id: UUID | str = None) -> SessionToAgent:
        """Create a new session assignment"""
        try:
            session = SessionToAgent(
                session_id=session_id,
                agent_id=agent_id,
                customer_id=customer_id,
                user_id=user_id,
                organization_id=organization_id,
                status=SessionStatus.OPEN
            )
            self.db.add(session)
            self.db.commit()
            self.db.refresh(session)
            return session
        except Exception as e:
            logger.error(f"Error creating session: {str(e)}")
            self.db.rollback()
            raise

    def get_session(self, session_id: UUID | str) -> Optional[SessionToAgent]:
        """Get session by ID"""
        try:
            if isinstance(session_id, str):
                session_id = UUID(session_id)
            return self.db.query(SessionToAgent).filter(
                SessionToAgent.session_id == session_id
            ).first()
        except Exception as e:
            logger.error(f"Error getting session: {str(e)}")
            return None

    def assign_user(self, session_id: UUID | str, user_id: UUID | str) -> bool:
        """Assign a user to a session"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False
            
            session.user_id = user_id
            session.status = SessionStatus.TRANSFERRED
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error assigning user to session: {str(e)}")
            self.db.rollback()
            return False

    def close_session(self, session_id: UUID | str) -> bool:
        """Close a session"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False
            
            session.status = SessionStatus.CLOSED
            session.closed_at = datetime.utcnow()
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error closing session: {str(e)}")
            self.db.rollback()
            return False

    def get_agent_sessions(self, agent_id: UUID | str, status: SessionStatus = None) -> List[SessionToAgent]:
        """Get all sessions for an agent"""
        try:
            query = self.db.query(SessionToAgent).filter(
                SessionToAgent.agent_id == agent_id
            )
            if status:
                query = query.filter(SessionToAgent.status == status)
            return query.all()
        except Exception as e:
            logger.error(f"Error getting agent sessions: {str(e)}")
            return []

    def get_user_sessions(self, user_id: UUID | str, status: SessionStatus = None) -> List[SessionToAgent]:
        """Get all sessions assigned to a user"""
        try:
            query = self.db.query(SessionToAgent).filter(
                SessionToAgent.user_id == user_id
            )
            if status:
                query = query.filter(SessionToAgent.status == status)
            return query.all()
        except Exception as e:
            logger.error(f"Error getting user sessions: {str(e)}")
            return []

    def get_open_sessions(self) -> List[SessionToAgent]:
        """Get all open sessions"""
        try:
            return self.db.query(SessionToAgent).filter(
                SessionToAgent.status == SessionStatus.OPEN
            ).all()
        except Exception as e:
            logger.error(f"Error getting open sessions: {str(e)}")
            return []

    def get_customer_sessions(self, customer_id: UUID | str, status: SessionStatus = None) -> List[SessionToAgent]:
        """Get all sessions for a customer"""
        try:
            query = self.db.query(
                SessionToAgent,
                User.full_name.label('user_full_name'),
                User.profile_pic.label('user_profile_pic')
            ).outerjoin(
                User, SessionToAgent.user_id == User.id
            ).filter(
                SessionToAgent.customer_id == customer_id
            )
            if status:
                query = query.filter(SessionToAgent.status == status)

            return query.order_by(SessionToAgent.assigned_at.desc()).all()
        except Exception as e:
            logger.error(f"Error getting customer sessions: {str(e)}")
            return []

    def get_active_customer_session(self, customer_id: UUID | str, agent_id: UUID | str = None) -> Optional[SessionToAgent]:
        """Get active session for a customer"""
        try:
            query = self.db.query(SessionToAgent).filter(
                SessionToAgent.customer_id == customer_id,
                or_(
                    SessionToAgent.status == SessionStatus.OPEN,
                    SessionToAgent.status == SessionStatus.TRANSFERRED
                )
            )
            if agent_id:
                query = query.filter(SessionToAgent.agent_id == agent_id)
            
            return query.order_by(SessionToAgent.assigned_at.desc()).first()
        except Exception as e:
            logger.error(f"Error getting active customer session: {str(e)}")
            return None

    def get_agent_customer_sessions(self, agent_id: UUID | str, customer_id: UUID | str, status: SessionStatus = None) -> List[SessionToAgent]:
        """Get all sessions between an agent and customer"""
        try:
            query = self.db.query(SessionToAgent).filter(
                SessionToAgent.agent_id == agent_id,
                SessionToAgent.customer_id == customer_id
            )
            if status:
                query = query.filter(SessionToAgent.status == status)
            
            return query.order_by(SessionToAgent.assigned_at.desc()).all()
        except Exception as e:
            logger.error(f"Error getting agent-customer sessions: {str(e)}")
            return []

    def reopen_closed_session(self, session_id: UUID | str) -> bool:
        """Reopen a closed session"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False
            
            if session.status == SessionStatus.CLOSED:
                session.status = SessionStatus.OPEN
                self.db.commit()
                return True
            return False  # Session was not closed
        except Exception as e:
            logger.error(f"Error reopening session: {str(e)}")
            self.db.rollback()
            return False
            
    def get_latest_customer_session(self, customer_id: UUID | str, agent_id: UUID | str = None) -> Optional[SessionToAgent]:
        """Get the latest session for a customer regardless of status"""
        try:
            query = self.db.query(SessionToAgent).filter(
                SessionToAgent.customer_id == customer_id
            )
            if agent_id:
                query = query.filter(SessionToAgent.agent_id == agent_id)
            
            return query.order_by(SessionToAgent.assigned_at.desc()).first()
        except Exception as e:
            logger.error(f"Error getting latest customer session: {str(e)}")
            return None

    def update_session(self, session_id: UUID | str, data: dict) -> bool:
        """Update a session"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False
            for key, value in data.items():
                setattr(session, key, value)
            self.db.commit()
            return True
        except Exception as e:
            logger.error(f"Error updating session: {str(e)}")
            self.db.rollback()
            return False

    def takeover_session(self, session_id: str, user_id: str) -> bool:
        """Take over a chat session"""
        try:
            session = self.get_session(session_id)
            if not session:
                return False

            # Check if session is already taken
            if session.user_id is not None:
                return False

            # Update session
            session.user_id = UUID(user_id)
            session.group_id = None  # Remove group assignment
            session.status = SessionStatus.OPEN  # Keep status as open
            
            self.db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error taking over session: {str(e)}")
            self.db.rollback()
            return False

    def update_session_status(self, session_id: UUID | str, status: str) -> Optional[SessionToAgent]:
        """Update the status of a session"""
        try:
            session = self.db.query(SessionToAgent).filter(SessionToAgent.session_id == session_id).first()
            if not session:
                logger.error(f"Session {session_id} not found")
                return None
                
            # Convert string status to enum if needed
            if isinstance(status, str):
                try:
                    status = SessionStatus[status]
                except KeyError:
                    logger.error(f"Invalid session status: {status}")
                    return None
            
            session.status = status
            session.updated_at = datetime.utcnow()
            
            self.db.commit()
            self.db.refresh(session)
            logger.info(f"Updated session {session_id} status to {status}")
            return session
        except Exception as e:
            logger.error(f"Error updating session status: {str(e)}")
            self.db.rollback()
            return None
