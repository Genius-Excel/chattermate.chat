"""
ChatterMate - Widget Chat
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

import datetime
import os
from fastapi import APIRouter
from app.core.socketio import sio
from app.core.logger import get_logger
import traceback
from app.agents.chat_agent import ChatAgent, ChatResponse
from app.core.auth_utils import authenticate_socket, authenticate_socket_conversation_token
from app.database import get_db
from app.repositories.ai_config import AIConfigRepository
from app.repositories.widget import WidgetRepository
from app.core.security import decrypt_api_key
from app.repositories.session_to_agent import SessionToAgentRepository
from app.repositories.chat import ChatRepository
import uuid
from app.services.socket_rate_limit import socket_rate_limit

from app.models.session_to_agent import SessionStatus
from app.agents.transfer_agent import get_agent_availability_response
from app.repositories.agent import AgentRepository
from app.repositories.rating import RatingRepository
from app.repositories.jira import JiraRepository
from app.models.ai_config import AIModelType


# Try to import enterprise modules
try:
    from app.enterprise.services.message_limit import check_message_limit
    HAS_ENTERPRISE = True
except ImportError:
    HAS_ENTERPRISE = False

router = APIRouter()
logger = get_logger(__name__)

def format_datetime(dt):
    """Convert datetime to ISO format string"""
    return dt.isoformat() if dt else None

@sio.on('connect', namespace='/widget')
async def widget_connect(sid, environ, auth):
    try:
       
        logger.info(f"Widget client connected: {auth}")
        # Authenticate using conversation token from Authorization header
        widget_id, org_id, customer_id, conversation_token = await authenticate_socket_conversation_token(sid, auth)
        
        if not widget_id or not org_id:
            raise ValueError("Widget authentication failed")

        # Get widget and verify it exists
        db = next(get_db())
        widget_repo = WidgetRepository(db)
        widget = widget_repo.get_widget(widget_id)
        if not widget:
            raise ValueError("Invalid widget ID")

        # Get AI config for widget's organization
        ai_config_repo = AIConfigRepository(db)
        ai_config = ai_config_repo.get_active_config(org_id)
        if not ai_config:
            await sio.emit('error', {
                'error': 'AI configuration required',
                'type': 'ai_config_missing'
            }, to=sid, namespace='/widget')
            return False
        
        message_limit_reached = False
        # Check message limits if enterprise module is available
        if HAS_ENTERPRISE and ai_config.model_type == AIModelType.CHATTERMATE:
            if not await check_message_limit(db, org_id, sid, sio):
                message_limit_reached = True

        
        session_repo = SessionToAgentRepository(db)
                
        # Try to get existing active session
        active_session = session_repo.get_active_customer_session(
            customer_id=customer_id,
            agent_id=widget.agent_id
        )
              
        if active_session:
            session_id = str(active_session.session_id)
            logger.debug(f"Active session: {session_id}")  
        else:
            # Create new session if none exists
            new_session_id = str(uuid.uuid4())
            session_repo.create_session(
                session_id=new_session_id,
                agent_id=widget.agent_id,
                customer_id=customer_id,
                organization_id=org_id
            )
            session_id = new_session_id
            logger.debug(f"New session: {session_id}")

        # Join the room using session_id
        await sio.enter_room(sid, session_id, namespace='/widget')
        
        # Get agent to retrieve rate limiting settings
        agent_repo = AgentRepository(db)
        agent = agent_repo.get_agent(widget.agent_id)
        
        # Store session data including rate limiting settings
        enable_rate_limiting = agent.enable_rate_limiting if agent else False
        overall_limit_per_ip = agent.overall_limit_per_ip if agent else 100
        requests_per_sec = agent.requests_per_sec if agent else 1.0
        
        session_data = {
            'widget_id': widget_id,
            'org_id': org_id,
            'agent_id': str(widget.agent_id),
            'customer_id': customer_id,
            'session_id': session_id,
            'ai_config': ai_config,
            'conversation_token': conversation_token,
            # Add rate limiting settings
            'enable_rate_limiting': enable_rate_limiting,
            'overall_limit_per_ip': overall_limit_per_ip,
            'requests_per_sec': requests_per_sec,
            'message_limit_reached': message_limit_reached
        }

        # Log rate limiting settings
        if enable_rate_limiting:
            logger.debug(f"Rate limiting enabled for agent {agent.name} - Daily limit: {overall_limit_per_ip} requests, Rate: {requests_per_sec} req/sec")
        else:
            logger.debug(f"Rate limiting disabled for agent {agent.name}")

        logger.debug(f"Session data: {session_data['ai_config'].encrypted_api_key}")
        await sio.save_session(sid, session_data, namespace='/widget')
        logger.info(f"Widget client connected: {sid} joined room: {session_id}")
        return True

    except Exception as e:
        logger.error(f"Widget connection error for sid {sid}: {str(e)}")
        logger.error(traceback.format_exc())
        await sio.emit('error', {
            'error': 'Connection failed',
            'type': 'connection_error'
        }, to=sid, namespace='/widget')
        return False


@sio.on('chat', namespace='/widget')
@socket_rate_limit(namespace='/widget')
async def handle_widget_chat(sid, data):
    """Handle widget chat messages"""
    try:
        # Authenticate using conversation token
        session = await sio.get_session(sid, namespace='/widget')

        widget_id, org_id, customer_id, conversation_token = await authenticate_socket_conversation_token(sid, session)
        
        if not widget_id or not org_id:
            logger.error(f"Widget authentication failed for sid {sid}")
            await sio.emit('error', {'error': 'Authentication failed', 'type': 'auth_error'}, room=sid, namespace='/widget')
            return

        # Process message
        message = data.get('message', '').strip()
        if not message:
            return

        session_id = session['session_id']
        # Verify session matches authenticated data
        if (session['widget_id'] != widget_id or 
            session['org_id'] != org_id or 
            session['customer_id'] != customer_id):
            raise ValueError("Session mismatch")

        db = next(get_db())
        session_repo = SessionToAgentRepository(db)
                
        # Try to get existing active session
        active_session = session_repo.get_active_customer_session(
            customer_id=customer_id
        )

        # Check message limit from session
        if HAS_ENTERPRISE and session.get('message_limit_reached') and active_session and active_session.user_id is None:
            logger.error(f"Message limit reached")
            await sio.emit('error', {
                    'error': 'Unable to process your message. Please contact support.',
                    'type': 'message_limit_exceeded'
            }, to=sid, namespace='/widget')
            return

        if not active_session:
            # Check if there's a closed session that can be reopened
            latest_session = session_repo.get_latest_customer_session(
                customer_id=customer_id
            )
            
            if latest_session and latest_session.status == SessionStatus.CLOSED:
                # Reopen the closed session if it matches the current session ID
                if str(latest_session.session_id) == session_id:
                    success = session_repo.reopen_closed_session(session_id)
                    if success:
                        # Refresh the session data
                        active_session = session_repo.get_session(session_id)
                        logger.info(f"Reopened closed session {session_id} for customer {customer_id}")
                    else:
                        raise ValueError("Failed to reopen closed session")
                else:
                    raise ValueError("Session mismatch")
            else:
                raise ValueError("No active session found")
        
        if str(active_session.session_id) != session_id:
            raise ValueError("Session mismatch")
        
        if active_session.status == SessionStatus.OPEN and active_session.user_id is None: # open and user has not taken over
            # Initialize chat agent
            chat_agent = ChatAgent(
                api_key=decrypt_api_key(session['ai_config'].encrypted_api_key),
                model_name=session['ai_config'].model_name,
                model_type=session['ai_config'].model_type,
                org_id=org_id,
                agent_id=session['agent_id'],
                customer_id=customer_id,
                session_id=session_id
            )
            # Get response from ai agent
            response = await chat_agent.get_response(
                message=message,
                session_id=chat_agent.agent.session_id,
                org_id=org_id,
                agent_id=session['agent_id'],
                customer_id=customer_id)
        elif active_session.status == SessionStatus.TRANSFERRED and active_session.user_id is None: # transferred and user has not taken over
            logger.debug(f"Transferring chat to human for session {session_id}")
            # Get response from agent transfer ai agent
            chat_repo = ChatRepository(db)
            chat_repo.create_message({
                "message": message,
                "message_type": "user",
                "session_id": session_id,
                "organization_id": org_id,
                "agent_id": session['agent_id'],
                "customer_id": customer_id,
            })
            chat_history = []
            chat_history = chat_repo.get_session_history(session_id)
            jira_repo = JiraRepository(db)
            agent_data = jira_repo.get_agent_with_jira_config(session['agent_id']) if session['agent_id'] else None
            availability_response = await get_agent_availability_response(
                agent=agent_data,
                customer_id=customer_id,
                chat_history=chat_history,
                db=db,
                api_key=decrypt_api_key(session['ai_config'].encrypted_api_key),
                model_name=session['ai_config'].model_name,
                model_type=session['ai_config'].model_type,
                session_id=session_id
            )

                # Create ChatResponse object
            response_content = ChatResponse(
                message=availability_response["message"],
                transfer_to_human=True,
                transfer_reason=None,
                transfer_description=None,
                end_chat=False,
                request_rating=False,
                create_ticket=False
            )
                
            # Store AI response with transfer status
            chat_repo.create_message({
                "message": response_content.message,
                "message_type": "bot",
                "session_id": session_id,
                "organization_id": org_id,  
                "agent_id": session['agent_id'],
                "customer_id": customer_id,
                "attributes": {
                    "transfer_to_human": response_content.transfer_to_human,
                    "transfer_reason": response_content.transfer_reason.value if response_content.transfer_reason else None,
                    "transfer_description": response_content.transfer_description,
                    "end_chat": response_content.end_chat,
                    "end_chat_reason": response_content.end_chat_reason.value if response_content.end_chat_reason else None,
                    "end_chat_description": response_content.end_chat_description,
                    "request_rating": response_content.request_rating,
                    "shopify_output": response_content.shopify_output
                }
            })
            response = response_content
        else:
            chat_repo = ChatRepository(db)
            chat_repo.create_message({
                "message": message,
                "message_type": "user",
                "session_id": session_id,
                "organization_id": org_id,  
                "agent_id": session['agent_id'],
                "customer_id": customer_id,
                "user_id": active_session.user_id,
            })
            # Get session data to find assigned user
            session_data = session_repo.get_session(session_id)
            user_id = str(session_data.user_id) if session_data and session_data.user_id else None
            timestamp = format_datetime(datetime.datetime.now())

            
            if user_id:
                # Also emit to user-specific room
                user_room = f"user_{user_id}"
                await sio.emit('chat_reply', {
                    'message': message,
                    'type': 'user_message',
                    'transfer_to_human': False,
                    'session_id': session_id,
                    'created_at': timestamp
                }, room=user_room, namespace='/agent')


            # Emit to both session room and user's personal room
            await sio.emit('chat_reply', {
                'message': message,
                'type': 'user_message',
                'transfer_to_human': False,
                'session_id': session_id,
                'timestamp': timestamp
            }, room=session_id, namespace='/agent')    

            return # don't do anything if the session is closed or the user has already taken over
        
        # Emit response to the specific room
        response_payload = {
            'message': response.message,
            'type': 'chat_response',
            'transfer_to_human': response.transfer_to_human,
            'end_chat': response.end_chat,
            'end_chat_reason': response.end_chat_reason.value if response.end_chat_reason else None,
            'end_chat_description': response.end_chat_description,
            'request_rating': response.request_rating,
            # Initialize shopify_output to None. It will be populated if data exists.
            'shopify_output': None 
        }
        
        # Check if the response object has the structured shopify_output field
        # and assign it directly if it's valid (should be a Pydantic model or dict)
        if hasattr(response, 'shopify_output') and response.shopify_output:
            # Assuming response.shopify_output is already the correct 
            # ShopifyOutputData model instance from ChatResponse
            # We need to convert it to a dict for JSON serialization
            try:
                response_payload['shopify_output'] = response.shopify_output.model_dump(exclude_unset=True)
            except AttributeError:
                 # Handle cases where it might be a plain dict already (less likely but safe)
                 if isinstance(response.shopify_output, dict):
                     response_payload['shopify_output'] = response.shopify_output
                 else:
                     logger.warning(f"Unexpected type for shopify_output: {type(response.shopify_output)}")

        await sio.emit('chat_response', response_payload, room=session_id, namespace='/widget')

    except Exception as e:
        logger.error(f"Widget chat error for sid {sid}: {str(e)}")
        logger.error(traceback.format_exc())
        await sio.emit('error', {
            'error': 'Unable to process your request, please try again later.',
            'type': 'chat_error'
        }, to=sid, namespace='/widget')


@sio.on('get_chat_history', namespace='/widget')
@socket_rate_limit(namespace='/widget')
async def get_widget_chat_history(sid):
    try:
        logger.info(f"Getting chat history for sid {sid}")
        # Get session data
        session = await sio.get_session(sid, namespace='/widget')
        widget_id, org_id, customer_id, conversation_token = await authenticate_socket_conversation_token(sid, session)
        
        if not widget_id or not org_id:
            logger.error(f"Widget authentication failed for sid {sid}")
            await sio.emit('error', {'error': 'Authentication failed', 'type': 'auth_error'}, room=sid, namespace='/widget')
            return


        
        # Verify session matches authenticated data
        if (session['widget_id'] != widget_id or 
            session['org_id'] != org_id or 
            session['customer_id'] != customer_id):
            raise ValueError("Session mismatch")
        
        db = next(get_db())
        
        # Get active session using new repository
        session_repo = SessionToAgentRepository(db)
        active_session = session_repo.get_active_customer_session(
            customer_id=customer_id,
            agent_id=session['agent_id']
        )

        if not active_session:
            logger.info("No active session found, returning empty history")
            await sio.emit('chat_history', {
                'messages': [],
                'type': 'chat_history'
            }, to=sid, namespace='/widget')
            return

        # Get chat history for active session
        chat_repo = ChatRepository(db)
        messages = chat_repo.get_session_history(
            session_id=active_session.session_id
        )

        # Convert datetime to ISO format string
        formatted_messages = [{
            'message': msg.message,
            'message_type': msg.message_type,
            'timestamp': format_datetime(msg.created_at),
            'attributes': msg.attributes,
            'user_name': msg.user.full_name if msg.user else None,
            'agent_name': msg.agent.display_name or msg.agent.name if msg.agent else None
        } for msg in messages]

        await sio.emit('chat_history', {
            'messages': formatted_messages,
            'type': 'chat_history'
        }, to=sid, namespace='/widget')

    except ValueError as e:
        logger.error(f"Widget authentication error for sid {sid}: {str(e)}")
        await sio.emit('error', {
            'error': 'Authentication failed',
            'type': 'auth_error'
        }, to=sid, namespace='/widget')
    except Exception as e:
        logger.error(f"Error getting chat history for sid {sid}: {str(e)}")
        logger.error(traceback.format_exc())
        await sio.emit('error', {
            'error': 'Failed to get chat history',
            'type': 'chat_history_error'
        }, to=sid, namespace='/widget')


# Add connection handler for agent namespace
@sio.on('connect', namespace='/agent')
async def agent_connect(sid, environ, auth):
    try:
        access_token, user_id, org_id = await authenticate_socket(sid, environ)
        if not access_token:
            raise ValueError("Authentication failed")
        logger.info(f"Authenticated connection for user {
                    user_id} org {org_id}")

        # Store session data
        session_data = {
            'user_id': user_id,
            'organization_id': org_id
        }
        
        await sio.save_session(sid, session_data, namespace='/agent')
        
        
        return True

    except Exception as e:
        logger.error(f"Agent connection error for sid {sid}: {str(e)}")
        return False 
    
# Add new socket event handler for agent messages
@sio.on('agent_message', namespace='/agent')
async def handle_agent_message(sid, data):
    try:
        session = await sio.get_session(sid, namespace='/agent')
        session_id = data['session_id']
        
        logger.info(f"Session ID: {session_id}")
        if not session_id:
            raise ValueError("No active session")

        db = next(get_db())
        session_repo = SessionToAgentRepository(db)
        chat_repo = ChatRepository(db)
        
        # Verify session and agent permissions
        session_data = session_repo.get_session(session_id)
        if not session_data or str(session_data.user_id) != session.get('user_id'):
            raise ValueError("Unauthorized")

        # Store the agent's message
        message = {
            "message": data['message'],
            "message_type": data.get('message_type', "agent"),
            "session_id": session_id,
            "organization_id": session.get('organization_id'),
            "agent_id": session_data.agent_id if session_data.agent_id else None,
            "customer_id": session_data.customer_id,
            "user_id": session_data.user_id,
            "attributes":{
                "end_chat": data.get('end_chat', False),
                "request_rating": data.get('request_rating', False),
                "end_chat_reason": data.get('end_chat_reason', None),
                "end_chat_description": data.get('end_chat_description', None),
                "shopify_output": data.get('shopify_output', None)
            }
        }
        
        chat_repo.create_message(message)
        
        # Check if this is an end chat message
        if data.get('end_chat') is True:
            logger.info(f"Agent ended chat session {session_id}")
            # Update session status to closed
            session_repo.update_session_status(session_id, "CLOSED")
            
        
        # Emit to widget clients
        response_payload = {
            'message': data['message'],
            'type': 'agent_message',
            'message_type': data.get('message_type', 'agent'),
            'end_chat': data.get('end_chat', False),
            'request_rating': data.get('request_rating', False),
            'end_chat_reason': data.get('end_chat_reason', None),
            'end_chat_description': data.get('end_chat_description', None),
            'shopify_output': data.get('shopify_output', False)
        }
        
        # Add individual product fields if shopify_output is true
        if response_payload['shopify_output']:
            response_payload.update({
                'product_id': data.get('product_id'),
                'product_title': data.get('product_title'),
                'product_description': data.get('product_description'),
                'product_handle': data.get('product_handle'),
                'product_inventory': data.get('product_inventory'),
                'product_price': data.get('product_price'),
                'product_currency': data.get('product_currency'),
                'product_image': data.get('product_image'),
            })
            
        await sio.emit('chat_response', response_payload, room=session_id, namespace='/widget')


    except Exception as e:
        logger.error(f"Agent message error for sid {sid}: {str(e)}")
        logger.error(traceback.format_exc())
        await sio.emit('error', {
            'error': 'Failed to send message',
            'type': 'message_error'
        }, to=sid, namespace='/agent')

# Add handlers for room management
@sio.on('join_room', namespace='/agent')
async def handle_join_room(sid, data):
    try:
        session = await sio.get_session(sid, namespace='/agent')
        session_id = data.get('session_id')
        if not session_id:
            raise ValueError("No session ID provided")

        # Handle user-specific rooms
        if session_id.startswith('user_'):
            user_id = session_id.split('_')[1]
            if str(session.get('user_id')) != user_id:
                raise ValueError("Unauthorized to join user room")
            await sio.enter_room(sid, session_id, namespace='/agent')
            logger.info(f"Agent {user_id} joined their user room")
            return

        # Verify this agent has permission to join this room
        db = next(get_db())
        session_repo = SessionToAgentRepository(db)
        session_data = session_repo.get_session(session_id)
        
        if not session_data:
            raise ValueError("Invalid session")
            
        if str(session_data.user_id) != str(session.get('user_id')):
            raise ValueError("Unauthorized to join this room")

        # Join the room
        await sio.enter_room(sid, session_id, namespace='/agent')
        logger.info(f"Agent {session.get('user_id')} joined room: {session_id}")


        # Notify room of join
        await sio.emit('room_event', {
            'type': 'join',
            'user_id': str(session.get('user_id')),
        }, room=session_id, namespace='/agent')

        session_data = {
            'session_id': session_id,
            'user_id': session.get('user_id'),
        }
        await sio.save_session(sid, session_data, namespace='/agent')

    except Exception as e:
        logger.error(f"Error joining room for sid {sid}: {str(e)}")
        await sio.emit('error', {
            'error': 'Failed to join room',
            'type': 'room_error'
        }, to=sid, namespace='/agent')

@sio.on('leave_room', namespace='/agent')
async def handle_leave_room(sid, data):
    try:
        session = await sio.get_session(sid, namespace='/agent')
        if not session:
            raise ValueError("No active session")

        session_id = data.get('session_id')
        if not session_id:
            raise ValueError("No session ID provided")

        # Leave the room
        await sio.leave_room(sid, session_id, namespace='/agent')
        logger.info(f"Agent {session.get('user_id')} left room: {session_id}")

        # Notify room of leave
        await sio.emit('room_event', {
            'type': 'leave',
            'user_id': str(session.get('user_id')),
        }, room=session_id, namespace='/agent')

    except Exception as e:
        logger.error(f"Error leaving room for sid {sid}: {str(e)}")
        await sio.emit('error', {
            'error': 'Failed to leave room',
            'type': 'room_error'
        }, to=sid, namespace='/agent')    


@sio.on('taken_over', namespace='/agent')
async def handle_taken_over(sid, data):
    logger.info(f"Agent {data['user_name']} has taken over chat {data['session_id']}")
    await sio.emit('handle_taken_over', data, room=data['session_id'] , namespace='/widget')

@sio.on('submit_rating', namespace='/widget')
@socket_rate_limit(namespace='/widget')
async def handle_rating_submission(sid, data):
    """Handle rating submission from widget"""
    try:
        # Get session data and authenticate
        session = await sio.get_session(sid, namespace='/widget')
        widget_id, org_id, customer_id, conversation_token = await authenticate_socket_conversation_token(sid, session)
        
        if not widget_id or not org_id:
            logger.error(f"Widget authentication failed for sid {sid}")
            await sio.emit('error', {'error': 'Authentication failed', 'type': 'auth_error'}, room=sid, namespace='/widget')
            return

        session_id = session['session_id']
        # Verify session matches authenticated data
        if (session['widget_id'] != widget_id or 
            session['org_id'] != org_id or 
            session['customer_id'] != customer_id):
            raise ValueError("Session mismatch")

        # Validate rating data
        rating = data.get('rating')
        feedback = data.get('feedback')
        
        if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
            raise ValueError("Invalid rating value")

        db = next(get_db())
        
        # Get session details
        session_repo = SessionToAgentRepository(db)
        session_data = session_repo.get_session(session_id)
        
        if not session_data:
            raise ValueError("Session not found")

        # Create rating using repository
        rating_repo = RatingRepository(db)
        rating_obj = rating_repo.create_rating(
            session_id=session_id,
            customer_id=customer_id,
            user_id=session_data.user_id,
            agent_id=session_data.agent_id,
            organization_id=org_id,
            rating=rating,
            feedback=feedback
        )

        # Emit success response
        await sio.emit('rating_submitted', {
            'success': True,
            'message': 'Rating submitted successfully'
        }, room=sid, namespace='/widget')

        # Also emit to agent room if there's an assigned agent
        if session_data.user_id:
            user_room = f"user_{session_data.user_id}"
            await sio.emit('rating_received', {
                'session_id': session_id,
                'rating': rating,
                'feedback': feedback
            }, room=user_room, namespace='/agent')

    except ValueError as e:
        logger.error(f"Rating submission error for sid {sid}: {str(e)}")
        await sio.emit('error', {
            'error': str(e),
            'type': 'rating_error'
        }, to=sid, namespace='/widget')
    except Exception as e:
        logger.error(f"Rating submission error for sid {sid}: {str(e)}")
        logger.error(traceback.format_exc())
        await sio.emit('error', {
            'error': 'Failed to submit rating',
            'type': 'rating_error'
        }, to=sid, namespace='/widget')