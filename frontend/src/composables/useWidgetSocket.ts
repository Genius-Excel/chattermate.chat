import { ref } from 'vue'
import { io, Socket } from 'socket.io-client'
import type { HumanAgent, SocketError } from '../types/widget'
import { getErrorMessage } from '../types/widget'
import { widgetEnv } from '../webclient/widget-env'
import type { Message } from '@/types/chat'

type ConnectionStatus = 'connected' | 'connecting' | 'failed'

export function useWidgetSocket() {
    const messages = ref<Message[]>([])
    const loading = ref(false)
    const errorMessage = ref('')
    const showError = ref(false)
    const loadingHistory = ref(false)
    const hasStartedChat = ref(false)
    const connectionStatus = ref<ConnectionStatus>('connecting')
    const retryCount = ref(0)
    const MAX_RETRIES = 5
    const humanAgent = ref<HumanAgent>({})

    let socket: Socket | null = null
    let onTakeoverCallback: ((data: { session_id: string, user_name: string }) => void) | null = null

    const initializeSocket = (sessionId: string) => {
        const token = localStorage.getItem('ctid');
        
        socket = io(`${widgetEnv.WS_URL}/widget`, {
            transports: ['websocket'],
            reconnection: true,
            reconnectionAttempts: MAX_RETRIES,
            reconnectionDelay: 1000,
            auth: token ? {
                conversation_token: token
            } : undefined
        })

        // Set up event listeners
        socket.on('connect', () => {
            connectionStatus.value = 'connected'
            retryCount.value = 0
        })

        socket.on('disconnect', () => {
            if (connectionStatus.value === 'connected') {
                connectionStatus.value = 'connecting'
            }
        })

        socket.on('connect_error', () => {
            retryCount.value++
            console.error('Socket connection failed, attempt:', retryCount.value)
            if (retryCount.value >= MAX_RETRIES) {
                connectionStatus.value = 'failed'
            }
        })

        socket.on('chat_response', (data) => {
            loading.value = false // Stop loading indicator first

            if (data.type === 'agent_message') {
                // Handle human agent messages (no change needed here)
                messages.value.push({
                    message: data.message,
                    message_type: 'agent',
                    created_at: new Date().toISOString(),
                    session_id: '',
                    agent_name: data.agent_name,
                    attributes: {
                        end_chat: data.end_chat,
                        end_chat_reason: data.end_chat_reason,
                        end_chat_description: data.end_chat_description,
                        request_rating: data.request_rating
                    }
                })
            // UPDATED CHECK: Look for the shopify_output object and products array
            } else if (data.shopify_output && typeof data.shopify_output === 'object' && data.shopify_output.products) {
                // Handle structured Shopify product data
                messages.value.push({
                    message: data.message, // Keep the accompanying text message
                    message_type: 'product', // Use 'product' type for rendering
                    created_at: new Date().toISOString(),
                    session_id: '', 
                    agent_name: data.agent_name,
                    // Assign the whole structured object
                    shopify_output: data.shopify_output, 
                    // Remove the old flattened fields (product_id, product_title, etc.)
                    attributes: { // Keep other attributes if needed
                         end_chat: data.end_chat,
                         request_rating: data.request_rating
                    }
                })
            } else {
                // Handle regular bot messages (without Shopify data)
                messages.value.push({
                    message: data.message,
                    message_type: 'bot',
                    created_at: new Date().toISOString(),
                    session_id: '',
                    agent_name: data.agent_name,
                    attributes: {
                        end_chat: data.end_chat,
                        end_chat_reason: data.end_chat_reason,
                        end_chat_description: data.end_chat_description,
                        request_rating: data.request_rating
                    }
                })
            }
            // loading.value = false // Moved to the top
        })

        socket.on('handle_taken_over', (data: { session_id: string, user_name: string, profile_picture?: string }) => {
            // Add system message for takeover
            messages.value.push({
                message: `${data.user_name} joined the conversation`,
                message_type: 'system',
                created_at: new Date().toISOString(),
                session_id: data.session_id
            })

            
            humanAgent.value = {
                ...humanAgent.value,
                human_agent_name: data.user_name,
                human_agent_profile_pic: data.profile_picture
            }

            // Call the callback if registered
            if (onTakeoverCallback) {
                onTakeoverCallback(data)
            }
        })

        socket.on('error', handleError)
        socket.on('chat_history', handleChatHistory)
        socket.on('rating_submitted', handleRatingSubmitted)

        return socket
    }

    const connect = async (): Promise<boolean> => {
        try {
            connectionStatus.value = 'connecting'
            retryCount.value = 0

            // Cleanup existing socket if any
            if (socket) {
                socket.removeAllListeners()
                socket.disconnect()
                socket = null
            }

            socket = initializeSocket('')

            return new Promise((resolve) => {
                socket?.on('connect', () => {
                    resolve(true)
                })

                socket?.on('connect_error', () => {
                    if (retryCount.value >= MAX_RETRIES) {
                        resolve(false)
                    }
                })
            })
        } catch (error) {
            console.error('Socket initialization failed:', error)
            connectionStatus.value = 'failed'
            return false
        }
    }

    // Manual reconnect function
    const reconnect = () => {
        if (socket) {
            socket.disconnect()
        }
        return connect()
    }

    // Register takeover callback
    const onTakeover = (callback: (data: { session_id: string, user_name: string }) => void) => {
        onTakeoverCallback = callback
    }

    // Socket event handlers
    const handleError = (error: any) => {
        loading.value = false
        errorMessage.value = getErrorMessage(error as SocketError)
        showError.value = true
        
        // Hide error after 5 seconds
        setTimeout(() => {
            showError.value = false
            errorMessage.value = ''
        }, 5000)
    }

    const handleChatHistory = (data: {
        type: string;
        messages: Message[];
    }) => {
        if (data.type === 'chat_history' && Array.isArray(data.messages)) {
            const historyMessages = data.messages.map((msg: Message) => {
                // Base message structure
                const messageObj = {
                    message: msg.message,
                    message_type: msg.message_type as "assistant" | "user" | "error" | "bot" | "agent" | "system" | "product",
                    created_at: msg.created_at,
                    session_id: '',
                    agent_name: msg.agent_name || '',
                    user_name: msg.user_name || '',
                    attributes: msg.attributes || {}
                }

                // Check if message has Shopify data in attributes
                if (msg.attributes?.shopify_output && typeof msg.attributes.shopify_output === 'object') {
                    return {
                        ...messageObj,
                        message_type: 'product',
                        shopify_output: msg.attributes.shopify_output
                    }
                }

                return messageObj
            })

            messages.value = [
                ...historyMessages.filter(newMsg => 
                    !messages.value.some(existingMsg => 
                        existingMsg.message === newMsg.message && 
                        existingMsg.created_at === newMsg.created_at
                    )
                ),
                ...messages.value
            ]
        }
    }

    // Add rating submission handler
    const handleRatingSubmitted = (data: { success: boolean, message: string }) => {
        if (data.success) {
            messages.value.push({
                message: 'Thank you for your feedback!',
                message_type: 'system',
                created_at: new Date().toISOString(),
                session_id: ''
            })
        }
    }

    // Add rating submission function
    const submitRating = async (rating: number, feedback?: string) => {
        if (!socket || !rating) return
        
        socket.emit('submit_rating', {
            rating,
            feedback
        })
    }

    // Send message function
    const sendMessage = async (newMessage: string, email: string) => {
        if (!socket || !newMessage.trim()) return
        
        if(!humanAgent.value.human_agent_name) 
           loading.value = true
        messages.value.push({
            message: newMessage,
            message_type: 'user',
            created_at: new Date().toISOString(),
            session_id: ''
        })

        socket.emit('chat', {
            message: newMessage,
            email: email
        })

        hasStartedChat.value = true
    }

    // Chat history functions
    const loadChatHistory = async () => {
        if (!socket) return

        try {
            loadingHistory.value = true
            socket.emit('get_chat_history')
        } catch (error) {
            console.error('Failed to load chat history:', error)
        } finally {
            loadingHistory.value = false
        }
    }

    const cleanup = () => {
        if (socket) {
            socket.removeAllListeners()
            socket.disconnect()
            socket = null
        }
        onTakeoverCallback = null
    }

    return {
        messages,
        loading,
        errorMessage,
        showError,
        loadingHistory,
        hasStartedChat,
        connectionStatus,
        sendMessage,
        loadChatHistory,
        connect,
        reconnect,
        cleanup,
        humanAgent,
        onTakeover,
        submitRating
    }
} 