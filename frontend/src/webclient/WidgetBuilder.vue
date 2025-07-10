<!--
ChatterMate - Widget Builder
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
-->

<script setup lang="ts">
// @ts-nocheck
import { ref, onMounted, computed, onUnmounted, watch, nextTick } from 'vue'
import {
    isValidEmail} from '../types/widget'
import { marked } from 'marked'
import { widgetEnv } from './widget-env'
import { useWidgetStyles } from '../composables/useWidgetStyles'
import { useWidgetSocket } from '../composables/useWidgetSocket'
import { useWidgetCustomization } from '../composables/useWidgetCustomization'
import { formatDistanceToNow } from 'date-fns'
// Add marked configuration before the props definition
marked.setOptions({
    renderer: new marked.Renderer(),
    gfm: true,
    breaks: true
})

// Configure marked renderer to add target="_blank" to links
const renderer = new marked.Renderer();
const linkRenderer = renderer.link;
// @ts-ignore
renderer.link = (href, title, text) => {
    // @ts-ignore
    const html = linkRenderer.call(renderer, href, title, text);
    return html.replace(/^<a /, '<a target="_blank" rel="nofollow" ');
};

marked.use({ renderer })

const props = defineProps<{
    widgetId: string
}>()

// Get widget ID from props or initial data
const widgetId = computed(() => props.widgetId || window.__INITIAL_DATA__?.widgetId)

const {
    customization,
    agentName,
    applyCustomization,
    initializeFromData
} = useWidgetCustomization()

const {
    messages,
    loading,
    errorMessage,
    showError,
    loadingHistory,
    hasStartedChat,
    connectionStatus,
    sendMessage: socketSendMessage,
    loadChatHistory,
    connect,
    reconnect,
    cleanup,
    humanAgent,
    onTakeover,
    submitRating: socketSubmitRating
} = useWidgetSocket()

const newMessage = ref('')
const isExpanded = ref(true)
const emailInput = ref('')
const hasConversationToken = ref(false)

// Add loading state
const isInitializing = ref(true)

// Add these to the script setup section after the imports
const TOKEN_KEY = 'ctid'
// @ts-ignore
const token = ref(window.__INITIAL_DATA__?.initialToken || localStorage.getItem(TOKEN_KEY))
const hasToken = computed(() => !!token.value)

// Initialize from initial data
initializeFromData()
const initialData = window.__INITIAL_DATA__

if (initialData?.initialToken) {
    token.value = initialData.initialToken
    // Notify parent window to store token
    window.parent.postMessage({ 
        type: 'TOKEN_UPDATE', 
        token: initialData.initialToken 
    }, '*')
    hasConversationToken.value = true
}

// Add after socket initialization
const messagesContainer = ref<HTMLElement | null>(null)

// Computed styles
const {
    chatStyles,
    chatIconStyles,
    agentBubbleStyles,
    userBubbleStyles,
    messageNameStyles,
    headerBorderStyles,
    photoUrl,
    shadowStyle
} = useWidgetStyles(customization)

// Update the computed property for message input enabled state
const isMessageInputEnabled = computed(() => {
    return (hasToken.value || isValidEmail(emailInput.value.trim())) && 
           connectionStatus.value === 'connected' && !loading.value
})

// Update the sendMessage function
const sendMessage = async () => {
    if (!newMessage.value.trim()) return

    // If first message, fetch customization with email first
    if (!hasStartedChat.value && emailInput.value) {
        await checkAuthorization()
    }

    await socketSendMessage(newMessage.value, emailInput.value)
    newMessage.value = ''
}

// Handle enter key
const handleKeyPress = (event: KeyboardEvent) => {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault()
        sendMessage()
    }
}

// Update the checkAuthorization function
const checkAuthorization = async () => {
    try {
        if (!widgetId.value) {
            console.error('Widget ID is not available')
            return false
        }

        const url = new URL(`${widgetEnv.API_URL}/widgets/${widgetId.value}`)
        if (emailInput.value.trim() && isValidEmail(emailInput.value.trim())) {
            url.searchParams.append('email', emailInput.value.trim())
        }

        const headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        if (token.value) {
            headers['Authorization'] = `Bearer ${token.value}`
        }

        const response = await fetch(url, {
            headers
        })

        if (response.status === 401) {
            hasConversationToken.value = false
            return false
        }
        
        const data = await response.json()
        
        // Update token if new one is provided
        if (data.token) {
            token.value = data.token
            localStorage.setItem(TOKEN_KEY, data.token)
            // Notify parent window of token update
            window.parent.postMessage({ type: 'TOKEN_UPDATE', token: data.token }, '*')
        }

        hasConversationToken.value = true
        
        // Connect socket and verify connection success
        const connected = await connect()
        if (!connected) {
            console.error('Failed to connect to chat service')
            return false
        }

        await fetchChatHistory()
        
        if (data.agent?.customization) {
            applyCustomization(data.agent.customization)
        }
        if(data.agent && !data?.human_agent) {
            agentName.value = data.agent.name
        }
        if (data?.human_agent) {
            humanAgent.value = data.human_agent
        }
        return true
    } catch (error) {
        console.error('Error checking authorization:', error)
        hasConversationToken.value = false
        return false
    } finally {
        isInitializing.value = false
    }
}

// Load history when chat starts
const fetchChatHistory = async () => {
    if (!hasStartedChat.value && hasConversationToken.value) {
        hasStartedChat.value = true
        await loadChatHistory()
    }
}

// Add this after messagesContainer ref definition
const scrollToBottom = () => {
    if (messagesContainer.value) {
        messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
    }
}

// Add watch effect for messages
watch(() => messages.value, (newMessages) => {
    // Scroll to bottom when new messages arrive
    nextTick(() => {
        scrollToBottom()
    })
    
   
    // Check for end chat in the last message
    if (newMessages.length > 0) {

        const lastMessage = newMessages[newMessages.length - 1]
        
        handleEndChat(lastMessage)
    }
}, { deep: true })

// Add reconnect handler
const handleReconnect = async () => {
    const connected = await reconnect()
    if (connected) {
        await checkAuthorization()
    }
}

// Add these refs after other refs
const showRatingDialog = ref(false)
const currentRating = ref(0)
const ratingFeedback = ref('')
const currentSessionId = ref('')

// Add these refs for star rating
const hoverRating = ref(0)
const isSubmittingRating = ref(false)

// Add this after other computed properties
const ratingEnabled = computed(() => {
    const lastMessage = messages.value[messages.value.length - 1]
    return lastMessage?.attributes?.request_rating || false
})

// Add this after other methods
const handleEndChat = (message) => {
    
    if (message.attributes?.end_chat && message.attributes?.request_rating) {
        // Determine the agent name with proper fallbacks
        const displayAgentName = message.agent_name || humanAgent.value?.human_agent_name || agentName.value || 'our agent'
        
        messages.value.push({
            message: `Rate the chat session that you had with ${displayAgentName}`,
            message_type: 'rating',
            created_at: new Date().toISOString(),
            session_id: message.session_id,
            agent_name: displayAgentName,
            showFeedback: false
        })
        currentSessionId.value = message.session_id
    }
}

const handleStarHover = (rating: number) => {
    if (!isSubmittingRating.value) {
        hoverRating.value = rating
    }
}

const handleStarLeave = () => {
    if (!isSubmittingRating.value) {
        const lastMessage = messages.value[messages.value.length - 1]
        hoverRating.value = lastMessage?.selectedRating || 0
    }
}

const handleStarClick = async (rating: number) => {
    if (!isSubmittingRating.value) {
        hoverRating.value = rating
        // Show feedback input after rating selection
        const lastMessage = messages.value[messages.value.length - 1]
        if (lastMessage && lastMessage.message_type === 'rating') {
            lastMessage.showFeedback = true
            lastMessage.selectedRating = rating
        }
    }
}

const handleSubmitRating = async (sessionId: string, rating: number, feedback: string | null = null) => {
    try {
        isSubmittingRating.value = true
        await socketSubmitRating(rating, feedback)
        
        // Instead of removing the rating message, mark it as submitted
        const lastMessage = messages.value.find(msg => msg.message_type === 'rating')
        if (lastMessage) {
            lastMessage.isSubmitted = true
            lastMessage.finalRating = rating
            lastMessage.finalFeedback = feedback
        }
    } catch (error) {
        console.error('Failed to submit rating:', error)
    } finally {
        isSubmittingRating.value = false
    }
}

const handleAddToCart = (message) => {
    const productData = message.shopify_output || {
        id: message.product_id,
        title: message.product_title,
        price: message.product_price,
        image: message.product_image,
        vendor: message.product_vendor
    };
    
    if (productData) {
        // Send a message to the parent window (the main shop)
        window.parent.postMessage({
            type: 'ADD_TO_CART',
            product: productData
        }, '*');
    }
};

const handleAddToCartFromCarousel = (product) => {
    if (product) {
        window.parent.postMessage({
            type: 'ADD_TO_CART',
            product: product
        }, '*');
    }
};

const handleViewDetails = (productId) => {
    if (productId) {
        window.parent.postMessage({
            type: 'VIEW_PRODUCT',
            productId: productId
        }, '*');
    }
};

// Add this function in the script section after the other helper functions
const removeUrls = (text) => {
    if (!text) return '';
    // Replace URLs with empty string
    // This regex looks for http/https URLs and removes them
    return text.replace(/https?:\/\/[^\s\)]+/g, '[link removed]');
}

onMounted(async () => {
    const isAuthorized = await checkAuthorization()
    if (!isAuthorized) {
        connectionStatus.value = 'connected'
        return
    }

    // Register takeover callback
    onTakeover(async () => {
        await checkAuthorization()
    })

    // Listen for scroll message from parent
    window.addEventListener('message', (event) => {
        if (event.data.type === 'SCROLL_TO_BOTTOM') {
            scrollToBottom()
        }
        if (event.data.type === 'TOKEN_RECEIVED') {
            // Parent confirmed token storage
            localStorage.setItem(TOKEN_KEY, event.data.token)
        }
    })
})

onUnmounted(() => {
    window.removeEventListener('message', (event) => {
        if (event.data.type === 'SCROLL_TO_BOTTOM') {
            scrollToBottom()
        }
    })
    cleanup()
})
</script>

<template>
    <div class="chat-container" :class="{ collapsed: !isExpanded }" :style="shadowStyle">
        <!-- Loading State -->
        <div v-if="isInitializing" class="initializing-overlay">
            <div class="loading-spinner">
                <div class="dot"></div>
                <div class="dot"></div>
                <div class="dot"></div>
            </div>
            <div class="loading-text">Initializing chat...</div>
        </div>

        <!-- Connection Status -->
        <div v-if="!isInitializing && connectionStatus !== 'connected'" class="connection-status" :class="connectionStatus">
            <div v-if="connectionStatus === 'connecting'" class="connecting-message">
                Connecting to chat service...
                <div class="loading-dots">
                    <div class="dot"></div>
                    <div class="dot"></div>
                    <div class="dot"></div>
                </div>
            </div>
            <div v-else-if="connectionStatus === 'failed'" class="failed-message">
                Connection failed. 
                <button @click="handleReconnect" class="reconnect-button">
                    Click here to reconnect
                </button>
            </div>
        </div>

        <!-- Error Alert -->
        <div v-if="showError" class="error-alert" :style="chatIconStyles">
            {{ errorMessage }}
        </div>

        <!-- Chat Panel -->
        <div class="chat-panel" :style="chatStyles" v-if="isExpanded">
            <div class="chat-header" :style="headerBorderStyles">
                <div class="header-content">
                    <img 
                        v-if="humanAgent.human_agent_profile_pic || photoUrl" 
                        :src="humanAgent.human_agent_profile_pic || photoUrl" 
                        :alt="humanAgent.human_agent_name || agentName" 
                        class="header-avatar"
                    >
                    <div class="header-info">
                        <h3 :style="messageNameStyles">{{ humanAgent.human_agent_name || agentName }}</h3>
                        <div class="status">
                            <span class="status-indicator online"></span>
                            <span class="status-text" :style="messageNameStyles">Online</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Loading indicator for history -->
            <div v-if="loadingHistory" class="loading-history">
                <div class="loading-spinner">
                    <div class="dot"></div>
                    <div class="dot"></div>
                    <div class="dot"></div>
                </div>
            </div>

            <div class="chat-messages" ref="messagesContainer">
                <template v-for="(message, index) in messages" :key="index">
                    <div 
                        :class="[
                            'message',
                            message.message_type === 'bot' ? 'agent-message' : 
                            message.message_type === 'agent' ? 'agent-message' : 
                            message.message_type === 'system' ? 'system-message' :
                            message.message_type === 'rating' ? 'rating-message' :
                            message.message_type === 'product' || message.shopify_output ? 'product-message' :
                            'user-message'
                        ]"
                    >
                        <div class="message-bubble" 
                            :style="message.message_type === 'system' || message.message_type === 'rating' || message.message_type === 'product' || message.shopify_output ? {} : 
                                   message.message_type === 'user' ? userBubbleStyles : 
                                   agentBubbleStyles"
                        >
                            <template v-if="message.message_type === 'rating'">
                                <div class="rating-content">
                                    <p class="rating-prompt">Rate the chat session that you had with {{ message.agent_name || humanAgent.human_agent_name || agentName || 'our agent' }}</p>
                                    
                                    <!-- Rating stars -->
                                    <div class="star-rating" :class="{ 'submitted': isSubmittingRating || message.isSubmitted }">
                                        <button
                                            v-for="star in 5"
                                            :key="star"
                                            class="star-button"
                                            :class="{
                                                'warning': star <= (message.isSubmitted ? message.finalRating : (hoverRating || message.selectedRating)) && (message.isSubmitted ? message.finalRating : (hoverRating || message.selectedRating)) <= 3,
                                                'success': star <= (message.isSubmitted ? message.finalRating : (hoverRating || message.selectedRating)) && (message.isSubmitted ? message.finalRating : (hoverRating || message.selectedRating)) > 3,
                                                'selected': star <= (message.isSubmitted ? message.finalRating : (hoverRating || message.selectedRating))
                                            }"
                                            @mouseover="!message.isSubmitted && handleStarHover(star)"
                                            @mouseleave="!message.isSubmitted && handleStarLeave"
                                            @click="!message.isSubmitted && handleStarClick(star)"
                                            :disabled="isSubmittingRating || message.isSubmitted"
                                        >
                                            ★
                                        </button>
                                    </div>
                                    
                                    <!-- Feedback input before submission -->
                                    <div v-if="message.showFeedback && !message.isSubmitted" class="feedback-wrapper">
                                        <div class="feedback-section">
                                            <input
                                                v-model="message.feedback"
                                                placeholder="Please share your feedback (optional)"
                                                :disabled="isSubmittingRating"
                                                maxlength="500"
                                                class="feedback-input"
                                            />
                                            <div class="feedback-counter">{{ message.feedback?.length || 0 }}/500</div>
                                        </div>
                                        <button
                                            @click="handleSubmitRating(message.session_id, hoverRating, message.feedback)"
                                            :disabled="isSubmittingRating || !hoverRating"
                                            class="submit-rating-button"
                                            :style="{ backgroundColor: customization.accent_color || 'var(--primary-color)' }"
                                        >
                                            {{ isSubmittingRating ? 'Submitting...' : 'Submit Rating' }}
                                        </button>
                                    </div>
                                    
                                    <!-- Submitted feedback display -->
                                    <div v-if="message.isSubmitted && message.finalFeedback" class="submitted-feedback-wrapper">
                                        <div class="submitted-feedback">
                                            <p class="submitted-feedback-text">{{ message.finalFeedback }}</p>
                                        </div>
                                        
                                    </div>
                                    
                                    <!-- Thank you message if no feedback was provided -->
                                    <div v-else-if="message.isSubmitted" class="submitted-message">
                                        Thank you for your rating!
                                    </div>
                                </div>
                            </template>
                            <template v-else-if="message.shopify_output || message.message_type === 'product'">
                                <div class="product-message-container">
                                    <!-- Display the message text -->
                                    <div v-if="message.message" v-html="marked(removeUrls(message.message), { renderer })" class="product-message-text"></div>
                                    
                                    <!-- Always use carousel/list display -->
                                    <div v-if="message.shopify_output?.products && message.shopify_output.products.length > 0" class="products-carousel">
                                        <h3 class="carousel-title">Products</h3>
                                        <div class="carousel-items">
                                            <div v-for="product in message.shopify_output.products" :key="product.id" class="product-card-compact carousel-item">
                                                <div class="product-image-compact" v-if="product.image?.src">
                                                    <img :src="product.image.src" :alt="product.title" class="product-thumbnail">
                                                </div>
                                                <div class="product-info-compact">
                                                    <div class="product-text-area">
                                                        <div class="product-title-compact">{{ product.title }}</div>
                                                        <div class="product-variant-compact" v-if="product.variant_title && product.variant_title !== 'Default Title'">{{ product.variant_title }}</div>
                                                        <div class="product-price-compact">{{ product.price_formatted || `₹${product.price}` }}</div>
                                                    </div>
                                                    <div class="product-actions-compact">
                                                        <button 
                                                            class="view-details-button-compact"
                                                            @click="handleViewDetails(product.id)"
                                                        >
                                                            View product <span class="external-link-icon">↗</span>
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>

                                    <!-- No products found message (remains the same) -->
                                    <div v-else-if="message.shopify_output?.products && message.shopify_output.products.length === 0" class="no-products-message">
                                        <p>No products found.</p>
                                    </div>
                                    <!-- Add a message if shopify_output exists but has no products array (edge case) -->
                                     <div v-else-if="message.shopify_output && !message.shopify_output.products" class="no-products-message">
                                        <p>No products to display.</p>
                                     </div>
                                </div>
                            </template>
                            <template v-else>
                                <div v-html="marked(message.message, { renderer })"></div>
                            </template>
                        </div>
                        <div class="message-info">
                            <span v-if="message.message_type === 'user'" class="agent-name">
                                You
                            </span>
                        </div>
                    </div>
                </template>

                <!-- Typing indicator -->
                <div v-if="loading" class="typing-indicator">
                    <div class="dot"></div>
                    <div class="dot"></div>
                    <div class="dot"></div>
                </div>
            </div>

            <div class="chat-input" :style="agentBubbleStyles">
                <div class="email-input" v-if="!hasStartedChat && !hasConversationToken">
                    <input 
                        v-model="emailInput"
                        type="email" 
                        placeholder="Enter your email address to begin" 
                        :disabled="loading || connectionStatus !== 'connected'"
                        :class="{ 
                            'invalid': emailInput.trim() && !isValidEmail(emailInput.trim()),
                            'disabled': connectionStatus !== 'connected'
                        }"
                    >
                </div>
                <div class="message-input">
                    <input 
                        v-model="newMessage" 
                        type="text" 
                        :placeholder="connectionStatus === 'connected' ? 'Type a message...' : 'Connecting...'" 
                        @keypress="handleKeyPress"
                        :disabled="!isMessageInputEnabled"
                        :class="{ 'disabled': connectionStatus !== 'connected' }"
                    >
                    <button 
                        class="send-button" 
                        :style="userBubbleStyles" 
                        @click="sendMessage"
                        :disabled="!newMessage.trim() || !isMessageInputEnabled"
                    >
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M5 12L3 21L21 12L3 3L5 12ZM5 12L13 12" stroke="currentColor" stroke-width="2"
                                stroke-linecap="round" stroke-linejoin="round" />
                        </svg>
                    </button>
                </div>
            </div>

            <!-- Powered by footer -->
            <div class="powered-by" :style="messageNameStyles">
                Powered by ChatterMate
            </div>
        </div>

        <!-- Rating Dialog -->
        <div v-if="showRatingDialog" class="rating-dialog">
            <div class="rating-content">
                <h3>Rate your conversation</h3>
                <div class="star-rating">
                    <button 
                        v-for="star in 5" 
                        :key="star"
                        @click="currentRating = star"
                        :class="{ active: star <= currentRating }"
                        class="star-button"
                    >
                        ★
                    </button>
                </div>
                <textarea
                    v-model="ratingFeedback"
                    placeholder="Additional feedback (optional)"
                    class="rating-feedback"
                ></textarea>
                <div class="rating-actions">
                    <button 
                        @click="submitRating(currentRating, ratingFeedback)"
                        :disabled="!currentRating"
                        class="submit-button"
                        :style="userBubbleStyles"
                    >
                        Submit
                    </button>
                    <button 
                        @click="showRatingDialog = false"
                        class="skip-rating"
                    >
                        Skip
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.chat-container {
    width: 100%;
    height: 580px;
    display: flex;
    flex-direction: column;
    background: transparent;
    overflow: hidden;
    position: relative;
    border-radius: var(--radius-lg);
}

.chat-container.collapsed {
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
}

.chat-panel {
    background: var(--background-base);
    display: flex;
    flex-direction: column;
    height: 100%;
    transition: all 0.3s ease;
    border-radius: 0;
}

.chat-header {
    padding: var(--space-md);
    display: flex;
    justify-content: flex-start;
    align-items: center;
}

.header-content {
    display: flex;
    align-items: center;
    gap: var(--space-sm);
}

.header-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    object-fit: cover;
}

.header-info {
    display: flex;
    flex-direction: column;
}

.header-info h3 {
    margin: 0;
    font-size: var(--text-md);
}

.status {
    display: flex;
    align-items: center;
    gap: var(--space-xs);
    font-size: var(--text-sm);
}

.status-indicator {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--error-color);
}

.status-indicator.online {
    background: var(--success-color);
}

.chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: var(--space-md);
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
    -webkit-overflow-scrolling: touch;
    scroll-behavior: smooth;
    margin-top: var(--space-sm);
}

.message {
    display: flex;
    gap: var(--space-sm);
    max-width: 85%;
    align-items: flex-start;
    margin-bottom: var(--space-md);
}

.message-avatar {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    object-fit: cover;
    margin-top: 4px;
}

.message-bubble {
    padding: 2px 14px;
    border-radius: 20px;
    line-height: 1.4;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    max-width: 85%;
}

.user-message {
    align-self: flex-end;
    flex-direction: row-reverse;
}

.user-message .message-bubble {
    border-bottom-right-radius: 4px;
}

.assistant-message .message-bubble {
    border-bottom-left-radius: 4px;
    background-color: #f5f5f5;
    /* Light gray background for assistant messages */
}

.chat-input {
    padding: var(--space-md);
    border-top: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    gap: var(--space-sm);
}

.email-input {
    width: 85%;
}

.email-input input {
    width: 100%;
    padding: var(--space-sm) var(--space-md);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
}

.email-input input.invalid {
    border-color: var(--error-color);
}

.email-input input.invalid:focus {
    outline-color: var(--error-color);
}

.message-input {
    display: flex;
    gap: var(--space-sm);
}

.message-input input {
    flex: 1;
    padding: var(--space-sm) var(--space-md);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
}

.message-input input:disabled {
    background-color: rgba(0, 0, 0, 0.05);
    cursor: not-allowed;
}

.send-button {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: var(--space-sm);
    min-width: 40px;
    height: 40px;
    border: none;
    border-radius: var(--radius-lg);
    cursor: pointer;
    color: white;
}

.send-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.loading {
    display: flex;
    gap: 4px;
    padding: 12px 16px;
}

.dot {
    width: 8px;
    height: 8px;
    background: currentColor;
    border-radius: 50%;
    opacity: 0.6;
    animation: bounce 1.4s infinite ease-in-out;
}

.dot:nth-child(1) {
    animation-delay: -0.32s;
}

.dot:nth-child(2) {
    animation-delay: -0.16s;
}

@keyframes bounce {

    0%,
    80%,
    100% {
        transform: scale(0);
    }

    40% {
        transform: scale(1);
    }
}

.powered-by {
    text-align: center;
    padding: var(--space-xs);
    font-size: 0.75rem;
    opacity: 0.7;
    border-top: 1px solid rgba(0, 0, 0, 0.1);
    margin-top: auto;
}

.error-alert {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    padding: 12px;
    text-align: center;
    color: white;
    z-index: 100;
    animation: slideDown 0.3s ease-out;
    border-radius: 24px 24px 0 0;
}

@keyframes slideDown {
    from {
        transform: translateY(-100%);
    }
    to {
        transform: translateY(0);
    }
}

.chat-container.collapsed .error-alert {
    display: none;
}

@media (max-width: 768px) {

    .chat-container,
    .chat-container.collapsed {
        width: 100%;
        height: 580px;
        border-radius: var(--radius-lg);
    }

    .chat-panel {
        height: 100%;
        border-radius: 0;
    }

    .chat-messages {
        padding: var(--space-sm);
    }

    .chat-toggle {
        width: 48px;
        height: 48px;
        font-size: 14px;
    }
}

.loading-history {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: var(--space-sm);
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    background: rgba(255, 255, 255, 0.9);
    z-index: 10;
}

.loading-spinner {
    display: flex;
    gap: 4px;
}

.message-time {
    font-size: 0.75rem;
    opacity: 0.7;
    margin-top: 4px;
    text-align: right;
}

.typing-indicator {
    display: flex;
    gap: 4px;
    padding: 12px 16px;
    margin-top: var(--space-md);
}

.connection-status {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    padding: 12px;
    text-align: center;
    z-index: 100;
    background: rgba(255, 255, 255, 0.95);
    border-bottom: 1px solid var(--border-color);
}

.connecting-message {
    color: var(--text-color);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
}

.failed-message {
    color: var(--error-color);
}

.reconnect-button {
    background: none;
    border: none;
    color: var(--primary-color);
    text-decoration: underline;
    cursor: pointer;
    padding: 4px 8px;
    margin-left: 8px;
}

.reconnect-button:hover {
    color: var(--primary-dark);
}

.loading-dots {
    display: flex;
    gap: 4px;
    margin-left: 4px;
}

.loading-dots .dot {
    width: 6px;
    height: 6px;
    background: currentColor;
    border-radius: 50%;
    animation: bounce 1.4s infinite ease-in-out;
}

.loading-dots .dot:nth-child(1) { animation-delay: -0.32s; }
.loading-dots .dot:nth-child(2) { animation-delay: -0.16s; }

@keyframes bounce {
    0%, 80%, 100% { transform: scale(0); }
    40% { transform: scale(1); }
}

.message-input input.disabled,
.email-input input.disabled {
    background-color: rgba(0, 0, 0, 0.05) !important;
    cursor: not-allowed;
    color: var(--text-muted);
}

.message-input input.disabled::placeholder,
.email-input input.disabled::placeholder {
    color: var(--text-muted);
}

/* Add styles for agent messages */
.message.agent-message {
    margin-right: auto;
    justify-content: flex-start;
}

.agent-name {
    font-size: 12px;
    color: #9ca3af;
    margin-top: 4px;
    margin-left: 8px;
}

.message-info {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 2px;
    margin-top: 4px;
}

/* Add system message styles */
.message.system-message {
    align-self: center;
    max-width: 100%;
    margin: var(--space-sm) 0;
}

.system-message .message-bubble {
    background: rgba(0, 0, 0, 0.05);
    color: var(--text-muted);
    font-size: 0.85em;
    padding: var(--space-xs) var(--space-md);
    border-radius: var(--radius-lg);
    text-align: center;
}

.initializing-overlay {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(255, 255, 255, 0.95);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    border-radius: var(--radius-lg);
}

.loading-text {
    margin-top: var(--space-md);
    color: var(--text-color);
    font-size: var(--text-md);
}

.loading-spinner {
    display: flex;
    gap: 6px;
}

.loading-spinner .dot {
    width: 10px;
    height: 10px;
    background: var(--primary-color);
    border-radius: 50%;
    animation: bounce 1.4s infinite ease-in-out;
}

.loading-spinner .dot:nth-child(1) { animation-delay: -0.32s; }
.loading-spinner .dot:nth-child(2) { animation-delay: -0.16s; }

.rating-dialog {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.rating-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1rem;
    padding: 0.5rem;
    width: 100%;
}

.star-rating {
    display: flex;
    gap: 0.75rem;
    justify-content: center;
    margin: 0 0 24px;
}

.star-button {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 28px;
    color: #d1d5db;
    transition: all var(--transition-fast);
    padding: 0 4px;
    transform-origin: center;
    line-height: 1;
}

.star-button:hover {
    transform: scale(1.1);
}

.star-button.selected {
    transform: scale(1.05);
}

.star-button.warning {
    color: var(--error-color);
    text-shadow: 0 0 5px rgba(239, 68, 68, 0.3);
}

.star-button.success {
    color: var(--success-color);
    text-shadow: 0 0 5px rgba(16, 185, 129, 0.3);
}

.star-button:disabled {
    cursor: not-allowed;
    opacity: 0.7;
}

.submit-button {
    padding: 12px 20px;
    border: none;
    border-radius: var(--radius-md);
    background-color: var(--primary-color);
    color: white;
    cursor: pointer;
    font-size: var(--text-base);
    font-weight: 600;
    transition: all var(--transition-fast);
    width: 100%;
    text-align: center;
    display: block;
    margin-top: 16px;
}

.submit-button:hover:not(:disabled) {
    opacity: 0.9;
}

.submit-button:disabled {
    opacity: 0.7;
    cursor: not-allowed;
}

.rating-prompt {
    font-size: var(--text-sm);
    color: var(--text-primary);
    margin-bottom: 24px;
    text-align: center;
    font-weight: 500;
}

.rating-message {
    align-self: center;
    width: 100%;
    max-width: 500px;
    margin: var(--space-sm) 0;
}

.rating-message .message-bubble {
    background-color: white;
    padding: var(--space-md) var(--space-md);
    border-radius: 12px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.08);
    border: 1px solid var(--border-color);
    transition: all var(--transition-normal);
}

.rating-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    padding: 0;
}

.rating-prompt {
    font-size: var(--text-sm);
    color: var(--text-primary);
    margin-bottom: 20px;
    text-align: center;
    font-weight: 500;
}

.star-rating {
    display: flex;
    gap: 0.75rem;
    justify-content: center;
    margin: 0 0 20px;
}

.feedback-wrapper {
    width: 100%;
}

.feedback-section {
    display: flex;
    flex-direction: column;
    gap: 2px;
    width: 100%;
    padding: 0;
    margin-bottom: 4px;
}

.feedback-input {
    padding: 10px 14px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    font-size: var(--text-sm);
    transition: border-color var(--transition-fast);
    background-color: white;
    box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.05);
}

.feedback-input:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 2px rgba(243, 70, 17, 0.1);
}

.feedback-counter {
    font-size: var(--text-xs);
    color: var(--text-muted);
    text-align: right;
    margin-right: 4px;
    padding: 0 4px;
}

.submit-rating-button {
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    background-color: var(--primary-color);
    color: white;
    cursor: pointer;
    font-size: var(--text-base);
    font-weight: 600;
    transition: all var(--transition-fast);
    width: 100%;
    text-align: center;
    display: block;
    margin: 12px 0 0;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.submit-rating-button:hover:not(:disabled) {
    opacity: 0.95;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    transform: translateY(-1px);
}

.submit-rating-button:active:not(:disabled) {
    transform: translateY(0);
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
}

.submit-rating-button:disabled {
    opacity: 0.7;
    cursor: not-allowed;
}

.submitted .star-button {
    pointer-events: none;
    opacity: 0.7;
}

.submitted-feedback-wrapper {
    width: 100%;
    margin-top: 16px;
}

.submitted-feedback {
    padding: 12px 16px;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    background-color: #f9f9f9;
    margin-bottom: 8px;
}

.submitted-feedback-text {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin: 0;
    line-height: 1.5;
    word-break: break-word;
}

.submitted-message {
    font-size: var(--text-sm);
    color: var(--success-color);
    text-align: center;
    font-weight: 500;
    margin-top: 8px;
}

/* Compact Product Card Styles - UPDATED */
.message.product-message .message-bubble {
    padding: 0;
    background: none;
    border: none;
    box-shadow: none;
    width: 100%;
    max-width: none;
}

.product-card-compact {
    display: flex; 
    flex-direction: row; 
    align-items: flex-start; 
    border: 1px solid var(--border-color); /* Keep border, ensure it uses token */
    border-radius: var(--radius-lg); /* Slightly larger radius for modern feel */
    overflow: hidden;
    background-color: var(--background-base);
    box-shadow: var(--shadow-sm); /* Use softer shadow */
    padding: var(--space-md); /* Increased padding */
    gap: var(--space-md); /* Increased gap */
    width: 100%; 
    transition: box-shadow var(--transition-fast); /* Add transition */
}

.product-card-compact:hover {
    box-shadow: var(--shadow-md); /* Slightly elevate on hover */
}

.product-card-compact.carousel-item {
    flex-direction: column; 
    align-items: stretch;
    width: 160px; 
    flex-shrink: 0;
    padding: 0; 
    gap: 0;
    height: auto; 
    border-radius: var(--radius-md); /* Keep standard radius for carousel */
    box-shadow: var(--shadow-sm);
}

.product-card-compact.carousel-item:hover {
     box-shadow: var(--shadow-md);
}

.product-card-compact.single-product {
    max-width: 280px; /* Reduced max width */
    align-self: flex-start; 
    padding: var(--space-sm); /* Reduced padding */
    gap: var(--space-sm); /* Reduced gap */
    display: flex;
    flex-direction: row;
    align-items: flex-start; /* Align items at the start */
}

.product-card-compact.single-product .product-image-compact {
    width: 50px; /* Smaller image */
    height: 50px;
    border-radius: var(--radius-xs); /* Smaller radius */
    flex-shrink: 0;
}

.product-card-compact.single-product .product-info-compact {
    display: flex;
    flex-direction: column;
    justify-content: space-between; /* Space out text and button */
    flex: 1; /* Take remaining space */
    min-height: 50px; /* Match image height */
    gap: var(--space-xxs); /* Reduced gap */
}

.product-card-compact.single-product .product-text-info {
    display: flex;
    flex-direction: column;
    gap: 1px; /* Very small gap between text lines */
}

.product-card-compact.single-product .product-title-compact {
    font-size: var(--text-xs); /* Smaller font */
    font-weight: 500;
    line-height: 1.3; 
    white-space: normal; /* Allow wrapping */
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
    text-overflow: ellipsis;
    margin: 0;
}

.product-card-compact.single-product .product-variant-compact {
    font-size: 10px; /* Even smaller variant text */
    color: var(--text-muted);
    line-height: 1.2;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.product-card-compact.single-product .product-price-compact {
    font-size: var(--text-xs); /* Smaller font */
    font-weight: 600;
    margin-top: 2px;
}

.product-card-compact.single-product .product-actions-compact {
    margin-top: auto; /* Push button to bottom */
    width: 100%; /* Make container full width */
}

.product-card-compact.single-product .view-details-button-compact {
    width: 100%; /* Make button full width */
    padding: 5px 8px; /* Smaller padding */
    font-size: 11px; /* Smaller font */
    justify-content: center; /* Center text/icon */
}

.product-image-compact {
    position: relative;
    width: 60px; /* Fixed width for thumbnail */
    height: 60px; /* Fixed height for thumbnail */
    aspect-ratio: 1 / 1;
    background-color: var(--background-soft);
    overflow: hidden;
    border: none; /* Remove border */
    border-radius: var(--radius-sm); /* Rounded corners */
    flex-shrink: 0; /* Prevent image from shrinking */
}

.product-card-compact.carousel-item .product-image-compact {
    width: 100%;
    height: auto;
    aspect-ratio: 1 / 1;
    border-radius: 0;
    border-bottom: 1px solid var(--border-color);
}

.product-thumbnail {
    display: block;
    width: 100%;
    height: 100%;
    object-fit: cover;
    transition: transform var(--transition-fast);
}

.product-thumbnail:hover {
    transform: scale(1.05);
}

.product-info-compact {
    display: flex;
    flex-direction: column;
    gap: 2px; /* Reduced gap */
    flex: 1; /* Allow info to take remaining space */
    justify-content: center; /* Center content vertically */
    min-width: 0; /* Prevent flex item overflow */
}

.product-card-compact.carousel-item .product-info-compact {
    padding: var(--space-sm);
    gap: var(--space-xs);
    justify-content: flex-start; /* Align items to start for carousel */
}

.product-title-compact {
    margin: 0;
    font-size: var(--text-sm);
    font-weight: 500;
    line-height: 1.4;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap; /* Single line */
}

.product-variant-compact {
    font-size: var(--text-xs);
    color: var(--text-muted);
    line-height: 1.3;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.product-price-compact {
    font-size: var(--text-sm); /* Adjusted size */
    font-weight: 600; /* Adjusted weight */
    color: var(--text-primary);
    white-space: nowrap;
    margin-top: 2px; /* Small top margin */
}

.product-actions-compact {
    display: flex;
    gap: var(--space-xs);
    margin-top: var(--space-sm); /* Add margin for single card */
}

.product-actions-compact.single {
     justify-content: flex-start; /* Align button left */
}

.product-card-compact.carousel-item .product-actions-compact {
    margin-top: auto; /* Push actions to bottom */
    padding-top: var(--space-xs);
}

.add-to-cart-button-compact,
.view-details-button-compact {
    flex: none; /* Don't grow */
    padding: 6px 10px; /* Adjusted padding */
    border: 1px solid var(--border-color);
    border-radius: var(--radius-sm);
    font-weight: 500;
    font-size: var(--text-xs);
    cursor: pointer;
    transition: all var(--transition-fast);
    text-align: center;
    white-space: nowrap;
    background-color: var(--background-base);
    color: var(--text-secondary);
    line-height: 1;
}

.add-to-cart-button-compact {
    background-color: var(--primary-color);
    color: white;
    border-color: transparent;
    box-shadow: var(--shadow-xs);
    flex: 1; /* Allow add button to take space in carousel */
}

.view-details-button-compact {
     display: inline-flex; /* Align icon */
     align-items: center;
     gap: 4px;
}

.external-link-icon {
    font-size: 1em;
    line-height: 1;
    display: inline-block;
}

.add-to-cart-button-compact:hover:not(:disabled) {
    opacity: 0.9;
    box-shadow: var(--shadow-sm);
}

.add-to-cart-button-compact:disabled {
    background-color: #cccccc;
    cursor: not-allowed;
    opacity: 0.7;
    box-shadow: none;
}

.view-details-button-compact:hover {
    background-color: var(--background-soft);
    border-color: var(--border-color-hover);
    color: var(--text-primary);
}

/* Remove old .product-card styles */
/* .product-card { ... } */
/* .product-image-container { ... } */
/* .product-image { ... } */
/* .product-badge { ... } */
/* .product-details { ... } */
/* .product-title { ... } */
/* .product-price { ... } */
/* .current-price { ... } */
/* .product-meta { ... } */
/* .product-vendor { ... } */
/* .label { ... } */
/* .product-type { ... } */
/* .product-description { ... } */
/* .product-actions { ... } */
/* .add-to-cart-button { ... } */
/* .view-details-button { ... } */

/* Ensure product message container uses full width */
.product-message-container {
    width: 100%;
    overflow: hidden; /* Hide scrollbar overflow from container */
}

.products-carousel {
    margin: var(--space-xs) 0;
    width: 100%;
    padding: var(--space-xs);
    background: rgba(0, 0, 0, 0.02);
    border-radius: 20px;
}

.carousel-title {
    font-size: var(--text-base);
    font-weight: 600;
    margin-bottom: var(--space-sm);
    color: var(--text-primary);
    padding: 0 var(--space-xs);
}

.carousel-items {
    display: flex;
    flex-direction: row;
    gap: var(--space-sm);
    margin-top: var(--space-xs);
    overflow-x: auto;
    padding: var(--space-xs);
    padding-bottom: var(--space-md);
    scroll-snap-type: x mandatory;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: thin;
    scrollbar-color: rgba(0, 0, 0, 0.3) rgba(0, 0, 0, 0.1);
}

/* Modern scrollbar styling */
.carousel-items::-webkit-scrollbar {
    display: block;
    height: 8px;
}

.carousel-items::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.05);
    border-radius: 4px;
}

.carousel-items::-webkit-scrollbar-thumb {
    background-color: rgba(0, 0, 0, 0.2);
    border-radius: 4px;
    transition: background-color 0.2s;
}

.carousel-items::-webkit-scrollbar-thumb:hover {
    background-color: rgba(0, 0, 0, 0.3);
}

/* Enhanced product card styling */
.product-card-compact {
    background-color: white;
    border: 1px solid rgba(0, 0, 0, 0.08);
    border-radius: 20px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06),
                0 1px 2px rgba(0, 0, 0, 0.04);
    overflow: hidden;
    width: 180px; /* Slightly reduced width */
    flex-shrink: 0;
    transition: all 0.2s ease;
}

.product-card-compact:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
                0 2px 4px rgba(0, 0, 0, 0.06);
}

.product-card-compact .product-info-compact {
    display: flex;
    flex-direction: column;
    padding: var(--space-sm) var(--space-sm);
    gap: var(--space-xs);
    background-color: white;
}

.product-card-compact .product-title-compact {
    font-size: var(--text-sm);
    font-weight: 500;
    line-height: 1.4;
    color: var(--text-primary);
    overflow: hidden;
    text-overflow: ellipsis;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    margin: 0;
    min-height: 2.8em;
}

.product-card-compact .product-price-compact {
    font-size: var(--text-sm);
    font-weight: 600;
    color: var(--text-primary);
    margin-top: 2px;
}

.product-card-compact .view-details-button-compact {
    width: 100%;
    padding: 8px 12px;
    background-color: white;
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    font-size: var(--text-xs);
    font-weight: 500;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: all 0.2s;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
    margin-top: var(--space-xs);
}

.product-card-compact .view-details-button-compact:hover {
    background-color: var(--background-soft);
    border-color: var(--border-color-hover);
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.08);
}

.product-message-container {
    width: 100%;
    margin: var(--space-sm) 0;
    padding: 0 var(--space-xs);
}

/* Adjust carousel title spacing */
.carousel-title {
    font-size: var(--text-base);
    font-weight: 600;
    margin-bottom: var(--space-sm);
    color: var(--text-primary);
    padding: 0 var(--space-xs);
}

.no-products-message {
    padding: var(--space-md);
    color: var(--text-muted);
    text-align: center;
    font-style: italic;
    font-size: var(--text-sm);
}
</style>