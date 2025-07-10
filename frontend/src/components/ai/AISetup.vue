<!--
ChatterMate - A I Setup
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
import { useAISetup } from '@/composables/useAISetup'
import { computed, ref, watch } from 'vue'
import { useEnterpriseFeatures } from '@/composables/useEnterpriseFeatures'

const emit = defineEmits<{
  (e: 'ai-setup-complete'): void
}>()

const { hasEnterpriseModule } = useEnterpriseFeatures()

const {
  isLoading,
  error,
  providers,
  setupConfig,
  saveAISetup,
  updateAISetup,
  hasExistingConfig
} = useAISetup()

// Set initial tab based on enterprise availability
const activeTab = ref(hasEnterpriseModule ? 'chattermate' : 'custom')
// API key is always required for our supported providers
const showApiKey = computed(() => true)

// Model options based on provider
const modelOptions = computed(() => {
  const provider = setupConfig.value.provider.toUpperCase();
  switch (provider) {
    case 'GROQ':
      return [
        { value: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B Versatile' },
      ]
    case 'OPENAI':
      return [
        { value: 'gpt-4o-mini', label: 'GPT-4o Mini' },
        { value: 'o1-mini', label: 'O1 Mini' },
        { value: 'o3-mini', label: 'O3 Mini' }
      ]
    default:
      return []
  }
})

// Reset model when provider changes
watch(() => setupConfig.value.provider, () => {
  setupConfig.value.model = ''
})

const selectTab = (tab: 'chattermate' | 'custom') => {
  if (tab === 'chattermate' && !hasEnterpriseModule) return
  activeTab.value = tab
}

const handleSubmit = async () => {
  try {
    let success = false
    if (hasExistingConfig.value) {
      success = await updateAISetup()
    } else {
      success = await saveAISetup()
    }
    
    if (success) {
      emit('ai-setup-complete')
    }
  } catch (error) {
    console.error('Submit error:', error)
  }
}

const setupChatterMateAI = async () => {
  try {
    // Set the config values first
    setupConfig.value.provider = 'chattermate'
    setupConfig.value.model = 'chattermate'
    setupConfig.value.apiKey = ''
    
    // Then save using the existing function without arguments
    let success = false
    if (hasExistingConfig.value) {
      success = await updateAISetup()
    } else {
      success = await saveAISetup()
    }
    
    if (success) {
      emit('ai-setup-complete')
    }
  } catch (error) {
    console.error('ChatterMate setup error:', error)
  }
}

// Button text based on whether we're creating or updating
const submitButtonText = computed(() => {
  if (isLoading.value) return 'Saving...'
  return hasExistingConfig.value ? 'Update Configuration' : 'Save Configuration'
})

const chatterMateButtonText = computed(() => {
  return hasExistingConfig.value ? 'Update to ChatterMate AI' : 'Proceed with ChatterMate AI'
})
</script>

<template>
  <div class="ai-setup">
    <div v-if="isLoading" class="loading-container">
      <div class="loader"></div>
    </div>
    
    <div v-else>
      <div v-if="error" class="error-message">
        {{ error }}
      </div>

      <div class="tabs-container">
        <div class="tabs">
          <div 
            v-if="hasEnterpriseModule"
            class="tab" 
            :class="{ active: activeTab === 'chattermate' }"
            @click="selectTab('chattermate')"
          >
            <span class="tab-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/>
              </svg>
            </span>
            <span class="tab-label">ChatterMate AI</span>
          </div>
          <div 
            class="tab" 
            :class="{ active: activeTab === 'custom' }"
            @click="selectTab('custom')"
          >
            <span class="tab-icon">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
              </svg>
            </span>
            <span class="tab-label">Bring Your Own Model</span>
          </div>
        </div>
        
        <div class="tab-content">
          <div v-if="activeTab === 'chattermate' && hasEnterpriseModule" class="chattermate-content">
            <div class="provider-info">
              <div class="provider-header">
                <h4>ChatterMate AI</h4>
              </div>
              
              <div class="plan-table">
                <div class="plan-row">
                  <div class="plan-cell plan-label">Starter Plan:</div>
                  <div class="plan-cell plan-value">1000 messages/month per seat</div>
                </div>
                <div class="plan-row">
                  <div class="plan-cell plan-label">Pro Plan:</div>
                  <div class="plan-cell plan-value">10,000 messages/month per seat</div>
                </div>
                <div class="plan-divider"></div>
                <div class="plan-row rate-limit-row">
                  <div class="plan-cell">Rate limit: 100 messages/minute</div>
                </div>
              </div>
              
              <div class="action-area">
                <button class="continue-button" @click="setupChatterMateAI">
                  {{ chatterMateButtonText }}
                </button>
              </div>
            </div>
          </div>
          
          <div v-else class="custom-content">
            <form @submit.prevent="handleSubmit" class="setup-form">
              <p class="setup-description">
                {{ hasExistingConfig ? 'Update your AI provider settings' : 'Set up your AI provider to start using ChatterMate\'s intelligent features' }}
              </p>

              <div class="form-group">
                <label for="provider">AI Provider</label>
                <select 
                  id="provider" 
                  v-model="setupConfig.provider"
                  required
                  class="form-control"
                >
                  <option value="">Select Provider</option>
                  <option 
                    v-for="provider in providers" 
                    :key="provider.value" 
                    :value="provider.value"
                  >
                    {{ provider.label }}
                  </option>
                </select>
              </div>

              <div class="form-group">
                <label for="model">Model Name</label>
                <select
                  id="model"
                  v-model="setupConfig.model"
                  required
                  class="form-control"
                  :disabled="!setupConfig.provider || modelOptions.length === 0"
                >
                  <option value="" disabled>Select Model</option>
                  <option 
                    v-for="model in modelOptions" 
                    :key="model.value" 
                    :value="model.value"
                  >
                    {{ model.label }}
                  </option>
                </select>
              </div>

              <div v-if="showApiKey" class="form-group">
                <label for="apiKey">API Key</label>
                <input
                  id="apiKey"
                  type="password"
                  v-model="setupConfig.apiKey"
                  :required="showApiKey"
                  placeholder="Enter your API key"
                  class="form-control"
                />
                <p class="key-hint">Your API key will be encrypted and stored securely</p>
              </div>

              <button 
                type="submit" 
                class="btn btn-primary"
                :disabled="isLoading"
              >
                {{ submitButtonText }}
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.ai-setup {
  width: 100%;
  max-width: 750px;
  margin: 0 auto;
}

.loading-container {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 200px;
}

.loader {
  border: 3px solid var(--border-color);
  border-top: 3px solid var(--primary-color);
  border-radius: 50%;
  width: 30px;
  height: 30px;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

.error-message {
  background-color: var(--secondary-color);
  color: var(--error-color);
  padding: 12px;
  border-radius: var(--radius-md);
  margin-bottom: 20px;
}

.tabs-container {
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  overflow: hidden;
  background-color: var(--background-color);
  box-shadow: var(--shadow-sm);
}

.tabs {
  display: flex;
  background-color: var(--background-soft);
  border-bottom: 1px solid var(--border-color);
}

.tab {
  padding: 12px 16px;
  cursor: pointer;
  font-weight: 500;
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-secondary);
  transition: var(--transition-fast);
  border-bottom: 2px solid transparent;
}

.tab:hover {
  color: var(--primary-color);
  background-color: var(--background-mute);
}

.tab.active {
  color: var(--primary-color);
  border-bottom: 2px solid var(--primary-color);
  background-color: var(--background-color);
}

.tab-icon {
  display: flex;
  align-items: center;
}

.tab-content {
  padding: var(--space-lg);
}

.setup-form {
  max-width: 500px;
}

.setup-description {
  margin-bottom: var(--space-lg);
  color: var(--text-secondary);
}

.form-group {
  margin-bottom: var(--space-lg);
}

.form-group label {
  display: block;
  margin-bottom: var(--space-sm);
  font-weight: 500;
}

.form-control {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  font-size: var(--text-base);
}

.key-hint {
  font-size: var(--text-sm);
  color: var(--text-muted);
  margin-top: var(--space-xs);
}

.btn {
  padding: 10px 16px;
  border: none;
  border-radius: var(--radius-md);
  cursor: pointer;
  font-weight: 500;
  transition: var(--transition-fast);
}

.btn-primary {
  background-color: var(--primary-color);
  color: var(--text-color-light);
}

.btn-primary:hover {
  background-color: var(--accent-color);
}

.btn-primary:disabled {
  background-color: var(--background-mute);
  cursor: not-allowed;
}

.provider-info {
  display: flex;
  flex-direction: column;
  gap: var(--space-lg);
  max-width: 600px;
}

.provider-header {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

.provider-header h4 {
  font-size: var(--text-xl);
  margin: 0;
  color: var(--text-primary);
}

.provider-header p {
  margin: 0;
  color: var(--text-secondary);
  font-weight: normal;
}

.plan-table {
  background-color: var(--background-soft);
  border-radius: var(--radius-md);
  padding: var(--space-md);
  border: 1px solid var(--border-color);
}

.plan-row {
  display: flex;
  padding: var(--space-sm) 0;
}

.plan-cell {
  flex: 1;
}

.plan-label {
  font-weight: 500;
}

.plan-divider {
  height: 1px;
  background-color: var(--border-color);
  margin: var(--space-sm) 0;
}

.rate-limit-row {
  color: var(--text-muted);
  font-size: var(--text-sm);
}

.action-area {
  display: flex;
  justify-content: flex-start;
  margin-top: var(--space-sm);
}

.continue-button {
  background-color: var(--primary-color);
  color: var(--text-color-light);
  border: none;
  border-radius: var(--radius-md);
  padding: 10px 16px;
  font-weight: 500;
  cursor: pointer;
  transition: var(--transition-fast);
}

.continue-button:hover {
  background-color: var(--accent-color);
}
</style>