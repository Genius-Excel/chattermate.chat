<!--
ChatterMate - Agent Advanced Tab
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
import { computed, ref } from 'vue'
import type { Agent } from '@/types/agent'

const props = defineProps<{
  agent: Agent
}>()

const emit = defineEmits<{
  (e: 'update', agent: Agent): void
}>()

// Create a ref for the agent
const agentRef = ref(props.agent)

// Import the composable
import { useAgentAdvanced } from '@/composables/useAgentAdvanced'

// Use the composable
const {
  localSettings,
  isLoading,
  error,
  hasUnsavedChanges,
  rateLimitTooltipContent,
  dailyLimitTooltipContent,
  requestsPerSecTooltipContent,
  toggleRateLimiting,
  updateLocalValue,
  saveRateLimitSettings
} = useAgentAdvanced(agentRef)

// Handle successful updates
const handleUpdate = (updatedAgent: Agent) => {
  emit('update', updatedAgent)
}

// Handle toggle rate limiting
const handleToggleRateLimiting = async () => {
  try {
    const updatedAgent = await toggleRateLimiting()
    handleUpdate(updatedAgent)
  } catch (err) {
    // Error is handled in the composable
  }
}

// Handle slider value changes
const handleValueChange = (type: 'overallLimitPerIp' | 'requestsPerSec', event: Event) => {
  const target = event.target as HTMLInputElement
  if (!target) return
  
  updateLocalValue(type, target.value)
}

// Handle save settings
const handleSaveSettings = async () => {
  try {
    const updatedAgent = await saveRateLimitSettings()
    handleUpdate(updatedAgent)
  } catch (err) {
    // Error is handled in the composable
  }
}
</script>

<template>
  <div class="advanced-settings">
    <h3 class="section-title">Advanced Settings</h3>
    
    <!-- Error message -->
    <div v-if="error" class="error-message">
      {{ error }}
    </div>
    
    <!-- Rate Limiting Section -->
    <div class="rate-limiting-section" :class="{ 'loading': isLoading }">
      <div class="section-header">
        <h4>Rate Limiting</h4>
        <div class="toggle-switch">
          <span class="toggle-label" v-tooltip="rateLimitTooltipContent()">
            Enable Rate Limiting
            <i class="fas fa-info-circle info-icon"></i>
          </span>
          <label class="switch">
            <input 
              type="checkbox" 
              :checked="localSettings.enableRateLimiting" 
              @change="handleToggleRateLimiting"
              :disabled="isLoading"
            >
            <span class="slider" :class="{ 'enabled': localSettings.enableRateLimiting }"></span>
          </label>
        </div>
      </div>
      
      <div class="rate-limit-settings" v-if="localSettings.enableRateLimiting">
        <p class="helper-text">Configure rate limiting to protect your agent from abuse and control traffic.</p>
        
        <div class="form-group">
          <label v-tooltip="dailyLimitTooltipContent()">
            Daily Limit (requests per IP)
            <i class="fas fa-info-circle info-icon"></i>
          </label>
          <div class="input-with-slider">
            <input 
              type="number" 
              v-model="localSettings.overallLimitPerIp"
              @input="(e) => handleValueChange('overallLimitPerIp', e)"
              min="10" 
              max="1000" 
              step="10"
              class="number-input"
              :disabled="isLoading"
            >
            <input 
              type="range" 
              v-model="localSettings.overallLimitPerIp"
              @input="(e) => handleValueChange('overallLimitPerIp', e)"
              min="10" 
              max="1000" 
              step="10"
              class="range-input"
              :disabled="isLoading"
            >
          </div>
        </div>
        
        <div class="form-group">
          <label v-tooltip="requestsPerSecTooltipContent()">
            Rate Limit (requests per second)
            <i class="fas fa-info-circle info-icon"></i>
          </label>
          <div class="input-with-slider">
            <input 
              type="number" 
              v-model="localSettings.requestsPerSec"
              @input="(e) => handleValueChange('requestsPerSec', e)"
              min="1" 
              max="10" 
              step="1"
              class="number-input"
              :disabled="isLoading"
            >
            <input 
              type="range" 
              v-model="localSettings.requestsPerSec"
              @input="(e) => handleValueChange('requestsPerSec', e)"
              min="1" 
              max="10" 
              step="1"
              class="range-input"
              :disabled="isLoading"
            >
          </div>
        </div>

        <!-- Save Settings Button -->
        <button 
          class="save-settings-btn" 
          @click="handleSaveSettings"
          :disabled="isLoading || !hasUnsavedChanges"
        >
          <i class="fas fa-save"></i>
          {{ isLoading ? 'Saving...' : 'Save Settings' }}
        </button>
      </div>
      
      <div class="rate-limit-disabled" v-else>
        <p class="disabled-message">
          <i class="fas fa-info-circle"></i>
          Rate limiting is currently disabled. Enable it to protect your agent from abuse and control traffic.
        </p>
      </div>
    </div>
  </div>
</template>

<style scoped>
.advanced-settings {
  animation: fadeIn 0.3s ease;
}

.section-title {
  font-size: 1.2rem;
  margin-bottom: var(--space-md);
  color: var(--text-color);
  font-weight: 600;
}

.rate-limiting-section {
  background: var(--background-soft);
  border-radius: var(--radius-lg);
  padding: var(--space-lg);
  margin-bottom: var(--space-xl);
  transition: opacity 0.3s ease;
}

.rate-limiting-section.loading {
  opacity: 0.7;
  pointer-events: none;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-sm);
}

.toggle-switch {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
}

.toggle-label {
  font-size: 0.9em;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: help;
}

.info-icon {
  font-size: 0.9em;
  color: var(--text-muted);
  opacity: 0.7;
}

.switch {
  position: relative;
  display: inline-block;
  width: 48px;
  height: 24px;
}

.switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: var(--error-color, #dc3545);
  transition: .4s;
  border-radius: 24px;
}

.slider.enabled {
  background-color: var(--success-color, #28a745);
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: rgb(255, 255, 255);
  transition: .4s;
  border-radius: 50%;
}

input:checked + .slider {
  background-color:  #4CAF50;
}

input:focus + .slider {
  box-shadow: 0 0 1px var(--primary-color);
}

input:checked + .slider:before {
  transform: translateX(24px);
}

.rate-limit-settings {
  margin-top: var(--space-md);
  padding-top: var(--space-md);
  border-top: 1px solid var(--border-color);
}

.helper-text {
  color: var(--text-muted);
  font-size: var(--text-sm);
  margin-bottom: var(--space-md);
}

.form-group {
  margin-bottom: var(--space-md);
}

.form-group label {
  display: flex;
  align-items: center;
  gap: var(--space-xs);
  margin-bottom: var(--space-xs);
  font-weight: 500;
  color: var(--text-color);
}

.input-with-slider {
  display: flex;
  align-items: center;
  gap: var(--space-md);
}

.number-input {
  width: 80px;
  padding: var(--space-sm);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-md);
  background: var(--background-color);
  color: var(--text-color);
  font-size: var(--text-sm);
}

.range-input {
  flex: 1;
  accent-color: var(--primary-color);
}

.save-settings-btn {
  margin-top: var(--space-lg);
  padding: var(--space-sm) var(--space-md);
  background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
  color: white;
  border: none;
  border-radius: var(--radius-full);
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-fast);
}

.save-settings-btn:hover {
  filter: brightness(1.1);
  transform: translateY(-1px);
}

.save-settings-btn:disabled {
  opacity: 0.7;
  cursor: not-allowed;
  filter: grayscale(0.5);
}

.rate-limit-disabled {
  margin-top: var(--space-md);
  padding: var(--space-md);
  background: var(--background-mute);
  border-radius: var(--radius-md);
}

.disabled-message {
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: var(--space-sm);
}

.disabled-message i {
  color: var(--warning);
}

.error-message {
  padding: var(--space-sm);
  margin-bottom: var(--space-md);
  background: var(--error-color-soft);
  color: var(--error-color);
  border-radius: var(--radius-lg);
  font-size: 0.875rem;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(5px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style> 