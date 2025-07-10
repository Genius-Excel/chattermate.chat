<!--
ChatterMate - Agent General Tab
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
import { computed, ref, watch } from 'vue'

interface UserGroup {
  id: string;
  name: string;
}

const props = defineProps({
  instructions: {
    type: String,
    required: true
  },
  transferToHuman: {
    type: Boolean,
    required: true
  },
  askForRating: {
    type: Boolean,
    required: true
  },
  userGroups: {
    type: Array as () => UserGroup[],
    required: true
  },
  selectedGroupIds: {
    type: Array as () => string[],
    required: true
  },
  loadingGroups: {
    type: Boolean,
    required: true
  },
  isEditing: {
    type: Boolean,
    required: true
  }
})

const emit = defineEmits([
  'update:instructions',
  'toggle-transfer-to-human',
  'toggle-ask-for-rating',
  'update-agent-groups'
])

// Create a local copy of selectedGroupIds
const localSelectedGroupIds = ref<string[]>([...props.selectedGroupIds])

// Watch for changes in the prop to update the local copy
watch(() => props.selectedGroupIds, (newValue) => {
  localSelectedGroupIds.value = [...newValue]
}, { deep: true })

const transferReasons = [
  "Knowledge gaps",
  "Need human contact",
  "Customer frustration",
  "High priority issues",
  "Compliance matters"
]

const tooltipContent = computed(() => {
  return `Auto-transfer when:\n${transferReasons.map(reason => `• ${reason}`).join('\n')}`
})

const ratingTooltipContent = computed(() => {
  return `Enable to:\n• Request feedback after chat ends\n• Collect star ratings (1-5)\n• Gather optional comments\n• Track customer satisfaction`
})

const toggleTransferToHuman = () => {
  emit('toggle-transfer-to-human')
}

const toggleAskForRating = () => {
  emit('toggle-ask-for-rating')
}

const updateAgentGroups = () => {
  emit('update-agent-groups', localSelectedGroupIds.value)
}

const updateInstructions = (event: Event) => {
  const target = event.target as HTMLTextAreaElement
  emit('update:instructions', target.value)
}
</script>

<template>
  <div>
    <section class="detail-section">
      <h4>Instructions</h4>
      <textarea 
        class="instructions-textarea" 
        :value="instructions"
        @input="updateInstructions"
        rows="6" 
        placeholder="Enter instructions for the agent..."
        :readonly="!isEditing"
      ></textarea>
    </section>
    <section class="detail-section">
      <div class="transfer-section">
        <!-- Transfer toggle -->
        <div class="transfer-toggle">
          <div class="toggle-header">
            <h4>Transfer to Human</h4>
            <label class="switch" v-tooltip="tooltipContent">
              <input type="checkbox" 
                :checked="transferToHuman"
                @change="toggleTransferToHuman"
              >
              <span class="slider"></span>
            </label>
          </div>
          <p class="helper-text">Enable automatic transfer to human agents when needed</p>
        </div>

        <!-- Group selection -->
        <div v-if="transferToHuman" class="transfer-groups">
          <h4>Transfer Groups</h4>
          <p v-if="userGroups.length" class="helper-text">Select groups that can handle transferred chats</p>
          
          <div v-if="!loadingGroups">
            <div v-if="userGroups.length" class="groups-list">
              <label v-for="group in userGroups" :key="group.id" class="group-item">
                <input 
                  type="checkbox" 
                  :value="group.id"
                  v-model="localSelectedGroupIds"
                  @change="updateAgentGroups"
                >
                <span>{{ group.name }}</span>
              </label>
            </div>
            <div v-else class="no-groups-message">
              <p>No groups available.</p>
              <router-link to="/human-agents" class="create-group-link">
                Create Group <i class="fas fa-arrow-right"></i>
              </router-link>
            </div>
          </div>
          
          <div v-else class="loading-groups">
            Loading groups...
          </div>
        </div>

        <!-- Ask for Rating -->
        <div class="rating-toggle">
          <div class="toggle-header">
            <h4>Ask for Rating</h4>
            <label class="switch" v-tooltip="ratingTooltipContent">
              <input type="checkbox" 
                :checked="askForRating"
                @change="toggleAskForRating"
              >
              <span class="slider"></span>
            </label>
          </div>
          <p class="helper-text">Request customer feedback when chats end</p>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.detail-section {
  margin-bottom: var(--space-xl);
}

.detail-section h4 {
  margin-bottom: var(--space-md);
  color: var(--text-muted);
}

.instructions-textarea {
  width: 100%;
  min-height: 150px;
  padding: var(--space-sm);
  background: var(--background-soft);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  font-family: inherit;
  font-size: inherit;
  line-height: 1.5;
  resize: vertical;
  color: var(--text-color);
}

.instructions-textarea:read-only {
  background: var(--background-soft);
  cursor: default;
  opacity: 0.9;
}

.instructions-textarea:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 2px var(--primary-soft);
}

.transfer-section {
  margin-top: var(--space-lg);
  border-top: 1px solid var(--border-color);
  padding-top: var(--space-lg);
}

.transfer-toggle {
  margin-bottom: var(--space-lg);
}

.toggle-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-sm);
}

.helper-text {
  color: var(--text-muted);
  font-size: var(--text-sm);
  margin-bottom: var(--space-md);
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
  background-color: rgb(252, 0, 0);
  transition: .4s;
  border-radius: 24px;
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
  background-color: green;
}

input:focus + .slider {
  box-shadow: 0 0 1px var(--primary-color);
}

input:checked + .slider:before {
  transform: translateX(24px);
}

.transfer-groups {
  padding: var(--space-md);
  background: var(--background-soft);
  border-radius: var(--radius-md);
}

.groups-list {
  display: flex;
  flex-direction: column;
  gap: var(--space-sm);
}

.group-item {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  cursor: pointer;
}

.no-groups-message {
  text-align: center;
  padding: var(--space-lg);
  background: var(--background-mute);
  border-radius: var(--radius-md);
  color: var(--text-muted);
}

.create-group-link {
  display: inline-flex;
  align-items: center;
  gap: var(--space-sm);
  margin-top: var(--space-md);
  color: var(--primary-color);
  font-weight: 500;
  transition: opacity var(--transition-fast);
}

.create-group-link:hover {
  opacity: 0.8;
}

.create-group-link i {
  font-size: 0.8em;
}

.loading-groups {
  text-align: center;
  padding: var(--space-md);
  background: var(--background-mute);
  border-radius: var(--radius-md);
  color: var(--text-muted);
}

.rating-toggle {
  margin-top: var(--space-lg);
  padding-top: var(--space-lg);
  border-top: 1px solid var(--border-color);
}
</style> 