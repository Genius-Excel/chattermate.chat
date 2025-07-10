<!--
ChatterMate - Agent Edit
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
import { useAgentEdit } from '@/composables/useAgentEdit'
import { ref, computed } from 'vue'
import type { Agent } from '@/types/agent'

const props = defineProps<{
    agent: Agent
}>()

const emit = defineEmits<{
    (e: 'save', agent: Agent): void
    (e: 'cancel'): void
}>()

const {
    displayName,
    isActive,
    instructions,
    isLoading,
    error,
    generateInstructions,
    handleSave,
} = useAgentEdit(props.agent)

// Convert array of instructions to a single string for the textarea
const instructionsText = computed({
    get: () => {
        return instructions.value.join('\n\n');
    },
    set: (value: string) => {
        // Enforce character limit
        if (value.length > maxInstructionsLength) {
            value = value.substring(0, maxInstructionsLength);
        }
        
        // Split by newlines, but ensure each instruction is trimmed
        // and filter out empty lines
        const lines = value.split('\n\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
        
        if (lines.length === 0) {
            // If there are no non-empty lines, add an empty instruction
            instructions.value = [''];
        } else {
            instructions.value = lines;
        }
    }
});

const isGeneratingInstructions = ref(false);
const generationPrompt = ref('');
const showGenerationModal = ref(false);
const maxPromptLength = 500;
const maxInstructionsLength = 2000;

// Calculate remaining characters for instructions
const instructionsCharactersRemaining = computed(() => {
    return maxInstructionsLength - instructionsText.value.length;
});

const openGenerationModal = () => {
    showGenerationModal.value = true;
}

const closeGenerationModal = () => {
    showGenerationModal.value = false;
    generationPrompt.value = '';
}

const promptCharactersRemaining = computed(() => {
    return maxPromptLength - generationPrompt.value.length;
})

const handleGenerateInstructions = async () => {
    if (!generationPrompt.value.trim()) return;
    
    try {
        isGeneratingInstructions.value = true;
        const generated = await generateInstructions(generationPrompt.value);
        if (generated && generated.length > 0) {
            instructionsText.value = generated.join('\n\n');
            closeGenerationModal();
        }
    } catch (error) {
        console.error('Failed to generate instructions:', error);
    } finally {
        isGeneratingInstructions.value = false;
    }
}

const onSave = async () => {
    try {
        const updatedAgent = await handleSave()
        emit('save', updatedAgent)
    } catch {
        // Error is handled in the composable
    }
}
</script>

<template>
    <div class="agent-edit">
        <div v-if="error" class="error-message">
            {{ error }}
        </div>
        <form @submit.prevent="onSave">
            <div class="form-group">
                <label>Display Name</label>
                <input type="text" v-model="displayName" placeholder="Enter display name" :disabled="isLoading">
            </div>

            <div class="form-group">
                <label class="toggle-label">
                    Status
                    <div class="toggle-wrapper">
                        <button type="button" class="status-toggle" :class="{ 'active': isActive }"
                            @click="isActive = !isActive" :disabled="isLoading">
                            {{ isActive ? 'Online' : 'Offline' }}
                        </button>
                    </div>
                </label>
            </div>

            <div class="form-group">
                <div class="instructions-header">
                    <label>Instructions</label>
                    <button 
                        type="button" 
                        class="generate-button" 
                        @click="openGenerationModal" 
                        :disabled="isLoading"
                    >
                        Generate with AI
                    </button>
                </div>
                <div class="instructions-area">
                    <textarea
                        v-model="instructionsText"
                        placeholder="Enter instructions for your agent. Separate different instructions with blank lines."
                        rows="8"
                        :disabled="isLoading"
                        maxlength="1500"
                    ></textarea>
                    <div class="character-count" :class="{ 'warning': instructionsCharactersRemaining < 150 }">
                        {{ instructionsCharactersRemaining }} characters remaining
                    </div>
                </div>
                <span v-if="!instructionsText.trim()" class="error-text">
                    Instructions are required
                </span>
                <div class="instructions-hint">
                    Good instructions help your agent understand its purpose and how to interact with users.
                </div>
            </div>

            <div class="form-actions">
                <button type="button" class="cancel-button" @click="$emit('cancel')"
                    :disabled="isLoading">Cancel</button>
                <button type="submit" class="save-button"
                    :disabled="!displayName.trim() || !instructionsText.trim() || isLoading">
                    {{ isLoading ? 'Saving...' : 'Save Changes' }}
                </button>
            </div>
        </form>

        <!-- AI Generation Modal -->
        <div class="modal-overlay" v-if="showGenerationModal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Generate Instructions with AI</h3>
                    <button type="button" class="close-button" @click="closeGenerationModal">&times;</button>
                </div>
                <div class="modal-body">
                    <div v-if="error" class="generation-error">
                        {{ error }}
                    </div>
                    <p class="modal-description">
                        Describe how you want to modify or enhance your agent's instructions. The AI will consider your existing instructions while generating new ones.
                    </p>
                    <div class="instructions-preview" v-if="instructions.length > 0">
                        <div class="preview-header">
                            <span>Current Instructions:</span>
                            <span class="instruction-count">{{ instructions.length }} instruction{{ instructions.length !== 1 ? 's' : '' }}</span>
                        </div>
                        <div class="preview-content">
                            <ul>
                                <li v-for="(instruction, index) in instructions" :key="index">
                                    {{ instruction }}
                                </li>
                            </ul>
                        </div>
                    </div>
                    <div class="textarea-container">
                        <textarea 
                            v-model="generationPrompt" 
                            placeholder="E.g., Make the agent more empathetic while maintaining its professional tone"
                            rows="6"
                            maxlength="1000"
                            @input="generationPrompt = generationPrompt.substring(0, maxPromptLength)"
                        ></textarea>
                        <div class="character-count" :class="{ 'warning': promptCharactersRemaining < 100 }">
                            {{ promptCharactersRemaining }} characters remaining
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button 
                        type="button" 
                        class="cancel-button" 
                        @click="closeGenerationModal"
                        :disabled="isGeneratingInstructions"
                    >
                        Cancel
                    </button>
                    <button 
                        type="button" 
                        class="primary-button" 
                        @click="handleGenerateInstructions"
                        :disabled="!generationPrompt.trim() || isGeneratingInstructions"
                    >
                        <span v-if="isGeneratingInstructions" class="loading-spinner"></span>
                        {{ isGeneratingInstructions ? 'Generating...' : 'Generate' }}
                    </button>
                </div>
            </div>
        </div>
    </div>
</template>

<style scoped>
.agent-edit {
    padding: var(--space-md);
}

.form-group {
    margin-bottom: var(--space-lg);
}

.form-group label {
    display: block;
    margin-bottom: var(--space-sm);
    color: var(--text-muted);
}

.form-group input,
.form-group textarea {
    width: 100%;
    padding: var(--space-sm);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
    background: var(--background);
    color: var(--text-color);
    font-family: inherit;
}

.form-group textarea {
    resize: vertical;
    min-height: 150px;
}

.instructions-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: var(--space-sm);
}

.instructions-hint {
    margin-top: var(--space-xs);
    font-size: 0.8rem;
    color: var(--text-muted);
}

.generate-button {
    background-color: var(--primary-soft);
    color: var(--primary-color);
    border: none;
    border-radius: var(--radius-md);
    padding: var(--space-xs) var(--space-sm);
    cursor: pointer;
    font-size: 0.875rem;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: var(--transition-fast);
}

.generate-button:hover {
    background-color: var(--primary-color);
    color: white;
}

.generate-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.form-actions {
    display: flex;
    gap: var(--space-sm);
    justify-content: flex-end;
}

.cancel-button,
.save-button {
    padding: var(--space-sm) var(--space-lg);
    border-radius: var(--radius-lg);
    cursor: pointer;
}

.cancel-button {
    background: var(--background-soft);
    border: none;
    color: var(--text-color);
}

.save-button {
    background: var(--primary-color);
    color: white;
    border: none;
}

.save-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.error-text {
    color: var(--error-color);
    font-size: 0.75rem;
    margin-top: var(--space-xs);
    display: block;
}

.toggle-label {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.toggle-wrapper {
    display: flex;
    align-items: center;
}

.status-toggle {
    padding: var(--space-sm) var(--space-md);
    border-radius: var(--radius-lg);
    border: none;
    background: var(--error-color);
    color: white;
    cursor: pointer;
    transition: background-color var(--transition-fast);
}

.status-toggle.active {
    background: var(--success-color);
}

.error-message {
    padding: var(--space-sm);
    margin-bottom: var(--space-md);
    background: var(--error-color-soft);
    color: var(--error-color);
    border-radius: var(--radius-lg);
    font-size: 0.875rem;
}

/* Modal Styles - Updated */
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.6);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
    backdrop-filter: blur(2px);
}

.modal-content {
    background: var(--background-color);
    border-radius: var(--radius-lg);
    width: 90%;
    max-width: 600px;
    box-shadow: var(--shadow-lg);
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    border: 1px solid var(--border-color);
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: var(--space-md) var(--space-lg);
    border-bottom: 1px solid var(--border-color);
}

.modal-header h3 {
    margin: 0;
    font-size: 1.25rem;
    color: var(--text-primary);
    font-weight: 600;
}

.close-button {
    background: transparent;
    border: none;
    font-size: 1.5rem;
    cursor: pointer;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    transition: var(--transition-fast);
}

.close-button:hover {
    background-color: var(--background-mute);
    color: var(--text-color);
}

.modal-body {
    padding: var(--space-lg);
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: var(--space-md);
}

.modal-description {
    margin-bottom: var(--space-md);
    color: var(--text-secondary);
    line-height: 1.5;
}

.instructions-preview {
    margin-bottom: var(--space-lg);
    border: 1px solid var(--border-color);
    border-radius: var(--radius-lg);
    background: var(--background-soft);
}

.preview-header {
    padding: var(--space-sm) var(--space-md);
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--background);
    border-radius: var(--radius-lg) var(--radius-lg) 0 0;
}

.instruction-count {
    font-size: var(--text-sm);
    color: var(--text-muted);
    background: var(--background-mute);
    padding: 2px var(--space-sm);
    border-radius: var(--radius-full);
}

.preview-content {
    padding: var(--space-md);
    max-height: 150px;
    overflow-y: auto;
}

.preview-content ul {
    list-style-type: none;
    padding: 0;
    margin: 0;
}

.preview-content li {
    padding: var(--space-xs) 0;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    line-height: 1.5;
    border-bottom: 1px solid var(--border-color-light);
}

.preview-content li:last-child {
    border-bottom: none;
}

.textarea-container {
    position: relative;
}

.modal-body textarea {
    width: 100%;
    padding: var(--space-md);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
    background: var(--background);
    color: var(--text-color);
    font-family: inherit;
    font-size: var(--text-base);
    resize: vertical;
    min-height: 120px;
    transition: var(--transition-fast);
    line-height: 1.5;
}

.modal-body textarea:focus {
    border-color: var(--primary-color);
    outline: none;
    box-shadow: 0 0 0 2px var(--primary-soft);
}

.character-count {
    position: absolute;
    bottom: var(--space-xs);
    right: var(--space-md);
    font-size: var(--text-xs);
    color: var(--text-muted);
    background-color: var(--background);
    padding: 2px var(--space-xs);
    border-radius: var(--radius-sm);
}

.character-count.warning {
    color: var(--warning-color);
}

.modal-footer {
    padding: var(--space-md) var(--space-lg);
    border-top: 1px solid var(--border-color);
    display: flex;
    justify-content: flex-end;
    gap: var(--space-md);
}

.primary-button {
    background: var(--primary-color);
    color: white;
    border: none;
    border-radius: var(--radius-lg);
    padding: var(--space-sm) var(--space-lg);
    font-weight: 500;
    cursor: pointer;
    transition: var(--transition-fast);
    display: inline-flex;
    align-items: center;
    gap: var(--space-sm);
}

.primary-button:hover:not(:disabled) {
    background: var(--accent-color);
}

.primary-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.loading-spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-radius: 50%;
    border-top-color: white;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    to {
        transform: rotate(360deg);
    }
}

.instructions-area {
    position: relative;
    margin-bottom: var(--space-xs);
}

.instructions-area textarea {
    width: 100%;
    padding: var(--space-md);
    padding-bottom: calc(var(--space-md) + 20px);
    border: 2px solid var(--border-color);
    border-radius: var(--radius-lg);
    background: var(--background);
    color: var(--text-color);
    font-family: inherit;
    resize: vertical;
    min-height: 150px;
    transition: var(--transition-fast);
    line-height: 1.5;
}

.instructions-area textarea:focus {
    border-color: var(--primary-color);
    outline: none;
    box-shadow: 0 0 0 2px var(--primary-soft);
}

.generation-error {
    padding: var(--space-sm);
    margin-bottom: var(--space-md);
    background: var(--error-color-soft);
    color: var(--error-color);
    border-radius: var(--radius-md);
    font-size: 0.875rem;
    display: flex;
    align-items: center;
    gap: var(--space-sm);
}

.generation-error::before {
    content: "⚠️";
}
</style>