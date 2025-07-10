<!--
ChatterMate - Agent Widget Tab
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
interface Widget {
  id: string;
  [key: string]: any;
}

const props = defineProps({
  widget: {
    type: Object as () => Widget | null,
    required: true
  },
  widgetUrl: {
    type: String,
    required: true
  },
  widgetLoading: {
    type: Boolean,
    required: true
  }
})

const emit = defineEmits(['copy-widget-code'])

const copyWidgetCode = () => {
  emit('copy-widget-code')
}
</script>

<template>
  <section class="detail-section">
    <h4>Widget Integration</h4>
    <div class="widget-info">
      <div v-if="widgetLoading" class="loading-indicator">
        Loading widget info...
      </div>
      <div v-else-if="widget" class="widget-code">
        <div class="code-container">
          <code>&lt;script&gt;window.chattermateId='{{ widget.id }}';&lt;/script&gt;&lt;script src="{{ widgetUrl }}/webclient/chattermate.min.js"&gt;&lt;/script&gt;</code>
          <button class="copy-button" @click="copyWidgetCode" title="Copy to clipboard">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
              xmlns="http://www.w3.org/2000/svg">
              <path
                d="M8 4V16C8 17.1046 8.89543 18 10 18H18C19.1046 18 20 17.1046 20 16V7.41421C20 6.88378 19.7893 6.37507 19.4142 6L16 2.58579C15.6249 2.21071 15.1162 2 14.5858 2H10C8.89543 2 8 2.89543 8 4Z"
                stroke="currentColor" stroke-width="2" stroke-linecap="round"
                stroke-linejoin="round" />
              <path
                d="M16 18V20C16 21.1046 15.1046 22 14 22H6C4.89543 22 4 21.1046 4 20V8C4 6.89543 4.89543 6 6 6H8"
                stroke="currentColor" stroke-width="2" stroke-linecap="round"
                stroke-linejoin="round" />
            </svg>
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.detail-section {
  margin-bottom: var(--space-xl);
}

.detail-section h4 {
  margin-bottom: var(--space-md);
  color: var(--text-muted);
}

.widget-info {
  background: var(--background-soft);
  border-radius: var(--radius-lg);
  padding: var(--space-sm);
  width: 100%;
}

.widget-code {
  font-family: monospace;
  font-size: 0.85em;
}

.code-container {
  background: var(--background-alt);
  padding: var(--space-sm);
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-sm);
  width: 100%;
}

.code-container code {
  font-size: 11px;
  color: var(--text-muted);
  white-space: normal;
  word-break: break-all;
  flex: 1;
}

.copy-button {
  background: transparent;
  border: none;
  padding: var(--space-xs);
  border-radius: var(--radius-sm);
  cursor: pointer;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  transition: all 0.2s ease;
}

.copy-button:hover {
  background: var(--background-soft);
  color: var(--text-color);
}

.loading-indicator {
  font-size: var(--text-sm);
  color: var(--text-muted);
  padding: var(--space-sm);
}
</style> 