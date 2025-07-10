import type { Agent } from '@/types/agent'
import type { UserGroup } from '@/types/user'

const STORAGE_KEYS = {
  ACTIVE_AGENT: 'active_agent',
  AGENTS: 'agents',
} as const

export const agentStorage = {
  // Store all agents
  setAgents(agents: Agent[]): void {
    localStorage.setItem(STORAGE_KEYS.AGENTS, JSON.stringify(agents))
  },

  // Get all agents
  getAgents(): Agent[] {
    const stored = localStorage.getItem(STORAGE_KEYS.AGENTS)
    if (!stored) return []
    try {
      return JSON.parse(stored) as Agent[]
    } catch (e) {
      console.error('Failed to parse stored agents:', e)
      return []
    }
  },
  setAgent(agent: Agent): void {
    const agents = this.getAgents()
    const index = agents.findIndex((a) => a.id === agent.id)
    if (index !== -1) {
      agents[index] = agent
    }
  },

  // Update specific agent
  updateAgent(updatedAgent: Agent): void {
    const agents = this.getAgents()
    const index = agents.findIndex((a) => a.id === updatedAgent.id)
    if (index !== -1) {
      agents[index] = updatedAgent
      this.setAgents(agents)
    }
  },



  // Update agent knowledge
  updateAgentKnowledge(agentId: string, knowledge: Agent['knowledge']): void {
    const agents = this.getAgents()
    const index = agents.findIndex((a) => a.id === agentId)
    if (index !== -1) {
      agents[index] = {
        ...agents[index],
        knowledge: knowledge,
      }
      this.setAgents(agents)

      // Update active agent if it's the same one
      const activeAgent = this.getActiveAgent()
      if (activeAgent && activeAgent.id === agentId) {
        this.setActiveAgent(agents[index])
      }
    }
  },

  // Get active agent
  getActiveAgent(): Agent | null {
    const stored = localStorage.getItem(STORAGE_KEYS.ACTIVE_AGENT)
    if (!stored) return null
    try {
      return JSON.parse(stored) as Agent
    } catch (e) {
      console.error('Failed to parse active agent:', e)
      return null
    }
  },

  // Set active agent
  setActiveAgent(agent: Agent): void {
    localStorage.setItem(STORAGE_KEYS.ACTIVE_AGENT, JSON.stringify(agent))
  },

  // Clear all stored agent data
  clear(): void {
    localStorage.removeItem(STORAGE_KEYS.ACTIVE_AGENT)
    localStorage.removeItem(STORAGE_KEYS.AGENTS)
  },
}

// Create a composable for agent storage
export function useAgentStorage() {
  return {
    ...agentStorage,
  }
}
