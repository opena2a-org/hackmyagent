/** DVAA agent port and endpoint configuration */

export interface DVAATarget {
  name: string;
  port: number;
  protocol: 'api' | 'mcp' | 'a2a';
  securityLevel: 'hardened' | 'weak' | 'vulnerable' | 'critical' | 'standard';
  vulnerabilities: string[];
}

export const DVAA_TARGETS: DVAATarget[] = [
  // API Agents (OpenAI-compatible)
  {
    name: 'SecureBot',
    port: 3001,
    protocol: 'api',
    securityLevel: 'hardened',
    vulnerabilities: [],
  },
  {
    name: 'HelperBot',
    port: 3002,
    protocol: 'api',
    securityLevel: 'weak',
    vulnerabilities: ['promptInjection', 'dataExfiltration', 'contextManipulation'],
  },
  {
    name: 'LegacyBot',
    port: 3003,
    protocol: 'api',
    securityLevel: 'critical',
    vulnerabilities: ['promptInjection', 'jailbreak', 'dataExfiltration', 'capabilityAbuse', 'contextManipulation'],
  },
  {
    name: 'CodeBot',
    port: 3004,
    protocol: 'api',
    securityLevel: 'vulnerable',
    vulnerabilities: ['capabilityAbuse'],
  },
  {
    name: 'RAGBot',
    port: 3005,
    protocol: 'api',
    securityLevel: 'weak',
    vulnerabilities: ['dataExfiltration'],
  },
  {
    name: 'VisionBot',
    port: 3006,
    protocol: 'api',
    securityLevel: 'weak',
    vulnerabilities: ['promptInjection'],
  },

  // MCP Agents
  {
    name: 'ToolBot',
    port: 3010,
    protocol: 'mcp',
    securityLevel: 'vulnerable',
    vulnerabilities: ['capabilityAbuse', 'mcpToolExploitation'],
  },
  {
    name: 'DataBot',
    port: 3011,
    protocol: 'mcp',
    securityLevel: 'weak',
    vulnerabilities: ['dataExfiltration'],
  },

  // A2A Agents
  {
    name: 'Orchestrator',
    port: 3020,
    protocol: 'a2a',
    securityLevel: 'standard',
    vulnerabilities: ['agentToAgent'],
  },
  {
    name: 'Worker',
    port: 3021,
    protocol: 'a2a',
    securityLevel: 'weak',
    vulnerabilities: ['agentToAgent', 'capabilityAbuse'],
  },
];

export const DVAA_DASHBOARD_PORT = 3000;

export function getTarget(name: string): DVAATarget | undefined {
  return DVAA_TARGETS.find((t) => t.name === name);
}

export function getTargetsByProtocol(protocol: 'api' | 'mcp' | 'a2a'): DVAATarget[] {
  return DVAA_TARGETS.filter((t) => t.protocol === protocol);
}
