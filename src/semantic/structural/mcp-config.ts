/**
 * Deep MCP Configuration Analysis (Layer 2)
 *
 * Parses MCP configs structurally and detects:
 * - Overprivileged filesystem scope (/, /home, /Users)
 * - Sandbox bypass flags (--no-sandbox, --privileged)
 * - Secrets in args array (exposed to LLM)
 * - Wildcard permissions
 * - Attack chains (filesystem + shell + network = read-execute-exfiltrate)
 * - Large attack surface (>5 servers)
 */

import type { SemanticFinding, AnalysisFile, McpServerConfig } from '../types';

/** Paths that indicate overprivileged filesystem scope */
const OVERPRIVILEGED_PATHS = [
  { pattern: /^\/$/,                     label: 'root filesystem (/)', severity: 'critical' as const },
  { pattern: /^\/home\/?$/,              label: '/home directory', severity: 'critical' as const },
  { pattern: /^\/Users\/?$/,             label: '/Users directory', severity: 'critical' as const },
  { pattern: /^\/etc\/?$/,               label: '/etc directory', severity: 'high' as const },
  { pattern: /^\/var\/?$/,               label: '/var directory', severity: 'high' as const },
  { pattern: /^~\/?$/,                   label: 'home directory (~)', severity: 'high' as const },
  { pattern: /^\/home\/[^/]+\/?$/,       label: 'user home directory', severity: 'high' as const },
  { pattern: /^\/Users\/[^/]+\/?$/,      label: 'user home directory', severity: 'high' as const },
];

/** Sandbox bypass flags */
const SANDBOX_BYPASS_FLAGS = [
  '--no-sandbox',
  '--disable-sandbox',
  '--privileged',
  '--disable-setuid-sandbox',
  '--no-zygote',
];

/** Patterns in args that look like secrets */
const SECRET_ARG_PATTERNS = [
  /sk-[a-zA-Z0-9_-]{20,}/,
  /ghp_[a-zA-Z0-9]{36}/,
  /github_pat_/,
  /AKIA[0-9A-Z]{16}/,
  /Bearer\s+[a-zA-Z0-9._-]{20,}/,
  /xox[baprs]-/,
  /AIza[0-9A-Za-z_-]{35}/,
];

/** Key-name pattern for secret args */
const SECRET_KEY_ARG = /^--(token|key|secret|password|api[-_]?key|auth|credential)$/i;

/** Known legitimate @modelcontextprotocol package suffixes */
const KNOWN_MCP_PACKAGES = new Set([
  'server-filesystem', 'server-memory', 'server-github',
  'server-google-drive', 'server-postgres', 'server-sqlite',
  'server-puppeteer', 'server-brave-search', 'inspector', 'sdk',
]);

/** Server capabilities for attack chain detection */
type Capability = 'filesystem' | 'shell' | 'network' | 'database' | 'browser';

function classifyServer(name: string, config: McpServerConfig): Capability[] {
  const capabilities: Capability[] = [];
  const lower = [name, config.command, ...(config.args || [])].join(' ').toLowerCase();

  if (lower.includes('filesystem') || lower.includes('fs') || lower.includes('file')) {
    capabilities.push('filesystem');
  }
  if (lower.includes('shell') || lower.includes('exec') || lower.includes('bash') || lower.includes('terminal') || lower.includes('command')) {
    capabilities.push('shell');
  }
  if (lower.includes('fetch') || lower.includes('http') || lower.includes('request') || lower.includes('curl') || lower.includes('network') || lower.includes('web')) {
    capabilities.push('network');
  }
  if (lower.includes('postgres') || lower.includes('mysql') || lower.includes('sqlite') || lower.includes('mongo') || lower.includes('redis') || lower.includes('database') || lower.includes('db')) {
    capabilities.push('database');
  }
  if (lower.includes('browser') || lower.includes('puppeteer') || lower.includes('playwright') || lower.includes('chrome') || lower.includes('selenium')) {
    capabilities.push('browser');
  }

  return capabilities;
}

export class McpConfigAnalyzer {
  analyze(files: AnalysisFile[]): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    for (const file of files) {
      if (file.type !== 'mcp_config' && file.type !== 'claude_settings') continue;

      let config: Record<string, unknown>;
      try {
        config = JSON.parse(file.content);
      } catch {
        continue;
      }

      const servers =
        (config as { mcpServers?: Record<string, McpServerConfig> }).mcpServers || {};

      const allCapabilities = new Map<string, Capability[]>();

      for (const [serverName, serverConfig] of Object.entries(servers)) {
        if (!serverConfig || typeof serverConfig !== 'object') continue;

        // Track capabilities for attack chain detection
        const caps = classifyServer(serverName, serverConfig);
        allCapabilities.set(serverName, caps);

        // Check overprivileged scope
        findings.push(...this.checkOverprivilegedScope(serverName, serverConfig, file));

        // Check sandbox bypass
        findings.push(...this.checkSandboxBypass(serverName, serverConfig, file));

        // Check secrets in args
        findings.push(...this.checkSecretsInArgs(serverName, serverConfig, file));

        // Check wildcard permissions
        findings.push(...this.checkWildcardPermissions(serverName, serverConfig, file));

        // Check typosquatted packages
        findings.push(...this.checkTyposquatPackages(serverName, serverConfig, file));

        // Check bootstrap/remote-code execution in args
        findings.push(...this.checkBootstrapScript(serverName, serverConfig, file));
      }

      // Check attack chains across servers
      findings.push(...this.checkAttackChains(allCapabilities, file));

      // Check server count
      const serverCount = Object.keys(servers).length;
      if (serverCount > 5) {
        findings.push({
          id: 'SEM-MCP-006',
          title: 'Large MCP attack surface',
          description: `${serverCount} MCP servers configured in ${file.path}. Each server expands the agent's capabilities and attack surface.`,
          rationale:
            'More servers mean more capabilities the agent can be manipulated into using. Review whether all servers are necessary.',
          category: 'mcp-config',
          severity: 'info',
          file: file.path,
          recommendation: 'Review each MCP server and remove any that are not actively needed.',
          layer: 2,
          autoFixable: false,
          attackClass: 'MCP-SCOPE-EXPAND',
        });
      }
    }

    return findings;
  }

  private checkOverprivilegedScope(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const args = config.args || [];

    for (const arg of args) {
      for (const { pattern, label, severity } of OVERPRIVILEGED_PATHS) {
        if (pattern.test(arg)) {
          const lineNum = this.findLineNumber(file.content, arg);
          findings.push({
            id: 'SEM-MCP-001',
            title: 'Overprivileged MCP server scope',
            description: `MCP server "${serverName}" has access to ${label}. This grants the agent read/write access to the entire ${label}.`,
            rationale:
              'Overprivileged filesystem access allows the agent (or an attacker via prompt injection) to read sensitive files like SSH keys, credentials, and system configs.',
            category: 'mcp-config',
            severity,
            file: file.path,
            line: lineNum,
            recommendation: `Scope "${serverName}" to the project directory: replace "${arg}" with "./" or a specific subdirectory.`,
            layer: 2,
            autoFixable: false,
            attackClass: 'MCP-PRIV-ESC',
          });
          break;
        }
      }
    }

    return findings;
  }

  private checkSandboxBypass(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const args = config.args || [];

    for (const arg of args) {
      if (SANDBOX_BYPASS_FLAGS.some((flag) => arg.includes(flag))) {
        const lineNum = this.findLineNumber(file.content, arg);
        findings.push({
          id: 'SEM-MCP-002',
          title: 'Sandbox bypass in MCP server',
          description: `MCP server "${serverName}" uses sandbox bypass flag "${arg}" in ${file.path}.`,
          rationale:
            'Sandbox bypass flags disable security boundaries that prevent the agent from accessing system resources. This significantly increases the blast radius of any compromise.',
          category: 'mcp-config',
          severity: 'high',
          file: file.path,
          line: lineNum,
          recommendation: `Remove the "${arg}" flag from "${serverName}" or document why sandbox bypass is required.`,
          layer: 2,
          autoFixable: false,
          attackClass: 'MCP-PRIV-ESC',
        });
      }
    }

    return findings;
  }

  private checkSecretsInArgs(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const args = config.args || [];

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];

      // Check for known secret patterns directly in args
      for (const pattern of SECRET_ARG_PATTERNS) {
        if (pattern.test(arg)) {
          const lineNum = this.findLineNumber(file.content, arg.substring(0, 20));
          findings.push({
            id: 'SEM-MCP-003',
            title: 'Secret exposed in MCP server args',
            description: `MCP server "${serverName}" has a credential-like value in its args array in ${file.path}. Args are visible to the LLM.`,
            rationale:
              'MCP server args are passed on the command line and visible to the LLM in tool descriptions. Secrets in args can be extracted via prompt injection. Use env block instead.',
            category: 'mcp-config',
            severity: 'critical',
            file: file.path,
            line: lineNum,
            recommendation: `Move the secret from args to the env block: "env": { "API_KEY": "..." } — or better, reference an environment variable.`,
            layer: 2,
            autoFixable: false,
            attackClass: 'MCP-CRED',
          });
          break;
        }
      }

      // Check for --secret=value or --token value patterns
      if (SECRET_KEY_ARG.test(arg) && i + 1 < args.length) {
        const nextArg = args[i + 1];
        if (nextArg && nextArg.length >= 8 && !nextArg.startsWith('-')) {
          const lineNum = this.findLineNumber(file.content, arg);
          findings.push({
            id: 'SEM-MCP-003',
            title: 'Secret exposed in MCP server args',
            description: `MCP server "${serverName}" passes "${arg}" as a command-line argument in ${file.path}.`,
            rationale:
              'Command-line arguments are visible in process listings and to the LLM. Use environment variables instead.',
            category: 'mcp-config',
            severity: 'high',
            file: file.path,
            line: lineNum,
            recommendation: `Move "${arg}" value to the env block of the MCP server config.`,
            layer: 2,
            autoFixable: false,
            attackClass: 'MCP-CRED',
          });
        }
      }
    }

    return findings;
  }

  private checkWildcardPermissions(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    const checkWildcard = (
      field: string[] | undefined,
      fieldName: string
    ) => {
      if (!field) return;
      if (field.includes('*') || field.some((v) => v === '*')) {
        findings.push({
          id: 'SEM-MCP-004',
          title: 'Wildcard permission in MCP server',
          description: `MCP server "${serverName}" has ${fieldName}: ["*"] in ${file.path}, granting unrestricted access.`,
          rationale:
            'Wildcard permissions disable capability boundaries. The agent (or an attacker) can use any tool or command without restriction.',
          category: 'mcp-config',
          severity: 'high',
          file: file.path,
          recommendation: `Replace wildcard with specific allowed ${fieldName}: ["tool1", "tool2"].`,
          layer: 2,
          autoFixable: false,
          attackClass: 'MCP-SCOPE-WILDCARD',
        });
      }
    };

    checkWildcard(config.allowedTools, 'allowedTools');
    checkWildcard(config.allowedCommands, 'allowedCommands');

    return findings;
  }

  private checkAttackChains(
    allCapabilities: Map<string, Capability[]>,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const allCaps = new Set<Capability>();

    for (const caps of allCapabilities.values()) {
      for (const cap of caps) {
        allCaps.add(cap);
      }
    }

    // Attack chain: filesystem + shell + network = read-execute-exfiltrate
    if (allCaps.has('filesystem') && allCaps.has('shell') && allCaps.has('network')) {
      const fsServers = [...allCapabilities.entries()].filter(([, c]) => c.includes('filesystem')).map(([n]) => n);
      const shellServers = [...allCapabilities.entries()].filter(([, c]) => c.includes('shell')).map(([n]) => n);
      const netServers = [...allCapabilities.entries()].filter(([, c]) => c.includes('network')).map(([n]) => n);

      findings.push({
        id: 'SEM-MCP-005',
        title: 'MCP attack chain: read-execute-exfiltrate',
        description: `MCP servers in ${file.path} form a complete attack chain: filesystem (${fsServers.join(', ')}) + shell (${shellServers.join(', ')}) + network (${netServers.join(', ')}). An attacker could read files, execute code, and exfiltrate data.`,
        rationale:
          'When filesystem, shell, and network capabilities are all available, a prompt injection attack can read sensitive files, execute arbitrary code, and send data to an external server. This is the most dangerous MCP configuration pattern.',
        category: 'mcp-config',
        severity: 'high',
        file: file.path,
        recommendation:
          'Remove at least one capability from the chain. If all three are needed, add strict scope limits to each server.',
        layer: 2,
        autoFixable: false,
        attackClass: 'MCP-CHAIN-EXFIL',
      });
    }

    // Attack chain: filesystem + network (no shell needed for data exfiltration)
    if (allCaps.has('filesystem') && allCaps.has('network') && !allCaps.has('shell')) {
      findings.push({
        id: 'SEM-MCP-005',
        title: 'MCP attack chain: read-exfiltrate',
        description: `MCP servers in ${file.path} enable a read-exfiltrate chain: filesystem access + network access. An attacker could read files and send data externally.`,
        rationale:
          'Even without shell access, filesystem + network capabilities allow reading sensitive files and exfiltrating them via HTTP requests.',
        category: 'mcp-config',
        severity: 'medium',
        file: file.path,
        recommendation:
          'Scope filesystem access to the project directory and restrict network access to specific domains.',
        layer: 2,
        autoFixable: false,
        attackClass: 'MCP-SCOPE-LEAK',
      });
    }

    return findings;
  }

  private editDistance(a: string, b: string): number {
    if (Math.abs(a.length - b.length) > 3) return 99;
    const dp: number[][] = [];
    for (let i = 0; i <= a.length; i++) {
      dp[i] = [];
      for (let j = 0; j <= b.length; j++) {
        dp[i][j] = i === 0 ? j : j === 0 ? i : 0;
      }
    }
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
    return dp[a.length][b.length];
  }

  private checkTyposquatPackages(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const args = config.args || [];

    for (const arg of args) {
      if (!arg.startsWith('@modelcontextprotocol/')) continue;
      const suffix = arg.slice('@modelcontextprotocol/'.length);
      // Exact match is legitimate
      if (KNOWN_MCP_PACKAGES.has(suffix)) continue;
      // Check edit distance from any known package (1–2 edits = likely typosquat)
      const isTypo = [...KNOWN_MCP_PACKAGES].some(
        known => {
          const d = this.editDistance(suffix, known);
          return d > 0 && d <= 2;
        }
      );
      if (!isTypo) continue;

      findings.push({
        id: 'SEM-MCP-007',
        title: 'Typosquatted MCP package',
        description: `MCP server "${serverName}" uses package "${arg}" which closely resembles a legitimate @modelcontextprotocol package. This may be a typosquatting attack.`,
        rationale:
          'Typosquatted packages execute arbitrary code during npm install and on every server start. A package name 1-2 characters off from an official package is a supply chain attack vector.',
        category: 'mcp-config',
        severity: 'critical',
        file: file.path,
        recommendation: `Replace "${arg}" with the correct package name. Verify: npm view ${arg} to see if it exists and who publishes it.`,
        layer: 2,
        autoFixable: false,
        attackClass: 'MCP-TYPOSQUAT',
      });
      break; // one finding per server is sufficient
    }
    return findings;
  }

  private checkBootstrapScript(
    serverName: string,
    config: McpServerConfig,
    file: AnalysisFile
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const allArgs = [config.command, ...(config.args || [])].join(' ');

    // Detect curl|sh, wget|sh, bash <(curl ...) patterns — unconditional remote code execution
    const bootstrapPattern = /\bcurl\b[^|]*\|\s*(?:sh|bash)|\bwget\b[^|]*\|\s*(?:sh|bash)|bash\s+<\s*\(curl/i;
    if (bootstrapPattern.test(allArgs)) {
      findings.push({
        id: 'SEM-MCP-008',
        title: 'Remote code execution via bootstrap script',
        description: `MCP server "${serverName}" executes a remote install script via curl|sh or similar. Any code served at that URL runs with the user's privileges on every agent startup.`,
        rationale:
          'curl|sh is an unconditional remote code execution vector. The remote server can serve different content at any time, turning every agent restart into a potential compromise.',
        category: 'mcp-config',
        severity: 'critical',
        file: file.path,
        recommendation:
          `Remove the bootstrap script. Install the MCP package via a verified package manager with a pinned version and hash. Never use curl|sh in an MCP server command.`,
        layer: 2,
        autoFixable: false,
        attackClass: 'MCP-SUPPLY-CHAIN',
      });
    }
    return findings;
  }

  private findLineNumber(content: string, searchStr: string): number | undefined {
    if (!searchStr) return undefined;
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(searchStr)) {
        return i + 1;
      }
    }
    return undefined;
  }
}
