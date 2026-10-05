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
import { MCP_SERVER_MAP_KEYS } from '../../mcp-clients';

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

/**
 * Read a list-valued server field (`args`, `allowedTools`, `allowedCommands`)
 * as the list of strings it declares.
 *
 * A server entry is parsed JSON, not a typed `McpServerConfig`, and every
 * check below iterates these fields and calls string methods on the elements.
 * `"allowedTools": 5`, `"args": {}` or `"args": ["x", 7]` threw a TypeError
 * there, the caller's catch swallowed it, and the scan dropped EVERY Layer-2
 * finding for the whole tree — the other servers' and the other analyzers'
 * included — with no notice. One malformed entry was a way to switch the
 * layer off.
 *
 * Arrays and strings are read the way the compiler's tool-declaration
 * normaliser reads them: an array keeps its string elements, and a lone string
 * is a one-element list (so `"allowedTools": "*"` is still the wildcard it
 * spells). Any other value declares nothing.
 */
function stringList(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  if (typeof value === 'string') return [value];
  return [];
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

      // The server map hangs off a key the CLIENT chooses: `mcpServers` in
      // `.mcp.json` and `.cursor/mcp.json`, `servers` in the VS Code workspace
      // file this collector also globs. Reading `mcpServers` alone handed this
      // analyzer an EMPTY map for every `.vscode/mcp.json` — no overprivileged
      // scope, no secret in args, no attack chain, a server count of zero —
      // while Layer 1's VSCODE-002 was reading the same file's servers.
      //
      // One map, so a server named under both keys is evaluated once.
      const servers: Record<string, McpServerConfig> = {};
      for (const mapKey of MCP_SERVER_MAP_KEYS) {
        const map = (config as Record<string, unknown>)[mapKey];
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        Object.assign(servers, map as Record<string, McpServerConfig>);
      }

      const allCapabilities = new Map<string, Capability[]>();
      // Built on the first finding that cites a line, then shared by every
      // finding in this file: one pass over the text, not one per finding.
      let located: Map<string, ServerLocation | null> | undefined;
      const locate = () => (located ??= locateServerEntries(file.content));

      for (const [serverName, rawConfig] of Object.entries(servers)) {
        if (!rawConfig || typeof rawConfig !== 'object') continue;

        const raw = rawConfig as unknown as Record<string, unknown>;
        const serverConfig: McpServerConfig = {
          ...rawConfig,
          args: stringList(raw.args),
          allowedTools: stringList(raw.allowedTools),
          allowedCommands: stringList(raw.allowedCommands),
        };

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
        findings.push(...this.checkWildcardPermissions(serverName, serverConfig, file, locate));

        // Check typosquatted packages
        findings.push(...this.checkTyposquatPackages(serverName, serverConfig, file, locate));

        // Check bootstrap/remote-code execution in args
        findings.push(...this.checkBootstrapScript(serverName, serverConfig, file, locate));
      }

      // Check attack chains across servers
      findings.push(...this.checkAttackChains(allCapabilities, file));

      // Check server count
      const serverNames = Object.keys(servers);
      const serverCount = serverNames.length;
      if (serverCount > 5) {
        const serverList = serverNames.join(', ');
        findings.push({
          id: 'SEM-MCP-006',
          title: 'Large MCP attack surface',
          description: `${serverCount} MCP servers configured in ${file.path}: ${serverList}. Each server expands the agent's capabilities and attack surface.`,
          rationale:
            'More servers mean more capabilities the agent can be manipulated into using via prompt injection. Review whether all servers are necessary for normal operation.',
          category: 'mcp-config',
          severity: 'info',
          file: file.path,
          recommendation: 'opena2a mcp audit — lists all configured MCP servers, scans each for security issues, and shows capability risk scores. Remove servers not actively needed.',
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
            recommendation: `opena2a protect . — scans MCP configs for hardcoded secrets and encrypts them into a secure vault. Keys are injected at runtime via the env block.`,
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
    file: AnalysisFile,
    locate: () => Map<string, ServerLocation | null>
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];

    const checkWildcard = (
      field: string[] | undefined,
      fieldName: string
    ) => {
      if (!field) return;
      if (field.includes('*')) {
        findings.push({
          id: 'SEM-MCP-004',
          title: 'Wildcard permission in MCP server',
          description: `MCP server "${serverName}" has ${fieldName}: ["*"] in ${file.path}, granting unrestricted access.`,
          rationale:
            'Wildcard permissions disable capability boundaries. The agent (or an attacker) can use any tool or command without restriction.',
          category: 'mcp-config',
          severity: 'high',
          file: file.path,
          line: serverFieldLine(locate(), serverName, fieldName),
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
    file: AnalysisFile,
    locate: () => Map<string, ServerLocation | null>
  ): SemanticFinding[] {
    const findings: SemanticFinding[] = [];
    const args = config.args || [];

    // A counter rather than `args.entries()`: `args` is whatever the file holds,
    // and iterating it is what this check already did with a non-array value.
    let argIndex = -1;
    for (const arg of args) {
      argIndex++;
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
        line: serverArgLine(locate(), serverName, argIndex),
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
    file: AnalysisFile,
    locate: () => Map<string, ServerLocation | null>
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
        line: serverKeyLine(locate(), serverName),
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

/**
 * Where one member of a server entry sits in the raw JSON (#644): the line of
 * its key, the key as written, and, for an array value, the line each element
 * starts on.
 */
interface MemberLocation {
  line: number;
  spelling: string;
  elementLines: number[];
}

/** Where one server entry sits in the raw JSON: its key's line, the key as written, its members. */
interface ServerLocation {
  line: number;
  spelling: string;
  members: Map<string, MemberLocation>;
}

/**
 * Every server entry under the top-level server-map keys, located in one pass
 * over the raw JSON (#644).
 *
 * Structural rather than textual: a key counts only at its depth, so a server
 * named `command` is not found at the first `"command":` in the file, and an
 * `env` holding a key named like a later server is not that server. Duplicate
 * keys resolve as `JSON.parse` resolves them (the last one wins), and the maps
 * merge in `MCP_SERVER_MAP_KEYS` order as `analyze` merges them, so each
 * location belongs to the entry the findings were computed from. A later value
 * that is not an object is kept as `null`, because it replaced the entry.
 *
 * One pass for the whole file, not one per finding: this analyzer can report
 * every server in a file, and a lookup that rescans the text per finding (as
 * `lineOfJsonValue` in `scanner/json-locate.ts` does, by design, for the one
 * grant it is asked about) makes a half-megabyte file of wildcard servers take
 * seconds instead of milliseconds.
 *
 * Iterative, with an explicit stack: a file nested deeper than the call stack
 * still parses with `JSON.parse`, and must not throw here. Called only on text
 * `JSON.parse` accepted; anything unexpected returns what was found so far.
 */
function locateServerEntries(content: string): Map<string, ServerLocation | null> {
  type Role = 'root' | 'map' | 'server' | 'args' | 'other';
  interface Frame {
    role: Role;
    isObject: boolean;
    awaitingKey: boolean;
    key: string;
    keySpelling: string;
    keyLine: number;
    map?: Map<string, ServerLocation | null>;
    server?: ServerLocation;
    elements?: number[];
  }
  const maps = new Map<string, Map<string, ServerLocation | null>>();
  const stack: Frame[] = [];
  let line = 1;
  let i = 0;
  const n = content.length;

  const frame = (role: Role, isObject: boolean): Frame =>
    ({ role, isObject, awaitingKey: isObject, key: '', keySpelling: '', keyLine: 0 });

  /** Records what a value at this position is, and returns the frame of the container it opens. */
  const beginValue = (opens: 'object' | 'array' | 'none'): Frame | undefined => {
    const top = stack[stack.length - 1];
    let child = opens === 'none' ? undefined : frame('other', opens === 'object');
    if (!top) {
      if (child && opens === 'object') child.role = 'root';
    } else if (!top.isObject) {
      if (top.role === 'args') top.elements!.push(line);
    } else if (top.role === 'root') {
      if (MCP_SERVER_MAP_KEYS.includes(top.key)) {
        if (child && opens === 'object') {
          child.role = 'map';
          child.map = new Map();
          maps.set(top.key, child.map);
        } else {
          maps.delete(top.key);
        }
      }
    } else if (top.role === 'map') {
      if (child && opens === 'object') {
        const server: ServerLocation = { line: top.keyLine, spelling: top.keySpelling, members: new Map() };
        top.map!.set(top.key, server);
        child.role = 'server';
        child.server = server;
      } else {
        top.map!.set(top.key, null);
      }
    } else if (top.role === 'server') {
      const member: MemberLocation = { line: top.keyLine, spelling: top.keySpelling, elementLines: [] };
      top.server!.members.set(top.key, member);
      if (child && opens === 'array' && top.key === 'args') {
        child.role = 'args';
        child.elements = member.elementLines;
      }
    }
    return child;
  };

  try {
    while (i < n) {
      const c = content.charCodeAt(i);
      if (c === 0x0a) {
        line++;
        i++;
      } else if (c === 0x20 || c === 0x09 || c === 0x0d || c === 0x3a /* : */) {
        i++;
      } else if (c === 0x2c /* , */) {
        const top = stack[stack.length - 1];
        if (top?.isObject) top.awaitingKey = true;
        i++;
      } else if (c === 0x7b /* { */ || c === 0x5b /* [ */) {
        stack.push(beginValue(c === 0x7b ? 'object' : 'array')!);
        i++;
      } else if (c === 0x7d /* } */ || c === 0x5d /* ] */) {
        stack.pop();
        i++;
      } else if (c === 0x22 /* " */) {
        let j = i + 1;
        while (j < n) {
          const d = content.charCodeAt(j);
          if (d === 0x5c /* \ */) j += 2;
          else if (d === 0x22) break;
          else j++;
        }
        const top = stack[stack.length - 1];
        if (top?.isObject && top.awaitingKey) {
          top.awaitingKey = false;
          if (top.role === 'root' || top.role === 'map' || top.role === 'server') {
            top.keySpelling = content.slice(i, j + 1);
            top.key = JSON.parse(top.keySpelling) as string;
            top.keyLine = line;
          }
        } else {
          beginValue('none');
        }
        i = j + 1;
      } else {
        // A number, true, false or null: runs to the next delimiter.
        beginValue('none');
        while (i < n && !/[\s,\]}:]/.test(content[i])) i++;
      }
    }
  } catch {
    // Unreachable on text JSON.parse accepted; keep what was located.
  }

  const servers = new Map<string, ServerLocation | null>();
  for (const mapKey of MCP_SERVER_MAP_KEYS) {
    for (const [name, location] of maps.get(mapKey) ?? []) servers.set(name, location);
  }
  return servers;
}

/**
 * The line of the server's key, or undefined (#644). The key must be written
 * as `JSON.stringify` writes the name: a key spelled another way (a `\u`
 * escape) is left without a line, as a line nobody can find the name on is no
 * help.
 */
function serverKeyLine(servers: Map<string, ServerLocation | null>, serverName: string): number | undefined {
  const server = servers.get(serverName);
  return server && server.spelling === JSON.stringify(serverName) ? server.line : undefined;
}

/** The line of the server's `field` key, else the server's key line (#644). */
function serverFieldLine(
  servers: Map<string, ServerLocation | null>,
  serverName: string,
  field: string,
): number | undefined {
  const keyLine = serverKeyLine(servers, serverName);
  if (keyLine === undefined) return undefined;
  const member = servers.get(serverName)?.members.get(field);
  return member && member.spelling === JSON.stringify(field) ? member.line : keyLine;
}

/** The line of the server's `args[index]`, else the server's key line (#644). */
function serverArgLine(
  servers: Map<string, ServerLocation | null>,
  serverName: string,
  index: number,
): number | undefined {
  return servers.get(serverName)?.members.get('args')?.elementLines[index] ?? serverKeyLine(servers, serverName);
}
