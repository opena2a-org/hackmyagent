/**
 * External Scanner
 * Scans remote targets for exposed MCP endpoints, configs, and credentials
 */

import * as net from 'net';
import * as http from 'http';
import * as https from 'https';
import type { ExternalScanResult, ExternalFinding, ScannerOptions, FindingSeverity } from './types';

// Default ports to scan
const DEFAULT_PORTS = [80, 443];

// Config file paths to check
const CONFIG_PATHS = [
  '/.claude/settings.json',
  '/mcp.json',
  '/.cursor/mcp.json',
  '/.vscode/mcp.json',
  '/config.json',
  '/.env',
];

// MCP endpoint paths to check
const MCP_SSE_PATHS = ['/sse', '/events', '/mcp/sse', '/mcp/events'];
const MCP_TOOLS_PATHS = ['/tools', '/list', '/mcp/tools', '/mcp/list'];

// CLAUDE.md paths
const CLAUDE_MD_PATHS = ['/CLAUDE.md', '/.claude/CLAUDE.md'];

// API key patterns
const API_KEY_PATTERNS = [
  { name: 'Anthropic', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{6,}/ },
  { name: 'OpenAI', pattern: /sk-proj-[a-zA-Z0-9]{6,}/ },
  { name: 'OpenAI', pattern: /sk-[a-zA-Z0-9]{20,}/ },
  { name: 'AWS', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
];

// Severity weights for scoring
const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 10,
  low: 5,
};

function generateId(): string {
  return Math.random().toString(36).substring(2, 10);
}

function calculateGrade(score: number): string {
  if (score >= 90) return 'strong';
  if (score >= 80) return 'good';
  if (score >= 70) return 'moderate';
  if (score >= 60) return 'improving';
  return 'needs-attention';
}

function isPrivateOrReserved(hostname: string): boolean {
  if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal') return true;
  if (net.isIPv4(hostname)) {
    const parts = hostname.split('.').map(Number);
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 0) return true;
  }
  return false;
}

function validateTarget(target: string): void {
  // Validate protocol if a full URL was provided
  if (target.includes('://')) {
    const protocol = target.split('://')[0].toLowerCase();
    if (protocol !== 'http' && protocol !== 'https') {
      throw new Error(`Unsupported protocol "${protocol}". Only http and https are allowed.`);
    }
  }
}

export class ExternalScanner {
  async scan(target: string, options?: ScannerOptions): Promise<ExternalScanResult> {
    // Validate protocol (block file://, gopher://, etc.)
    validateTarget(target);

    // Extract hostname for private IP warning
    const hostname = target.replace(/^https?:\/\//, '').split(/[:/]/)[0];
    if (isPrivateOrReserved(hostname)) {
      // Log warning but allow -- scanning local services is a core use case for security testing
      console.warn(`[HMA] Warning: scanning private/reserved address "${hostname}". Ensure you have authorization.`);
    }

    const startTime = Date.now();
    const timeout = options?.timeout ?? 2000;
    const ports = options?.ports ?? DEFAULT_PORTS;
    const skipPortScan = options?.skipPortScan ?? false;

    // Global scan timeout: per-port timeout * port count, capped at 60s
    const globalTimeout = Math.min(timeout * ports.length, 60_000);

    // Race the scan against a global timeout
    const scanWork = async (): Promise<ExternalScanResult> => {
      // Port scan
      let openPorts: number[] = [];
      if (!skipPortScan) {
        openPorts = await this.scanPorts(target, ports, timeout);
      }

      // Run security checks on open ports
      const findings: ExternalFinding[] = [];

      const insecure = options?.insecure === true;
      for (const port of openPorts) {
        const portFindings = await this.checkPort(target, port, timeout, insecure);
        findings.push(...portFindings);
      }

      // If no ports were reachable, score reflects that nothing was tested
      if (openPorts.length === 0 && !skipPortScan) {
        const duration = Date.now() - startTime;
        return {
          id: generateId(),
          target,
          score: -1,
          grade: 'N/A',
          findings: [{
            id: generateId(),
            checkId: 'SCAN-UNREACHABLE',
            severity: 'medium' as FindingSeverity,
            title: 'Target unreachable',
            description: `No open ports detected on ${target}. The target may be offline, blocking connections, or the ports are filtered. Score is not applicable — nothing was tested.`,
            port: 0,
            evidence: 'Port scan returned 0 open ports',
            impact: 'Cannot assess security posture of an unreachable target',
            fix: 'Verify the target is running and accessible. Try specifying ports explicitly with -p (e.g., -p 80,443).',
          }],
          duration,
          timestamp: new Date(),
          openPorts: [],
        };
      }

      // Calculate score using exponential decay (diminishing returns per finding)
      let weightedSum = 0;
      for (const finding of findings) {
        weightedSum += SEVERITY_WEIGHTS[finding.severity];
      }
      const DECAY_CONSTANT = 150;
      const score = weightedSum === 0
        ? 100
        : Math.round(100 * Math.exp(-weightedSum / DECAY_CONSTANT));

      const grade = calculateGrade(score);
      const duration = Date.now() - startTime;

      return {
        id: generateId(),
        target,
        score,
        grade,
        findings,
        duration,
        timestamp: new Date(),
        openPorts,
      };
    };

    const timeoutPromise = new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Scan timed out after ${globalTimeout}ms (${ports.length} ports x ${timeout}ms each). Try fewer ports (-p 80,443) or increase -t timeout.`)), globalTimeout)
    );

    return Promise.race([scanWork(), timeoutPromise]);
  }

  private async scanPorts(
    target: string,
    ports: number[],
    timeout: number
  ): Promise<number[]> {
    const openPorts: number[] = [];

    await Promise.all(
      ports.map(async (port) => {
        const isOpen = await this.isPortOpen(target, port, timeout);
        if (isOpen) {
          openPorts.push(port);
        }
      })
    );

    return openPorts.sort((a, b) => a - b);
  }

  private isPortOpen(host: string, port: number, timeout: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        socket.destroy();
        resolve(false);
      });

      socket.connect(port, host);
    });
  }

  private async checkPort(
    target: string,
    port: number,
    timeout: number,
    insecure = false
  ): Promise<ExternalFinding[]> {
    const findings: ExternalFinding[] = [];
    const useHttps = port === 443;
    const baseUrl = `http${useHttps ? 's' : ''}://${target}:${port}`;

    // Check MCP SSE endpoints
    for (const path of MCP_SSE_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.contentType?.includes('text/event-stream')) {
        findings.push({
          id: generateId(),
          checkId: 'MCP-SSE',
          severity: 'critical',
          title: 'MCP SSE Endpoint Exposed',
          description: 'Server-Sent Events endpoint for MCP is publicly accessible',
          port,
          path,
          evidence: `Content-Type: ${result.contentType}`,
          impact: 'Attackers can connect to the MCP server and potentially execute commands',
          fix: 'Restrict access with authentication or firewall rules',
        });
        break;
      }
    }

    // Check MCP tools endpoints
    for (const path of MCP_TOOLS_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && result.body?.includes('tools')) {
        findings.push({
          id: generateId(),
          checkId: 'MCP-TOOLS',
          severity: 'critical',
          title: 'MCP Tools Endpoint Exposed',
          description: 'MCP tools listing is publicly accessible',
          port,
          path,
          evidence: `Found tools listing at ${path}`,
          impact: 'Attackers can enumerate available MCP tools and capabilities',
          fix: 'Restrict access with authentication or remove from public access',
        });
        break;
      }
    }

    // Check config files
    for (const path of CONFIG_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && result.body) {
        // Check if it looks like JSON config
        if (
          result.contentType?.includes('application/json') ||
          result.body.trim().startsWith('{')
        ) {
          findings.push({
            id: generateId(),
            checkId: 'CONFIG-EXPOSED',
            severity: 'critical',
            title: 'Configuration File Exposed',
            description: `Configuration file ${path} is publicly accessible`,
            port,
            path,
            evidence: `HTTP 200 at ${path}`,
            impact: 'Configuration files may contain sensitive settings, API keys, or server details',
            fix: 'Remove file from public access or configure web server to deny access',
          });
        }
      }
    }

    // Check CLAUDE.md
    for (const path of CLAUDE_MD_PATHS) {
      const result = await this.httpProbe(baseUrl + path, timeout, insecure);
      if (result && result.status === 200 && result.body) {
        findings.push({
          id: generateId(),
          checkId: 'CLAUDE-MD-EXPOSED',
          severity: 'high',
          title: 'CLAUDE.md System Instructions Exposed',
          description: 'Agent system instructions file is publicly accessible',
          port,
          path,
          evidence: `Found CLAUDE.md at ${path}`,
          impact: 'System instructions reveal agent behavior, capabilities, and potential weaknesses',
          fix: 'Remove file from public access or configure web server to deny access',
        });
        break;
      }
    }

    // Check root path for API keys in responses
    const rootResult = await this.httpProbe(baseUrl + '/', timeout, insecure);
    if (rootResult && rootResult.body) {
      for (const { name, pattern } of API_KEY_PATTERNS) {
        if (pattern.test(rootResult.body)) {
          findings.push({
            id: generateId(),
            checkId: 'API-KEY-EXPOSED',
            severity: 'critical',
            title: `${name} API Key Exposed`,
            description: `${name} API key found in HTTP response`,
            port,
            path: '/',
            evidence: `Found ${name} API key pattern in response`,
            impact: 'API keys can be used to access services, incur costs, or steal data',
            fix: 'Remove API keys from responses and rotate compromised keys',
          });
          break;
        }
      }
    }

    return findings;
  }

  private httpProbe(
    url: string,
    timeout: number,
    insecure = false
  ): Promise<{ status: number; contentType?: string; body?: string } | null> {
    return new Promise((resolve) => {
      const isHttps = url.startsWith('https://');
      const client = isHttps ? https : http;

      const req = client.get(
        url,
        {
          timeout,
          headers: {
            'User-Agent': 'HackMyAgent-Scanner/1.0',
            'ngrok-skip-browser-warning': 'true',
          },
          rejectUnauthorized: !insecure,
        },
        (res) => {
          let body = '';
          res.on('data', (chunk) => {
            body += chunk;
            // Limit body size
            if (body.length > 10000) {
              res.destroy();
            }
          });
          res.on('end', () => {
            resolve({
              status: res.statusCode ?? 0,
              contentType: res.headers['content-type'],
              body: body.substring(0, 10000),
            });
          });
          res.on('error', () => resolve(null));
        }
      );

      req.on('timeout', () => {
        req.destroy();
        resolve(null);
      });

      req.on('error', () => resolve(null));
    });
  }
}
