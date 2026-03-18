/**
 * NemoClaw Hardening Scanner
 *
 * Scans a live NemoClaw installation for misconfigurations, exposed secrets,
 * network exposure, skill/blueprint integrity issues, and privilege escalation risks.
 *
 * Check ID range: HMA-NMC-001 through HMA-NMC-052
 */

import { execSync } from 'child_process';
import { statSync, readdirSync, readFileSync, existsSync } from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { SecurityFinding, Severity } from './security-check';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const NEMOCLAW_CATEGORIES = [
  'secrets',
  'network',
  'skills',
  'process',
  'openclaw-layer',
] as const;

const HOME = os.homedir();
const NEMOCLAW_DIR = path.join(HOME, '.nemoclaw');
const OPENSHELL_DIR = path.join(HOME, '.openshell');
const OPENCLAW_DIR = path.join(HOME, '.openclaw');

const NVAPI_PATTERNS = [/nvapi-[a-zA-Z0-9_-]{20,}/g, /nv-[a-zA-Z0-9_-]{20,}/g];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeExec(cmd: string): string | null {
  try {
    return execSync(cmd, {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

function maskSecret(value: string): string {
  if (value.length <= 4) return '***';
  return value.substring(0, 4) + '***';
}

function isWorldReadable(filePath: string): boolean {
  try {
    const stats = statSync(filePath);
    return (stats.mode & 0o044) !== 0;
  } catch {
    return false;
  }
}

function isWorldWritable(filePath: string): boolean {
  try {
    const stats = statSync(filePath);
    return (stats.mode & 0o022) !== 0;
  } catch {
    return false;
  }
}

function getListenersOnPort(port: number): string[] {
  const output = safeExec(
    process.platform === 'darwin'
      ? `lsof -iTCP:${port} -sTCP:LISTEN -P -n 2>/dev/null`
      : `ss -tlnp 'sport = :${port}' 2>/dev/null`,
  );
  return output ? output.split('\n').filter(Boolean) : [];
}

function isBoundToNonLoopback(listeners: string[]): boolean {
  for (const line of listeners) {
    if (line.includes('*:') || line.includes('0.0.0.0') || line.includes(':::')) {
      return true;
    }
  }
  return false;
}

function safeReadFile(filePath: string): string | null {
  try {
    return readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function listFilesRecursive(dir: string, maxDepth = 3, depth = 0): string[] {
  if (depth >= maxDepth) return [];
  const results: string[] = [];
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isFile()) {
        results.push(full);
      } else if (entry.isDirectory() && !entry.name.startsWith('.')) {
        results.push(...listFilesRecursive(full, maxDepth, depth + 1));
      }
    }
  } catch {
    // permission denied or missing — skip
  }
  return results;
}

function finding(
  checkId: string,
  name: string,
  description: string,
  category: string,
  severity: Severity,
  passed: boolean,
  message: string,
  extra?: Partial<SecurityFinding>,
): SecurityFinding {
  return {
    checkId,
    name,
    description,
    category,
    severity,
    passed,
    message,
    fixable: extra?.fixable ?? false,
    fixed: extra?.fixed,
    fixMessage: extra?.fixMessage,
    wouldFix: extra?.wouldFix,
    file: extra?.file,
    line: extra?.line,
    fix: extra?.fix,
    attackClass: extra?.attackClass,
    details: extra?.details,
  };
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

function detectInstallation(): {
  hasBinary: boolean;
  hasConfig: boolean;
  hasDocker: boolean;
  hasK3s: boolean;
} {
  const hasBinary = safeExec('which nemoclaw') !== null;
  const hasConfig =
    existsSync(NEMOCLAW_DIR) || existsSync(OPENSHELL_DIR) || existsSync(OPENCLAW_DIR);
  const hasDocker = safeExec('docker info') !== null;
  const hasK3s = safeExec('which k3s') !== null || existsSync('/etc/rancher/k3s');
  return { hasBinary, hasConfig, hasDocker, hasK3s };
}

// ---------------------------------------------------------------------------
// NemoClawScanner
// ---------------------------------------------------------------------------

export class NemoClawScanner {
  async scan(
    targetDir: string,
    options: { autoFix?: boolean; dryRun?: boolean } = {},
  ): Promise<SecurityFinding[]> {
    const install = detectInstallation();

    if (!install.hasBinary && !install.hasConfig && !install.hasDocker) {
      return [
        finding(
          'HMA-NMC-000',
          'NemoClaw not detected',
          'No NemoClaw binary, configuration directories, or Docker daemon found',
          'secrets',
          'low',
          true,
          'NemoClaw does not appear to be installed on this system',
        ),
      ];
    }

    const findings: SecurityFinding[] = [];

    // --- 1. Secrets & Credential Exposure ---
    findings.push(...this.checkSecrets(targetDir));

    // --- 2. Network Exposure ---
    findings.push(...this.checkNetwork(install));

    // --- 3. Skills & Blueprint Integrity ---
    findings.push(...this.checkSkills(targetDir));

    // --- 4. Process & Privilege ---
    findings.push(...this.checkProcess(install));

    // --- 5. OpenClaw Layer ---
    findings.push(...this.checkOpenClawLayer(install));

    // --- 6. Internet Exposure (bonus) ---
    findings.push(...this.checkInternetExposure());

    return findings;
  }

  // =========================================================================
  // 1. Secrets & Credential Exposure (HMA-NMC-001 — HMA-NMC-006)
  // =========================================================================

  private checkSecrets(targetDir: string): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    // HMA-NMC-001: NVIDIA API key in plaintext config files
    results.push(...this.checkNMC001(targetDir));

    // HMA-NMC-002: API key in OpenShell gateway logs
    results.push(...this.checkNMC002());

    // HMA-NMC-003: API key leaked into Docker environment
    results.push(...this.checkNMC003());

    // HMA-NMC-004: API key in shell history
    results.push(...this.checkNMC004());

    // HMA-NMC-005: Blueprint cache world-readable
    results.push(...this.checkNMC005());

    // HMA-NMC-006: OpenClaw session files world-readable
    results.push(...this.checkNMC006());

    return results;
  }

  private checkNMC001(targetDir: string): SecurityFinding[] {
    const results: SecurityFinding[] = [];
    const configFiles: string[] = [];

    // Gather candidate files
    const nemoConfig = path.join(NEMOCLAW_DIR, 'config');
    if (existsSync(nemoConfig)) configFiles.push(nemoConfig);

    // .env files in working dir
    try {
      const entries = readdirSync(targetDir);
      for (const e of entries) {
        if (e === '.env' || e.startsWith('.env.')) {
          configFiles.push(path.join(targetDir, e));
        }
      }
    } catch {
      // skip
    }

    // Dotfiles in working dir
    try {
      const entries = readdirSync(targetDir);
      for (const e of entries) {
        if (e.startsWith('.') && !e.startsWith('.env')) {
          const full = path.join(targetDir, e);
          try {
            if (statSync(full).isFile()) configFiles.push(full);
          } catch {
            // skip
          }
        }
      }
    } catch {
      // skip
    }

    // Also scan ~/.nemoclaw/ recursively for any files
    if (existsSync(NEMOCLAW_DIR)) {
      configFiles.push(...listFilesRecursive(NEMOCLAW_DIR, 2));
    }

    let foundAny = false;
    for (const file of configFiles) {
      const content = safeReadFile(file);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pat of NVAPI_PATTERNS) {
          pat.lastIndex = 0;
          const match = pat.exec(lines[i]);
          if (match) {
            foundAny = true;
            results.push(
              finding(
                'HMA-NMC-001',
                'NVIDIA API key in plaintext config',
                'An NVIDIA API key was found in a plaintext configuration file',
                'secrets',
                'critical',
                false,
                `Found key ${maskSecret(match[0])} in ${file} at line ${i + 1}`,
                {
                  file,
                  line: i + 1,
                  fixable: true,
                  fix: 'Move the API key to an environment variable and reference it as $NVIDIA_API_KEY',
                  attackClass: 'CRED-HARVEST',
                },
              ),
            );
          }
        }
      }
    }

    if (!foundAny) {
      results.push(
        finding(
          'HMA-NMC-001',
          'NVIDIA API key in plaintext config',
          'No NVIDIA API keys found in plaintext configuration files',
          'secrets',
          'critical',
          true,
          'No plaintext NVIDIA API keys detected in config files',
        ),
      );
    }

    return results;
  }

  private checkNMC002(): SecurityFinding[] {
    const logsDir = path.join(OPENSHELL_DIR, 'logs');
    if (!existsSync(logsDir)) {
      return [
        finding(
          'HMA-NMC-002',
          'API key in OpenShell gateway logs',
          'OpenShell logs directory not found',
          'secrets',
          'high',
          true,
          'No OpenShell logs directory at ~/.openshell/logs/',
        ),
      ];
    }

    const results: SecurityFinding[] = [];
    const logFiles = listFilesRecursive(logsDir, 2);
    let foundAny = false;

    for (const file of logFiles) {
      const content = safeReadFile(file);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pat of NVAPI_PATTERNS) {
          pat.lastIndex = 0;
          const match = pat.exec(lines[i]);
          if (match) {
            foundAny = true;
            results.push(
              finding(
                'HMA-NMC-002',
                'API key in OpenShell gateway logs',
                'An API key was found in OpenShell gateway log files',
                'secrets',
                'high',
                false,
                `Found key ${maskSecret(match[0])} in ${file} at line ${i + 1}`,
                {
                  file,
                  line: i + 1,
                  fixable: true,
                  fix: 'Purge log files containing keys: rm ~/.openshell/logs/*.log && configure log redaction in gateway settings',
                  attackClass: 'CRED-HARVEST',
                },
              ),
            );
          }
        }
      }
    }

    if (!foundAny) {
      results.push(
        finding(
          'HMA-NMC-002',
          'API key in OpenShell gateway logs',
          'No API keys found in OpenShell gateway logs',
          'secrets',
          'high',
          true,
          'No API keys detected in OpenShell log files',
        ),
      );
    }

    return results;
  }

  private checkNMC003(): SecurityFinding[] {
    const containerNames = safeExec("docker ps --format '{{.Names}}' 2>/dev/null");
    if (!containerNames) {
      return [
        finding(
          'HMA-NMC-003',
          'API key leaked into Docker environment',
          'Docker not available or no running containers',
          'secrets',
          'high',
          true,
          'Docker daemon not reachable or no running containers',
        ),
      ];
    }

    const results: SecurityFinding[] = [];
    const names = containerNames.split('\n').filter(Boolean);
    let foundAny = false;

    for (const name of names) {
      const inspectOutput = safeExec(`docker inspect ${name} 2>/dev/null`);
      if (!inspectOutput) continue;

      try {
        const containers = JSON.parse(inspectOutput);
        for (const container of containers) {
          const envVars: string[] = container?.Config?.Env ?? [];
          for (const envVar of envVars) {
            for (const pat of NVAPI_PATTERNS) {
              pat.lastIndex = 0;
              const match = pat.exec(envVar);
              if (match) {
                foundAny = true;
                results.push(
                  finding(
                    'HMA-NMC-003',
                    'API key leaked into Docker environment',
                    'An NVIDIA API key was found in a Docker container environment variable',
                    'secrets',
                    'high',
                    false,
                    `Container "${name}" has key ${maskSecret(match[0])} in env`,
                    {
                      fixable: false,
                      fix: 'Use Docker secrets or a secrets manager instead of environment variables. Recreate the container without the key in env.',
                      attackClass: 'CRED-HARVEST',
                      details: { container: name },
                    },
                  ),
                );
              }
            }
          }
        }
      } catch {
        // malformed JSON — skip
      }
    }

    if (!foundAny) {
      results.push(
        finding(
          'HMA-NMC-003',
          'API key leaked into Docker environment',
          'No API keys found in Docker container environments',
          'secrets',
          'high',
          true,
          'No NVIDIA API keys detected in running container environments',
        ),
      );
    }

    return results;
  }

  private checkNMC004(): SecurityFinding[] {
    const historyFiles = [
      path.join(HOME, '.bash_history'),
      path.join(HOME, '.zsh_history'),
      path.join(HOME, '.fish_history'),
    ];

    const results: SecurityFinding[] = [];
    let foundAny = false;

    for (const file of historyFiles) {
      const content = safeReadFile(file);
      if (!content) continue;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pat of NVAPI_PATTERNS) {
          pat.lastIndex = 0;
          const match = pat.exec(lines[i]);
          if (match) {
            foundAny = true;
            results.push(
              finding(
                'HMA-NMC-004',
                'API key in shell history',
                'An NVIDIA API key was found in shell command history',
                'secrets',
                'high',
                false,
                `Found key ${maskSecret(match[0])} in ${path.basename(file)} at line ${i + 1}`,
                {
                  file,
                  line: i + 1,
                  fixable: true,
                  fix: `Remove the line from ${file} or clear history with: history -c && rm ${file}`,
                  attackClass: 'CRED-HARVEST',
                },
              ),
            );
            break; // one per history file is enough
          }
        }
        if (foundAny) break;
      }
    }

    if (!foundAny) {
      results.push(
        finding(
          'HMA-NMC-004',
          'API key in shell history',
          'No API keys found in shell history files',
          'secrets',
          'high',
          true,
          'No NVIDIA API keys detected in shell history',
        ),
      );
    }

    return results;
  }

  private checkNMC005(): SecurityFinding[] {
    const blueprintsDir = path.join(NEMOCLAW_DIR, 'blueprints');
    if (!existsSync(blueprintsDir)) {
      return [
        finding(
          'HMA-NMC-005',
          'Blueprint cache world-readable',
          'Blueprints directory not found',
          'secrets',
          'high',
          true,
          'No blueprints directory at ~/.nemoclaw/blueprints/',
        ),
      ];
    }

    const files = listFilesRecursive(blueprintsDir, 3);
    const worldReadable = files.filter(isWorldReadable);

    if (worldReadable.length === 0) {
      return [
        finding(
          'HMA-NMC-005',
          'Blueprint cache world-readable',
          'Blueprint cache files have restricted permissions',
          'secrets',
          'high',
          true,
          'All blueprint cache files have appropriate permissions',
        ),
      ];
    }

    return [
      finding(
        'HMA-NMC-005',
        'Blueprint cache world-readable',
        'Blueprint cache files are readable by other users on the system',
        'secrets',
        'high',
        false,
        `${worldReadable.length} blueprint file(s) are world-readable`,
        {
          fixable: true,
          fix: 'chmod 600 ~/.nemoclaw/blueprints/**/*',
          attackClass: 'CRED-HARVEST',
          details: {
            files: worldReadable.slice(0, 10),
            total: worldReadable.length,
          },
        },
      ),
    ];
  }

  private checkNMC006(): SecurityFinding[] {
    const sessionsDir = path.join(OPENCLAW_DIR, 'sessions');
    if (!existsSync(sessionsDir)) {
      return [
        finding(
          'HMA-NMC-006',
          'OpenClaw session files world-readable',
          'OpenClaw sessions directory not found',
          'secrets',
          'medium',
          true,
          'No sessions directory at ~/.openclaw/sessions/',
        ),
      ];
    }

    const files = listFilesRecursive(sessionsDir, 3);
    const worldReadable = files.filter(isWorldReadable);

    if (worldReadable.length === 0) {
      return [
        finding(
          'HMA-NMC-006',
          'OpenClaw session files world-readable',
          'OpenClaw session files have restricted permissions',
          'secrets',
          'medium',
          true,
          'All OpenClaw session files have appropriate permissions',
        ),
      ];
    }

    return [
      finding(
        'HMA-NMC-006',
        'OpenClaw session files world-readable',
        'OpenClaw session files are readable by other users on the system',
        'secrets',
        'medium',
        false,
        `${worldReadable.length} session file(s) are world-readable`,
        {
          fixable: true,
          fix: 'chmod 600 ~/.openclaw/sessions/**/*',
          attackClass: 'CRED-HARVEST',
          details: {
            files: worldReadable.slice(0, 10),
            total: worldReadable.length,
          },
        },
      ),
    ];
  }

  // =========================================================================
  // 2. Network Exposure (HMA-NMC-010 — HMA-NMC-015)
  // =========================================================================

  private checkNetwork(install: ReturnType<typeof detectInstallation>): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    // HMA-NMC-010: OpenShell gateway bound to 0.0.0.0
    results.push(this.checkPortBinding('HMA-NMC-010', 'OpenShell gateway bound to 0.0.0.0',
      'OpenShell gateway is listening on all interfaces instead of localhost only',
      18789, 'network', 'critical',
      'Reconfigure OpenShell to bind to 127.0.0.1 only: set bind_address=127.0.0.1 in ~/.openshell/config'));

    // HMA-NMC-011: k3s API server on non-loopback
    if (install.hasK3s) {
      results.push(this.checkPortBinding('HMA-NMC-011', 'k3s API server on non-loopback',
        'k3s API server is listening on all interfaces',
        6443, 'network', 'critical',
        'Start k3s with --bind-address 127.0.0.1 to restrict API access to localhost'));
    } else {
      results.push(finding('HMA-NMC-011', 'k3s API server on non-loopback',
        'k3s not detected on this system', 'network', 'critical', true,
        'k3s is not installed — check skipped'));
    }

    // HMA-NMC-012: Docker socket world-accessible
    results.push(this.checkNMC012());

    // HMA-NMC-013: Sandbox egress policy set to allow-all
    results.push(this.checkNMC013());

    // HMA-NMC-014: Brev remote endpoint without auth
    results.push(this.checkNMC014());

    // HMA-NMC-015: Inference gateway on non-loopback
    results.push(this.checkPortBinding('HMA-NMC-015', 'Inference gateway on non-loopback',
      'Inference gateway is listening on all interfaces instead of localhost only',
      18791, 'network', 'critical',
      'Reconfigure inference gateway to bind to 127.0.0.1: set inference_bind=127.0.0.1 in ~/.nemoclaw/config'));

    return results;
  }

  private checkPortBinding(
    checkId: string,
    name: string,
    description: string,
    port: number,
    category: string,
    severity: Severity,
    fixInstruction: string,
  ): SecurityFinding {
    const listeners = getListenersOnPort(port);

    if (listeners.length === 0) {
      return finding(checkId, name, `No listener detected on port ${port}`,
        category, severity, true, `Port ${port} is not in use`);
    }

    if (isBoundToNonLoopback(listeners)) {
      return finding(checkId, name, description, category, severity, false,
        `Port ${port} is bound to a non-loopback address (accessible from network)`, {
          fixable: true,
          fix: fixInstruction,
          attackClass: 'NETWORK-EXPOSURE',
          details: { port, listeners: listeners.slice(0, 5) },
        });
    }

    return finding(checkId, name, `Port ${port} is bound to loopback only`,
      category, severity, true, `Port ${port} is correctly bound to localhost`);
  }

  private checkNMC012(): SecurityFinding {
    const socketPath = '/var/run/docker.sock';

    if (!existsSync(socketPath)) {
      return finding('HMA-NMC-012', 'Docker socket world-accessible',
        'Docker socket not found', 'network', 'high', true,
        'Docker socket not present at /var/run/docker.sock');
    }

    try {
      const stats = statSync(socketPath);
      const otherRW = stats.mode & 0o006;
      if (otherRW !== 0) {
        return finding('HMA-NMC-012', 'Docker socket world-accessible',
          'Docker socket is accessible by any user on the system', 'network', 'high', false,
          'Docker socket at /var/run/docker.sock is world-accessible', {
            fixable: true,
            fix: 'chmod 660 /var/run/docker.sock && chown root:docker /var/run/docker.sock',
            attackClass: 'PRIV-ESCALATION',
          });
      }
    } catch {
      // cannot stat — likely permission denied, which is fine
    }

    return finding('HMA-NMC-012', 'Docker socket world-accessible',
      'Docker socket permissions are restricted', 'network', 'high', true,
      'Docker socket has appropriate permissions');
  }

  private checkNMC013(): SecurityFinding {
    const policiesDir = path.join(NEMOCLAW_DIR, 'policies');

    if (!existsSync(policiesDir)) {
      return finding('HMA-NMC-013', 'Sandbox egress policy set to allow-all',
        'No policies directory found', 'network', 'high', true,
        'No NemoClaw policies directory at ~/.nemoclaw/policies/ — using defaults');
    }

    const policyFiles = listFilesRecursive(policiesDir, 2);
    for (const file of policyFiles) {
      const content = safeReadFile(file);
      if (!content) continue;

      if (/egress\s*:\s*allow[_-]?all/i.test(content) || /egress_policy\s*=\s*["']?allow/i.test(content)) {
        return finding('HMA-NMC-013', 'Sandbox egress policy set to allow-all',
          'Sandbox containers are allowed unrestricted outbound network access', 'network', 'high', false,
          `Egress policy is set to allow-all in ${file}`, {
            file,
            fixable: true,
            fix: 'Set egress policy to deny-all with explicit allowlist: egress: deny-all in policy file',
            attackClass: 'NETWORK-EXPOSURE',
          });
      }
    }

    return finding('HMA-NMC-013', 'Sandbox egress policy set to allow-all',
      'Sandbox egress policy is restricted', 'network', 'high', true,
      'No allow-all egress policy detected');
  }

  private checkNMC014(): SecurityFinding {
    const configFile = path.join(NEMOCLAW_DIR, 'config');
    const content = safeReadFile(configFile);

    if (!content) {
      return finding('HMA-NMC-014', 'Brev remote endpoint without auth',
        'NemoClaw config file not found', 'network', 'high', true,
        'No NemoClaw config at ~/.nemoclaw/config');
    }

    const hasBrevEndpoint = /brev[_-]?endpoint/i.test(content) || /brev[_-]?remote/i.test(content);
    const hasBrevToken = /brev[_-]?token\s*[=:]\s*\S+/i.test(content);

    if (hasBrevEndpoint && !hasBrevToken) {
      return finding('HMA-NMC-014', 'Brev remote endpoint without auth',
        'A Brev remote endpoint is configured without an authentication token', 'network', 'high', false,
        'Brev remote endpoint configured but no brev_token found', {
          file: configFile,
          fixable: true,
          fix: 'Add brev_token=<your-token> to ~/.nemoclaw/config or set BREV_TOKEN env var',
          attackClass: 'AUTH-BYPASS',
        });
    }

    return finding('HMA-NMC-014', 'Brev remote endpoint without auth',
      'Brev endpoint configuration is secure or not present', 'network', 'high', true,
      hasBrevEndpoint
        ? 'Brev remote endpoint has authentication token configured'
        : 'No Brev remote endpoint configured');
  }

  // =========================================================================
  // 3. Skills & Blueprint Integrity (HMA-NMC-020 — HMA-NMC-024)
  // =========================================================================

  private checkSkills(targetDir: string): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    // HMA-NMC-020: Skills not verified against registry
    results.push(this.checkNMC020(targetDir));

    // HMA-NMC-021: Blueprint not pinned to digest
    results.push(this.checkNMC021());

    // HMA-NMC-022: Skills directory world-writable
    results.push(this.checkNMC022(targetDir));

    // HMA-NMC-023: Heartbeat URLs using HTTP not HTTPS
    results.push(this.checkNMC023());

    // HMA-NMC-024: Skills without Ed25519 signature
    results.push(...this.checkNMC024(targetDir));

    return results;
  }

  private checkNMC020(targetDir: string): SecurityFinding {
    const skillsDir = path.join(targetDir, '.agents', 'skills');

    if (!existsSync(skillsDir)) {
      return finding('HMA-NMC-020', 'Skills not verified against registry',
        'No skills directory found', 'skills', 'high', true,
        'No .agents/skills/ directory in target');
    }

    const unverified: string[] = [];
    try {
      const entries = readdirSync(skillsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const manifestPath = path.join(skillsDir, entry.name, 'manifest.yaml');
        const manifestPathJson = path.join(skillsDir, entry.name, 'manifest.json');
        const manifestContent =
          safeReadFile(manifestPath) ?? safeReadFile(manifestPathJson);

        if (!manifestContent || !/registry[_-]?verified\s*[=:]\s*true/i.test(manifestContent)) {
          unverified.push(entry.name);
        }
      }
    } catch {
      // skip
    }

    if (unverified.length === 0) {
      return finding('HMA-NMC-020', 'Skills not verified against registry',
        'All skills are verified against the registry', 'skills', 'high', true,
        'All skills in .agents/skills/ have registry_verified=true');
    }

    return finding('HMA-NMC-020', 'Skills not verified against registry',
      'One or more skills are not verified against the trust registry', 'skills', 'high', false,
      `${unverified.length} skill(s) not registry-verified: ${unverified.join(', ')}`, {
        fixable: false,
        fix: 'Verify skills against the registry: nemoclaw skill verify --all',
        attackClass: 'SUPPLY-CHAIN',
        details: { unverified },
      });
  }

  private checkNMC021(): SecurityFinding {
    const blueprintsDir = path.join(NEMOCLAW_DIR, 'blueprints');

    if (!existsSync(blueprintsDir)) {
      return finding('HMA-NMC-021', 'Blueprint not pinned to digest',
        'No blueprints directory found', 'skills', 'high', true,
        'No blueprints directory at ~/.nemoclaw/blueprints/');
    }

    const unpinned: string[] = [];
    try {
      const entries = readdirSync(blueprintsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const bpFile = path.join(blueprintsDir, entry.name, 'blueprint.yaml');
        const content = safeReadFile(bpFile);

        if (!content) {
          unpinned.push(entry.name);
          continue;
        }

        // Check for digest field with a non-empty value
        if (!/digest\s*[=:]\s*\S+/i.test(content)) {
          unpinned.push(entry.name);
        }
      }
    } catch {
      // skip
    }

    if (unpinned.length === 0) {
      return finding('HMA-NMC-021', 'Blueprint not pinned to digest',
        'All blueprints are pinned to a content digest', 'skills', 'high', true,
        'All blueprints have a digest pin');
    }

    return finding('HMA-NMC-021', 'Blueprint not pinned to digest',
      'One or more blueprints are not pinned to a content digest, allowing supply-chain substitution',
      'skills', 'high', false,
      `${unpinned.length} blueprint(s) without digest pin: ${unpinned.join(', ')}`, {
        fixable: false,
        fix: 'Pin blueprints to their content digest: nemoclaw blueprint pin --all',
        attackClass: 'SUPPLY-CHAIN',
        details: { unpinned },
      });
  }

  private checkNMC022(targetDir: string): SecurityFinding {
    const skillsDir = path.join(targetDir, '.agents', 'skills');

    if (!existsSync(skillsDir)) {
      return finding('HMA-NMC-022', 'Skills directory world-writable',
        'No skills directory found', 'skills', 'critical', true,
        'No .agents/skills/ directory in target');
    }

    if (isWorldWritable(skillsDir)) {
      return finding('HMA-NMC-022', 'Skills directory world-writable',
        'The skills directory is writable by any user, allowing skill injection',
        'skills', 'critical', false,
        '.agents/skills/ is world-writable', {
          file: skillsDir,
          fixable: true,
          fix: 'chmod 755 .agents/skills/',
          attackClass: 'SUPPLY-CHAIN',
        });
    }

    return finding('HMA-NMC-022', 'Skills directory world-writable',
      'Skills directory has appropriate write permissions', 'skills', 'critical', true,
      '.agents/skills/ is not world-writable');
  }

  private checkNMC023(): SecurityFinding {
    const configDirs = [OPENCLAW_DIR, NEMOCLAW_DIR, OPENSHELL_DIR];
    const httpHeartbeats: Array<{ file: string; url: string }> = [];

    for (const dir of configDirs) {
      if (!existsSync(dir)) continue;
      const files = listFilesRecursive(dir, 3);
      for (const file of files) {
        const content = safeReadFile(file);
        if (!content) continue;

        const matches = content.match(/heartbeat[_-]?url\s*[=:]\s*http:\/\/[^\s"']+/gi);
        if (matches) {
          for (const m of matches) {
            const url = m.replace(/heartbeat[_-]?url\s*[=:]\s*/i, '').trim();
            httpHeartbeats.push({ file, url });
          }
        }
      }
    }

    if (httpHeartbeats.length === 0) {
      return finding('HMA-NMC-023', 'Heartbeat URLs using HTTP not HTTPS',
        'No insecure heartbeat URLs found', 'skills', 'medium', true,
        'No HTTP heartbeat URLs detected in configuration');
    }

    return finding('HMA-NMC-023', 'Heartbeat URLs using HTTP not HTTPS',
      'Heartbeat endpoints are configured with HTTP instead of HTTPS, allowing interception',
      'skills', 'medium', false,
      `${httpHeartbeats.length} heartbeat URL(s) using HTTP instead of HTTPS`, {
        fixable: true,
        fix: 'Change heartbeat URLs to use https:// in configuration files',
        attackClass: 'NETWORK-EXPOSURE',
        details: { urls: httpHeartbeats.slice(0, 10) },
      });
  }

  private checkNMC024(targetDir: string): SecurityFinding[] {
    const skillsDir = path.join(targetDir, '.agents', 'skills');

    if (!existsSync(skillsDir)) {
      return [
        finding('HMA-NMC-024', 'Skills without Ed25519 signature',
          'No skills directory found', 'skills', 'high', true,
          'No .agents/skills/ directory in target'),
      ];
    }

    const unsigned: string[] = [];
    try {
      const entries = readdirSync(skillsDir, { withFileTypes: true });
      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const skillDir = path.join(skillsDir, entry.name);

        // Look for .sig files
        try {
          const skillFiles = readdirSync(skillDir);
          const hasSig = skillFiles.some(
            (f) => f.endsWith('.sig') || f.endsWith('.ed25519'),
          );
          if (!hasSig) {
            unsigned.push(entry.name);
          }
        } catch {
          unsigned.push(entry.name);
        }
      }
    } catch {
      // skip
    }

    if (unsigned.length === 0) {
      return [
        finding('HMA-NMC-024', 'Skills without Ed25519 signature',
          'All skills have Ed25519 signatures', 'skills', 'high', true,
          'All skills in .agents/skills/ have signature files'),
      ];
    }

    return [
      finding('HMA-NMC-024', 'Skills without Ed25519 signature',
        'One or more skills lack a cryptographic signature, making tampering undetectable',
        'skills', 'high', false,
        `${unsigned.length} skill(s) without signature: ${unsigned.join(', ')}`, {
          fixable: false,
          fix: 'Sign skills with Ed25519: nemoclaw skill sign --key ~/.nemoclaw/signing.key --all',
          attackClass: 'SUPPLY-CHAIN',
          details: { unsigned },
        }),
    ];
  }

  // =========================================================================
  // 4. Process & Privilege (HMA-NMC-030 — HMA-NMC-034)
  // =========================================================================

  private checkProcess(install: ReturnType<typeof detectInstallation>): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    // HMA-NMC-030: NemoClaw running as root
    results.push(this.checkNMC030());

    // HMA-NMC-031: Docker sandbox with --privileged
    results.push(this.checkNMC031(install));

    // HMA-NMC-032: seccomp unconfined
    results.push(this.checkNMC032(install));

    // HMA-NMC-033: Landlock not supported by kernel
    results.push(this.checkNMC033());

    // HMA-NMC-034: k3s with --disable-network-policy
    results.push(this.checkNMC034(install));

    return results;
  }

  private checkNMC030(): SecurityFinding {
    const psOutput = safeExec('ps aux 2>/dev/null');
    if (!psOutput) {
      return finding('HMA-NMC-030', 'NemoClaw running as root',
        'Unable to check NemoClaw process ownership', 'process', 'high', true,
        'Could not inspect running processes');
    }

    const nemoLines = psOutput
      .split('\n')
      .filter((line) => /nemoclaw/i.test(line) && !/grep/i.test(line));

    const rootProcesses = nemoLines.filter((line) => {
      const parts = line.trim().split(/\s+/);
      return parts[0] === 'root';
    });

    if (rootProcesses.length > 0) {
      return finding('HMA-NMC-030', 'NemoClaw running as root',
        'NemoClaw processes are running as the root user',
        'process', 'high', false,
        `${rootProcesses.length} NemoClaw process(es) running as root`, {
          fixable: false,
          fix: 'Run NemoClaw as a non-root user: sudo -u nemoclaw nemoclaw start',
          attackClass: 'PRIV-ESCALATION',
        });
    }

    if (nemoLines.length === 0) {
      return finding('HMA-NMC-030', 'NemoClaw running as root',
        'No running NemoClaw processes found', 'process', 'high', true,
        'No NemoClaw processes detected');
    }

    return finding('HMA-NMC-030', 'NemoClaw running as root',
      'NemoClaw processes are running as a non-root user', 'process', 'high', true,
      'NemoClaw is not running as root');
  }

  private checkNMC031(install: ReturnType<typeof detectInstallation>): SecurityFinding {
    if (!install.hasDocker) {
      return finding('HMA-NMC-031', 'Docker sandbox with --privileged',
        'Docker not available', 'process', 'critical', true,
        'Docker daemon not reachable — check skipped');
    }

    const containerNames = safeExec("docker ps --format '{{.Names}}' 2>/dev/null");
    if (!containerNames) {
      return finding('HMA-NMC-031', 'Docker sandbox with --privileged',
        'No running containers', 'process', 'critical', true,
        'No running Docker containers');
    }

    const names = containerNames.split('\n').filter(Boolean);
    const privileged: string[] = [];

    for (const name of names) {
      const inspectOutput = safeExec(`docker inspect ${name} 2>/dev/null`);
      if (!inspectOutput) continue;

      try {
        const containers = JSON.parse(inspectOutput);
        for (const container of containers) {
          if (container?.HostConfig?.Privileged === true) {
            privileged.push(name);
          }
        }
      } catch {
        // skip
      }
    }

    if (privileged.length > 0) {
      return finding('HMA-NMC-031', 'Docker sandbox with --privileged',
        'One or more sandbox containers are running in privileged mode, defeating isolation',
        'process', 'critical', false,
        `Privileged container(s): ${privileged.join(', ')}`, {
          fixable: false,
          fix: 'Recreate containers without --privileged. Use specific capabilities instead: --cap-add=SYS_PTRACE',
          attackClass: 'SANDBOX-ESCAPE',
          details: { privileged },
        });
    }

    return finding('HMA-NMC-031', 'Docker sandbox with --privileged',
      'No containers running in privileged mode', 'process', 'critical', true,
      'No privileged containers detected');
  }

  private checkNMC032(install: ReturnType<typeof detectInstallation>): SecurityFinding {
    if (!install.hasDocker) {
      return finding('HMA-NMC-032', 'seccomp unconfined',
        'Docker not available', 'process', 'critical', true,
        'Docker daemon not reachable — check skipped');
    }

    const containerNames = safeExec("docker ps --format '{{.Names}}' 2>/dev/null");
    if (!containerNames) {
      return finding('HMA-NMC-032', 'seccomp unconfined',
        'No running containers', 'process', 'critical', true,
        'No running Docker containers');
    }

    const names = containerNames.split('\n').filter(Boolean);
    const unconfined: string[] = [];

    for (const name of names) {
      const inspectOutput = safeExec(`docker inspect ${name} 2>/dev/null`);
      if (!inspectOutput) continue;

      try {
        const containers = JSON.parse(inspectOutput);
        for (const container of containers) {
          const securityOpts: string[] = container?.HostConfig?.SecurityOpt ?? [];
          if (securityOpts.some((opt: string) => opt.includes('seccomp=unconfined'))) {
            unconfined.push(name);
          }
        }
      } catch {
        // skip
      }
    }

    if (unconfined.length > 0) {
      return finding('HMA-NMC-032', 'seccomp unconfined',
        'One or more containers have seccomp disabled, allowing unrestricted system calls',
        'process', 'critical', false,
        `Unconfined container(s): ${unconfined.join(', ')}`, {
          fixable: false,
          fix: 'Remove --security-opt seccomp=unconfined and use the default seccomp profile',
          attackClass: 'SANDBOX-ESCAPE',
          details: { unconfined },
        });
    }

    return finding('HMA-NMC-032', 'seccomp unconfined',
      'All containers have seccomp profiles applied', 'process', 'critical', true,
      'No containers with seccomp=unconfined detected');
  }

  private checkNMC033(): SecurityFinding {
    if (process.platform !== 'linux') {
      return finding('HMA-NMC-033', 'Landlock not supported by kernel',
        'Landlock is a Linux-specific security feature', 'process', 'medium', true,
        `Current platform is ${process.platform} — Landlock check not applicable`);
    }

    const unameR = safeExec('uname -r');
    if (!unameR) {
      return finding('HMA-NMC-033', 'Landlock not supported by kernel',
        'Unable to determine kernel version', 'process', 'medium', false,
        'Could not determine kernel version', {
          fix: 'Upgrade to Linux kernel >= 5.13 for Landlock filesystem sandboxing',
        });
    }

    // Parse major.minor from kernel version string
    const match = unameR.match(/^(\d+)\.(\d+)/);
    if (!match) {
      return finding('HMA-NMC-033', 'Landlock not supported by kernel',
        'Could not parse kernel version', 'process', 'medium', false,
        `Kernel version ${unameR} could not be parsed`);
    }

    const major = parseInt(match[1], 10);
    const minor = parseInt(match[2], 10);

    if (major > 5 || (major === 5 && minor >= 13)) {
      return finding('HMA-NMC-033', 'Landlock not supported by kernel',
        'Kernel supports Landlock filesystem sandboxing', 'process', 'medium', true,
        `Kernel ${unameR} supports Landlock (>= 5.13)`);
    }

    return finding('HMA-NMC-033', 'Landlock not supported by kernel',
      'The running kernel does not support Landlock, limiting filesystem sandboxing',
      'process', 'medium', false,
      `Kernel ${unameR} does not support Landlock (requires >= 5.13)`, {
        fixable: false,
        fix: 'Upgrade to Linux kernel >= 5.13 for Landlock filesystem sandboxing',
      });
  }

  private checkNMC034(install: ReturnType<typeof detectInstallation>): SecurityFinding {
    if (!install.hasK3s) {
      return finding('HMA-NMC-034', 'k3s with --disable-network-policy',
        'k3s not detected', 'process', 'high', true,
        'k3s is not installed — check skipped');
    }

    const psOutput = safeExec('ps aux 2>/dev/null');
    if (!psOutput) {
      return finding('HMA-NMC-034', 'k3s with --disable-network-policy',
        'Unable to check k3s process arguments', 'process', 'high', true,
        'Could not inspect running processes');
    }

    const k3sLines = psOutput
      .split('\n')
      .filter((line) => /k3s\s+server/i.test(line));

    const disabledPolicy = k3sLines.some((line) => /--disable[_-]network[_-]?policy/i.test(line));

    if (disabledPolicy) {
      return finding('HMA-NMC-034', 'k3s with --disable-network-policy',
        'k3s is running with network policies disabled, allowing unrestricted pod-to-pod traffic',
        'process', 'high', false,
        'k3s server started with --disable-network-policy', {
          fixable: false,
          fix: 'Restart k3s without the --disable-network-policy flag and apply NetworkPolicy resources',
          attackClass: 'NETWORK-EXPOSURE',
        });
    }

    if (k3sLines.length === 0) {
      return finding('HMA-NMC-034', 'k3s with --disable-network-policy',
        'No running k3s server process found', 'process', 'high', true,
        'k3s server process not currently running');
    }

    return finding('HMA-NMC-034', 'k3s with --disable-network-policy',
      'k3s has network policies enabled', 'process', 'high', true,
      'k3s server is running with network policies enabled');
  }

  // =========================================================================
  // 5. OpenClaw Layer (HMA-NMC-040 — HMA-NMC-042)
  // =========================================================================

  private checkOpenClawLayer(install: ReturnType<typeof detectInstallation>): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    // HMA-NMC-040: Re-run OpenClaw checks inside sandbox
    results.push(
      finding('HMA-NMC-040', 'Re-run OpenClaw checks inside sandbox',
        'OpenClaw security checks should also be run inside the sandbox environment for full coverage',
        'openclaw-layer', 'medium', true,
        'Run hackmyagent scan inside the sandbox to check for OpenClaw-specific misconfigurations', {
          fix: 'docker exec <sandbox-container> npx hackmyagent scan --ci /app',
        }),
    );

    // HMA-NMC-041: OpenClaw heartbeat active inside sandbox
    results.push(this.checkNMC041(install));

    // HMA-NMC-042: OpenClaw sessions persisted outside sandbox
    results.push(this.checkNMC042(install));

    return results;
  }

  private checkNMC041(install: ReturnType<typeof detectInstallation>): SecurityFinding {
    if (!install.hasDocker) {
      return finding('HMA-NMC-041', 'OpenClaw heartbeat active inside sandbox',
        'Docker not available', 'openclaw-layer', 'high', true,
        'Docker daemon not reachable — check skipped');
    }

    const containerNames = safeExec("docker ps --format '{{.Names}}' 2>/dev/null");
    if (!containerNames) {
      return finding('HMA-NMC-041', 'OpenClaw heartbeat active inside sandbox',
        'No running containers', 'openclaw-layer', 'high', true,
        'No running Docker containers');
    }

    const names = containerNames.split('\n').filter(Boolean);
    const noHeartbeat: string[] = [];

    for (const name of names) {
      // Check if container has OpenClaw heartbeat config
      const result = safeExec(
        `docker exec ${name} test -f /root/.openclaw/heartbeat.yaml 2>/dev/null && echo exists`,
      );
      if (result === null || !result.includes('exists')) {
        // Also check /home/*/.openclaw/
        const altResult = safeExec(
          `docker exec ${name} sh -c 'ls /home/*/.openclaw/heartbeat.yaml 2>/dev/null' 2>/dev/null`,
        );
        if (!altResult) {
          noHeartbeat.push(name);
        }
      }
    }

    if (noHeartbeat.length === 0) {
      return finding('HMA-NMC-041', 'OpenClaw heartbeat active inside sandbox',
        'All sandbox containers have heartbeat configuration', 'openclaw-layer', 'high', true,
        'OpenClaw heartbeat is configured in sandbox containers');
    }

    if (noHeartbeat.length === names.length) {
      return finding('HMA-NMC-041', 'OpenClaw heartbeat active inside sandbox',
        'No sandbox containers have OpenClaw heartbeat configuration', 'openclaw-layer', 'high', false,
        `No heartbeat config found in ${noHeartbeat.length} container(s)`, {
          fixable: false,
          fix: 'Mount heartbeat.yaml into sandbox: -v ~/.openclaw/heartbeat.yaml:/root/.openclaw/heartbeat.yaml:ro',
          attackClass: 'MONITORING-GAP',
          details: { containers: noHeartbeat },
        });
    }

    return finding('HMA-NMC-041', 'OpenClaw heartbeat active inside sandbox',
      'Some sandbox containers lack heartbeat configuration', 'openclaw-layer', 'high', false,
      `${noHeartbeat.length} container(s) without heartbeat: ${noHeartbeat.join(', ')}`, {
        fixable: false,
        fix: 'Mount heartbeat.yaml into sandbox: -v ~/.openclaw/heartbeat.yaml:/root/.openclaw/heartbeat.yaml:ro',
        attackClass: 'MONITORING-GAP',
        details: { containers: noHeartbeat },
      });
  }

  private checkNMC042(install: ReturnType<typeof detectInstallation>): SecurityFinding {
    if (!install.hasDocker) {
      return finding('HMA-NMC-042', 'OpenClaw sessions persisted outside sandbox',
        'Docker not available', 'openclaw-layer', 'high', true,
        'Docker daemon not reachable — check skipped');
    }

    const containerNames = safeExec("docker ps --format '{{.Names}}' 2>/dev/null");
    if (!containerNames) {
      return finding('HMA-NMC-042', 'OpenClaw sessions persisted outside sandbox',
        'No running containers', 'openclaw-layer', 'high', true,
        'No running Docker containers');
    }

    const names = containerNames.split('\n').filter(Boolean);
    const leaking: string[] = [];

    for (const name of names) {
      const inspectOutput = safeExec(`docker inspect ${name} 2>/dev/null`);
      if (!inspectOutput) continue;

      try {
        const containers = JSON.parse(inspectOutput);
        for (const container of containers) {
          const mounts: Array<{ Source?: string; Destination?: string }> =
            container?.Mounts ?? [];
          for (const mount of mounts) {
            if (
              mount.Source?.includes('.openclaw') &&
              mount.Destination?.includes('.openclaw')
            ) {
              // Host .openclaw is bind-mounted into the container
              leaking.push(name);
              break;
            }
          }
        }
      } catch {
        // skip
      }
    }

    if (leaking.length === 0) {
      return finding('HMA-NMC-042', 'OpenClaw sessions persisted outside sandbox',
        'No containers have host OpenClaw directories bind-mounted', 'openclaw-layer', 'high', true,
        'OpenClaw session data is not leaking from sandbox containers');
    }

    return finding('HMA-NMC-042', 'OpenClaw sessions persisted outside sandbox',
      'Sandbox containers have host ~/.openclaw/ bind-mounted, allowing session data to persist outside the sandbox',
      'openclaw-layer', 'high', false,
      `${leaking.length} container(s) with bind-mounted ~/.openclaw/: ${leaking.join(', ')}`, {
        fixable: false,
        fix: 'Use a named Docker volume instead of bind-mounting ~/.openclaw/. Remove -v ~/.openclaw:/root/.openclaw from container config.',
        attackClass: 'DATA-LEAK',
        details: { containers: leaking },
      });
  }

  // =========================================================================
  // 6. Internet Exposure — Bonus (HMA-NMC-050 — HMA-NMC-052)
  // =========================================================================

  private checkInternetExposure(): SecurityFinding[] {
    const results: SecurityFinding[] = [];

    const checks: Array<{
      id: string;
      name: string;
      port: number;
      service: string;
    }> = [
      { id: 'HMA-NMC-050', name: 'Gateway port internet-exposed', port: 18789, service: 'OpenShell gateway' },
      { id: 'HMA-NMC-051', name: 'k3s API internet-exposed', port: 6443, service: 'k3s API server' },
      { id: 'HMA-NMC-052', name: 'Browser automation port exposed', port: 18791, service: 'browser automation endpoint' },
    ];

    for (const check of checks) {
      const listeners = getListenersOnPort(check.port);

      if (listeners.length === 0) {
        results.push(
          finding(check.id, check.name,
            `${check.service} is not running on port ${check.port}`,
            'network', 'critical', true,
            `Port ${check.port} is not in use`),
        );
        continue;
      }

      if (!isBoundToNonLoopback(listeners)) {
        results.push(
          finding(check.id, check.name,
            `${check.service} is bound to loopback only`,
            'network', 'critical', true,
            `Port ${check.port} is bound to localhost — not internet-exposed`),
        );
        continue;
      }

      // Port is bound to non-loopback — check for firewall rules
      const hasFirewall = this.detectFirewallRule(check.port);

      if (hasFirewall) {
        results.push(
          finding(check.id, check.name,
            `${check.service} is on a non-loopback address but a firewall rule was detected`,
            'network', 'critical', true,
            `Port ${check.port} is on non-loopback but firewall rule detected`),
        );
      } else {
        results.push(
          finding(check.id, check.name,
            `${check.service} is bound to a non-loopback address with no detected firewall rule — potentially internet-exposed`,
            'network', 'critical', false,
            `Port ${check.port} is potentially internet-exposed (no firewall rule detected)`, {
              fixable: true,
              fix: `Bind ${check.service} to 127.0.0.1 or add a firewall rule: sudo ufw deny ${check.port} (Linux) / sudo pfctl -e (macOS). Self-check: curl https://internetdb.shodan.io/$(curl -s ifconfig.me)`,
              attackClass: 'NETWORK-EXPOSURE',
              details: { port: check.port, listeners: listeners.slice(0, 5) },
            }),
        );
      }
    }

    return results;
  }

  private detectFirewallRule(port: number): boolean {
    if (process.platform === 'darwin') {
      // macOS: check pf
      const pfStatus = safeExec('sudo pfctl -s rules 2>/dev/null');
      if (pfStatus && pfStatus.includes(String(port))) return true;

      // Also check Application Firewall
      const fwStatus = safeExec('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null');
      if (fwStatus && fwStatus.includes('enabled')) return true;
    } else {
      // Linux: check iptables / nftables / ufw
      const iptables = safeExec(`iptables -L -n 2>/dev/null`);
      if (iptables && iptables.includes(String(port))) return true;

      const ufw = safeExec('ufw status 2>/dev/null');
      if (ufw && ufw.includes(String(port))) return true;

      const nft = safeExec('nft list ruleset 2>/dev/null');
      if (nft && nft.includes(String(port))) return true;
    }

    return false;
  }
}
