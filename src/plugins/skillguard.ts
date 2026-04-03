export const VERSION = '0.1.0';

import type {
  OpenA2APlugin,
  PluginMetadata,
  PluginStatus,
  Finding,
  Remediation,
  FixOptions,
  PluginInitOptions,
} from './core';
import type { AIMCore } from '@opena2a/aim-core';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// --- Types ---

export interface SkillPin {
  skillName: string;
  hash: string;
  pinnedAt: string;
  filePath: string;
}

export interface SkillGuardConfig {
  dataDir?: string;
  autoPin?: boolean;
}

// --- Constants ---

const GUARD_DIR = '.opena2a/skillguard';
const PINS_FILE = 'pins.json';
const MAX_SCAN_DEPTH = 5;

// --- Dangerous patterns (aligned with hackmyagent-core SKILL-002 through SKILL-006) ---

interface DangerPattern {
  findingId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  patterns: RegExp[];
}

const DANGER_PATTERNS: DangerPattern[] = [
  {
    findingId: 'SKILL-002',
    title: 'Remote fetch pattern',
    description: 'Skill contains remote code execution patterns (curl|sh, wget|sh). This could download and execute malicious code.',
    severity: 'critical',
    patterns: [
      /curl\s.*\|\s*(?:sh|bash|sudo)/i,
      /wget\s.*\|\s*(?:sh|bash|sudo)/i,
      /fetch\s*\(.*\)\s*\.then.*eval/i,
    ],
  },
  {
    findingId: 'SKILL-004',
    title: 'Filesystem write outside sandbox',
    description: 'Skill has unrestricted filesystem write access. Restrict to specific directories.',
    severity: 'high',
    patterns: [
      /filesystem:\*/,
      /filesystem:~\/\*/,
      /filesystem:\//,
    ],
  },
  {
    findingId: 'SKILL-005',
    title: 'Credential file access',
    description: 'Skill accesses sensitive credential directories (~/.ssh, ~/.aws, etc.).',
    severity: 'critical',
    patterns: [
      /~\/\.ssh/,
      /~\/\.aws/,
      /~\/\.config\/solana/,
      /~\/\.config\/gcloud/,
      /~\/\.kube/,
      /~\/\.gnupg/,
      /keychain/i,
      /wallet\.json/i,
      /seed\s*phrase/i,
      /private\s*key/i,
      /credentials\.json/i,
    ],
  },
  {
    findingId: 'SKILL-006',
    title: 'Data exfiltration pattern',
    description: 'Skill contains patterns associated with data exfiltration (webhook.site, requestbin, etc.).',
    severity: 'critical',
    patterns: [
      /webhook\.site/i,
      /requestbin/i,
      /ngrok\.io/i,
      /curl\s.*(?:-d|--data|-X\s*POST)/i,
    ],
  },
  {
    findingId: 'SKILL-008',
    title: 'Reverse shell pattern',
    description: 'Skill contains reverse shell patterns. This is a strong indicator of malicious intent.',
    severity: 'critical',
    patterns: [
      /netcat\s.*-e/i,
      /bash\s+-i\s+/i,
      /\/dev\/tcp\//,
      /\/dev\/udp\//,
    ],
  },
];

// --- Scan helpers ---

function findSkillFiles(dir: string, depth: number = 0): string[] {
  if (depth > MAX_SCAN_DEPTH) return [];

  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findSkillFiles(fullPath, depth + 1));
      } else if (entry.name === 'SKILL.md' || entry.name.endsWith('.skill.md')) {
        results.push(fullPath);
      }
    }
  } catch {
    // Not readable
  }
  return results;
}

function computeHash(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null; // File missing or unreadable
  }
}

function loadPins(agentDir: string): SkillPin[] {
  const pinsPath = path.join(agentDir, GUARD_DIR, PINS_FILE);
  try {
    return JSON.parse(fs.readFileSync(pinsPath, 'utf-8'));
  } catch {
    return []; // File missing or unparseable
  }
}

function savePins(agentDir: string, pins: SkillPin[]): void {
  const guardDir = path.join(agentDir, GUARD_DIR);
  fs.mkdirSync(guardDir, { recursive: true });
  fs.writeFileSync(
    path.join(guardDir, PINS_FILE),
    JSON.stringify(pins, null, 2),
    'utf-8'
  );
}

function scanForDangerousPatterns(filePath: string, agentDir: string): Finding[] {
  const findings: Finding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  const relativePath = path.relative(agentDir, filePath);

  for (const danger of DANGER_PATTERNS) {
    for (const pattern of danger.patterns) {
      if (pattern.test(content)) {
        findings.push({
          id: danger.findingId,
          title: danger.title,
          description: `${relativePath}: ${danger.description}`,
          severity: danger.severity,
          filePath: relativePath,
          autoFixable: false, // Dangerous patterns require manual review
        });
        break; // One finding per danger category per file
      }
    }
  }

  return findings;
}

function scanForTampering(agentDir: string): Finding[] {
  const findings: Finding[] = [];
  const pins = loadPins(agentDir);

  for (const pin of pins) {
    const fullPath = path.join(agentDir, pin.filePath);
    const currentHash = computeHash(fullPath);
    if (currentHash === null) {
      findings.push({
        id: 'SKILL-TAMPER',
        title: 'Pinned skill file missing',
        description: `${pin.filePath} was pinned but no longer exists. It may have been deleted or moved.`,
        severity: 'high',
        filePath: pin.filePath,
        autoFixable: false,
      });
      continue;
    }

    if (currentHash !== pin.hash) {
      findings.push({
        id: 'SKILL-TAMPER',
        title: 'Skill file tampered',
        description: `${pin.filePath} hash does not match pinned value. File was modified after pinning.`,
        severity: 'critical',
        filePath: pin.filePath,
        autoFixable: false,
      });
    }
  }

  return findings;
}

function scanForUnpinnedSkills(agentDir: string): Finding[] {
  const findings: Finding[] = [];
  const pins = loadPins(agentDir);
  const pinnedPaths = new Set(pins.map((p) => p.filePath));

  const skillFiles = findSkillFiles(agentDir);
  for (const file of skillFiles) {
    const relativePath = path.relative(agentDir, file);
    if (!pinnedPaths.has(relativePath)) {
      findings.push({
        id: 'SKILL-UNPIN',
        title: 'Unpinned skill',
        description: `${relativePath} has no integrity pin. Pin with SHA-256 hash to detect tampering.`,
        severity: 'medium',
        filePath: relativePath,
        autoFixable: true,
      });
    }
  }

  return findings;
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: 'hackmyagent',
  displayName: 'Skill Safety Scanner',
  description: 'Detect dangerous patterns in skills (RCE, exfiltration, reverse shells) and pin hashes for tamper detection',
  version: VERSION,
  findings: ['SKILL-002', 'SKILL-004', 'SKILL-005', 'SKILL-006', 'SKILL-008', 'SKILL-UNPIN', 'SKILL-TAMPER'],
  scoreImprovement: 12,
};

export class SkillGuardPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private config: SkillGuardConfig = {};

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.config = (options?.config as SkillGuardConfig) ?? {};
  }

  async scan(agentDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    // Check for dangerous patterns in skill files
    const skillFiles = findSkillFiles(agentDir);
    for (const file of skillFiles) {
      findings.push(...scanForDangerousPatterns(file, agentDir));
    }

    // Check for unpinned skills
    findings.push(...scanForUnpinnedSkills(agentDir));

    // Check for tampered skills (hash mismatch)
    findings.push(...scanForTampering(agentDir));

    if (this.aimCore) {
      this.aimCore.logEvent({
        plugin: 'skillguard',
        action: 'scan.complete',
        target: agentDir,
        result: findings.length > 0 ? 'denied' : 'allowed',
        metadata: { findingsCount: findings.length, skillsScanned: skillFiles.length },
      });
    }

    return findings;
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    const remediations: Remediation[] = [];
    const findings = await this.scan(agentDir);

    if (options?.dryRun) {
      return findings
        .filter((f) => f.autoFixable)
        .map((f) => ({
          findingId: f.id,
          description: `Would pin: ${f.filePath}`,
          filesModified: f.filePath ? [f.filePath] : [],
          rollbackAvailable: true,
        }));
    }

    // Fix: Pin all unpinned skills
    const unpinned = findings.filter((f) => f.id === 'SKILL-UNPIN');
    if (unpinned.length > 0) {
      const pins = loadPins(agentDir);

      for (const finding of unpinned) {
        if (!finding.filePath) continue;

        const fullPath = path.join(agentDir, finding.filePath);
        const hash = computeHash(fullPath);
        if (!hash) continue; // File missing or unreadable
        const skillName = path.basename(finding.filePath, '.skill.md')
          .replace('.md', '');

        pins.push({
          skillName,
          hash,
          pinnedAt: new Date().toISOString(),
          filePath: finding.filePath,
        });
      }

      savePins(agentDir, pins);

      remediations.push({
        findingId: 'SKILL-UNPIN',
        description: `Pinned ${unpinned.length} skill file(s) with SHA-256 hashes`,
        filesModified: [path.join(GUARD_DIR, PINS_FILE)],
        rollbackAvailable: true,
      });
    }

    if (this.aimCore && remediations.length > 0) {
      this.aimCore.logEvent({
        plugin: 'skillguard',
        action: 'fix.applied',
        target: agentDir,
        result: 'allowed',
        metadata: { pinnedSkills: unpinned.length },
      });

      this.aimCore.setTrustHints({ skillsVerified: true });
    }

    return remediations;
  }

  async status(): Promise<PluginStatus> {
    return {
      name: metadata.displayName,
      version: metadata.version,
      active: false,
      findingsCount: 0,
    };
  }

  async uninstall(agentDir: string): Promise<void> {
    const guardDir = path.join(agentDir, GUARD_DIR);
    if (fs.existsSync(guardDir)) {
      fs.rmSync(guardDir, { recursive: true, force: true });
    }
  }
}

export function createPlugin(): SkillGuardPlugin {
  return new SkillGuardPlugin();
}
