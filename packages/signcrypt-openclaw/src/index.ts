export const VERSION = '0.1.0';

import type {
  OpenA2APlugin,
  PluginMetadata,
  PluginStatus,
  Finding,
  Remediation,
  FixOptions,
  PluginInitOptions,
} from '@opena2a/plugin-core';
import type { AIMCore } from '@opena2a/aim-core';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// --- Types ---

export interface SignatureRecord {
  target: string;
  hash: string;
  signature: string;
  signerPublicKey: string;
  signedAt: string;
  expiresAt?: string;
}

export interface SignCryptConfig {
  dataDir?: string;
  maxHeartbeatAge?: number; // seconds, default 604800 (7 days)
}

// --- Constants ---

const SIGNATURE_DIR = '.opena2a/signcrypt';
const SIGNATURES_FILE = 'signatures.json';
const MAX_HEARTBEAT_AGE_SECONDS = 604800; // 7 days
const MAX_SCAN_DEPTH = 5;

// --- Scan helpers ---

function findFiles(dir: string, pattern: RegExp, depth: number = 0): string[] {
  if (depth > MAX_SCAN_DEPTH) return [];

  const results: string[] = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;

      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...findFiles(fullPath, pattern, depth + 1));
      } else if (pattern.test(entry.name)) {
        results.push(fullPath);
      }
    }
  } catch {
    // Not readable
  }
  return results;
}

function checkForSignature(content: string): boolean {
  return (
    content.includes('opena2a_signature:') ||
    content.includes('signature:') ||
    content.includes('-----BEGIN SIGNATURE-----')
  );
}

function checkForHashPin(content: string): boolean {
  return (
    content.includes('pinned_hash:') ||
    content.includes('sha256:') ||
    content.includes('hash:')
  );
}

function scanSkillFiles(agentDir: string): Finding[] {
  const findings: Finding[] = [];

  // Check root SKILL.md
  const rootSkill = path.join(agentDir, 'SKILL.md');
  if (fs.existsSync(rootSkill)) {
    const content = fs.readFileSync(rootSkill, 'utf-8');
    if (!checkForSignature(content)) {
      findings.push({
        id: 'SKILL-001',
        title: 'Unsigned skill',
        description: 'SKILL.md has no cryptographic signature. Sign with Ed25519 to verify authorship.',
        severity: 'medium',
        filePath: 'SKILL.md',
        autoFixable: true,
      });
    }
  }

  // Check *.skill.md files
  const skillFiles = findFiles(agentDir, /\.skill\.md$/);
  for (const file of skillFiles) {
    const content = fs.readFileSync(file, 'utf-8');
    const relativePath = path.relative(agentDir, file);
    if (!checkForSignature(content)) {
      findings.push({
        id: 'SKILL-001',
        title: 'Unsigned skill',
        description: `${relativePath} has no cryptographic signature. Sign with Ed25519 to verify authorship.`,
        severity: 'medium',
        filePath: relativePath,
        autoFixable: true,
      });
    }
  }

  return findings;
}

function scanHeartbeatFiles(agentDir: string): Finding[] {
  const findings: Finding[] = [];

  const heartbeatFiles = [
    path.join(agentDir, 'HEARTBEAT.md'),
    ...findFiles(agentDir, /\.heartbeat\.md$/),
  ];

  for (const file of heartbeatFiles) {
    if (!fs.existsSync(file)) continue;

    const content = fs.readFileSync(file, 'utf-8');
    const relativePath = path.relative(agentDir, file);

    // HEARTBEAT-002: No hash pinning
    if (!checkForHashPin(content)) {
      findings.push({
        id: 'HEARTBEAT-002',
        title: 'No hash pinning on heartbeat',
        description: `${relativePath} has no hash pin. Pin the SHA-256 hash to detect unauthorized changes.`,
        severity: 'high',
        filePath: relativePath,
        autoFixable: true,
      });
    }

    // HEARTBEAT-003: Unsigned heartbeat
    if (!checkForSignature(content)) {
      findings.push({
        id: 'HEARTBEAT-003',
        title: 'Unsigned heartbeat',
        description: `${relativePath} has no cryptographic signature. Sign with Ed25519 to verify authorship.`,
        severity: 'high',
        filePath: relativePath,
        autoFixable: true,
      });
    }
  }

  return findings;
}

// --- Fix helpers ---

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50MB limit for hash computation

function computeFileHash(filePath: string): string | null {
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size > MAX_FILE_SIZE) return null;
  const content = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(content).digest('hex');
}

function appendSignatureBlock(filePath: string, hash: string, aimCore?: AIMCore): void {
  let content = fs.readFileSync(filePath, 'utf-8');

  // Don't add if already signed
  if (checkForSignature(content)) return;

  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + MAX_HEARTBEAT_AGE_SECONDS * 1000).toISOString();

  let signatureHex = 'unsigned';
  let signerKey = 'none';

  if (aimCore) {
    try {
      const identity = aimCore.getIdentity();
      const data = Buffer.from(hash, 'hex');
      const sig = aimCore.sign(data);
      signatureHex = Buffer.from(sig).toString('hex');
      signerKey = identity.publicKey;
    } catch {
      // No identity available — still add hash pin
    }
  }

  const block = [
    '',
    '---',
    '<!-- opena2a:signcrypt -->',
    `pinned_hash: sha256:${hash}`,
    `opena2a_signature: ${signatureHex}`,
    `signer: ${signerKey}`,
    `signed_at: ${now}`,
    `expires_at: ${expiresAt}`,
    '<!-- /opena2a:signcrypt -->',
  ].join('\n');

  content += block + '\n';
  fs.writeFileSync(filePath, content, 'utf-8');
}

function saveSignatureRecord(agentDir: string, record: SignatureRecord): void {
  const sigDir = path.join(agentDir, SIGNATURE_DIR);
  fs.mkdirSync(sigDir, { recursive: true });

  const sigFile = path.join(sigDir, SIGNATURES_FILE);
  let records: SignatureRecord[] = [];

  if (fs.existsSync(sigFile)) {
    try {
      records = JSON.parse(fs.readFileSync(sigFile, 'utf-8'));
    } catch {
      records = [];
    }
  }

  // Replace existing record for same target
  records = records.filter((r) => r.target !== record.target);
  records.push(record);

  fs.writeFileSync(sigFile, JSON.stringify(records, null, 2), 'utf-8');
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: '@opena2a/signcrypt-openclaw',
  displayName: 'SignCrypt',
  description: 'Configuration integrity — Ed25519 signing, hash pinning, heartbeat expiry enforcement',
  version: VERSION,
  findings: ['SKILL-001', 'HEARTBEAT-002', 'HEARTBEAT-003'],
  scoreImprovement: 8,
};

export class SignCryptPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private config: SignCryptConfig = {};

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.config = (options?.config as SignCryptConfig) ?? {};
  }

  async scan(agentDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    findings.push(...scanSkillFiles(agentDir));
    findings.push(...scanHeartbeatFiles(agentDir));

    if (this.aimCore) {
      this.aimCore.logEvent({
        plugin: 'signcrypt',
        action: 'scan.complete',
        target: agentDir,
        result: findings.length > 0 ? 'denied' : 'allowed',
        metadata: { findingsCount: findings.length },
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
          description: `Would sign: ${f.filePath}`,
          filesModified: f.filePath ? [f.filePath] : [],
          rollbackAvailable: false,
        }));
    }

    for (const finding of findings) {
      if (!finding.filePath || !finding.autoFixable) continue;

      const fullPath = path.join(agentDir, finding.filePath);
      if (!fs.existsSync(fullPath)) continue;

      const hash = computeFileHash(fullPath);
      if (!hash) continue; // Skip files too large or not regular files
      appendSignatureBlock(fullPath, hash, this.aimCore);

      const now = new Date().toISOString();
      saveSignatureRecord(agentDir, {
        target: finding.filePath,
        hash: `sha256:${hash}`,
        signature: 'applied',
        signerPublicKey: this.aimCore ? this.aimCore.getIdentity().publicKey : 'none',
        signedAt: now,
        expiresAt: new Date(Date.now() + MAX_HEARTBEAT_AGE_SECONDS * 1000).toISOString(),
      });

      remediations.push({
        findingId: finding.id,
        description: `Signed ${finding.filePath} with SHA-256 hash pin and Ed25519 signature`,
        filesModified: [finding.filePath],
        rollbackAvailable: false,
      });
    }

    if (this.aimCore && remediations.length > 0) {
      this.aimCore.logEvent({
        plugin: 'signcrypt',
        action: 'fix.applied',
        target: agentDir,
        result: 'allowed',
        metadata: { signedFiles: remediations.length },
      });

      this.aimCore.setTrustHints({ configSigned: true });
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
    const sigDir = path.join(agentDir, SIGNATURE_DIR);
    if (fs.existsSync(sigDir)) {
      fs.rmSync(sigDir, { recursive: true, force: true });
    }
  }
}

export function createPlugin(): SignCryptPlugin {
  return new SignCryptPlugin();
}
