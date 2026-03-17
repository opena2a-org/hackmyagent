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

// --- Types for secretless-ai dynamic import ---
// These mirror secretless-ai's exported types without requiring a compile-time dependency.
// secretless-ai is loaded dynamically at runtime so it remains optional.

interface SecretlessInitResult {
  toolsDetected: string[];
  toolsConfigured: string[];
  filesCreated: string[];
  filesModified: string[];
  secretsFound: number;
}

interface SecretlessScanFinding {
  file: string;
  line: number;
  patternId: string;
  patternName: string;
  severity: 'critical' | 'high';
  preview: string;
}

interface SecretlessVerifyResult {
  envVars: Record<string, boolean>;
  exposedInContext: Array<{
    envVar: string;
    patternName: string;
    file: string;
    line: number;
  }>;
  exposedInTranscripts: Array<{
    file: string;
    line: number;
    jsonPath: string;
    patternName: string;
  }>;
  passed: boolean;
}

interface SecretlessAPI {
  init: (projectDir: string) => SecretlessInitResult;
  scan: (projectDir: string, options?: { scanGlobal?: boolean }) => SecretlessScanFinding[];
  verify: (projectDir: string) => SecretlessVerifyResult;
  detectAITools: (projectDir: string) => Array<{
    tool: string;
    configDir: string;
    settingsFile: string;
    hooksSupported: boolean;
  }>;
}

// --- Dynamic import ---

let _secretlessApi: SecretlessAPI | null | undefined; // undefined = not checked, null = not available

async function loadSecretless(): Promise<SecretlessAPI | null> {
  if (_secretlessApi !== undefined) return _secretlessApi;

  try {
    // Use a variable to prevent TypeScript from resolving the module at compile time.
    // secretless-ai is an optional runtime dependency loaded dynamically.
    const moduleName = 'secretless-ai';
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require(moduleName);
    _secretlessApi = {
      init: mod.init,
      scan: mod.scan,
      verify: mod.verify,
      detectAITools: mod.detectAITools,
    };
    return _secretlessApi;
  } catch {
    _secretlessApi = null;
    return null;
  }
}

// --- Scan helpers ---

function checkAIToolProtection(agentDir: string, api: SecretlessAPI): Finding[] {
  const findings: Finding[] = [];

  const tools = api.detectAITools(agentDir);
  if (tools.length === 0) {
    // No AI tools detected in this project — nothing to protect against
    return findings;
  }

  let verifyResult: SecretlessVerifyResult;
  try {
    verifyResult = api.verify(agentDir);
  } catch {
    // verify may fail if project structure is unexpected — skip gracefully
    return findings;
  }

  // Credentials visible in AI tool context files (.env, CLAUDE.md, .cursorrules, etc.)
  for (const exposed of verifyResult.exposedInContext) {
    findings.push({
      id: 'SLAI-001',
      title: `${exposed.patternName} visible to AI tools`,
      description: `${exposed.file}:${exposed.line} -- this credential is readable by AI coding ` +
        `tools in their context window.`,
      severity: 'critical',
      filePath: exposed.file,
      line: exposed.line,
      autoFixable: true,
    });
  }

  // Credentials that already leaked into AI chat transcripts
  for (const leaked of verifyResult.exposedInTranscripts) {
    findings.push({
      id: 'SLAI-002',
      title: `${leaked.patternName} leaked in AI transcript`,
      description: `${leaked.file}:${leaked.line} -- credential found in AI chat history. ` +
        `It may have been sent to a cloud LLM provider.`,
      severity: 'high',
      filePath: leaked.file,
      line: leaked.line,
      autoFixable: false, // transcript redaction needs manual review
    });
  }

  // AI tools present but credential files not blocked
  if (verifyResult.exposedInContext.length === 0 && !verifyResult.passed) {
    // No direct exposure yet, but protections aren't set up either
    findings.push({
      id: 'SLAI-003',
      title: 'AI tools detected without credential blocking',
      description: `${tools.map(t => t.tool).join(', ')} detected but .env and secret files ` +
        `are not blocked from AI visibility. Add protection before credentials are added.`,
      severity: 'medium',
      autoFixable: true,
    });
  }

  return findings;
}

// --- Plugin Implementation ---

export const metadata: PluginMetadata = {
  packageName: 'secretless-ai',
  displayName: 'AI Visibility Protection',
  description: 'Block credentials from AI tool context and encrypt MCP server keys',
  version: VERSION,
  findings: ['SLAI-001', 'SLAI-002', 'SLAI-003'],
  scoreImprovement: 20,
};

export class SecretlessPlugin implements OpenA2APlugin {
  readonly metadata = metadata;
  private aimCore?: AIMCore;
  private api: SecretlessAPI | null = null;

  async init(options?: PluginInitOptions): Promise<void> {
    this.aimCore = options?.aimCore;
    this.api = await loadSecretless();
  }

  async scan(agentDir: string): Promise<Finding[]> {
    if (!this.api) {
      // secretless-ai not installed -- surface this as an informational finding
      return [{
        id: 'SLAI-000',
        title: 'Secretless AI not installed',
        description: 'Install secretless-ai to automatically block credentials from AI tool ' +
          'visibility and encrypt MCP server keys. Run: npm install -g secretless-ai',
        severity: 'medium',
        autoFixable: false,
      }];
    }

    const findings = checkAIToolProtection(agentDir, this.api);

    if (this.aimCore) {
      this.aimCore.logEvent({
        plugin: 'secretless',
        action: 'scan.complete',
        target: agentDir,
        result: findings.length > 0 ? 'denied' : 'allowed',
        metadata: { findingsCount: findings.length },
      });
    }

    return findings;
  }

  async fix(agentDir: string, options?: FixOptions): Promise<Remediation[]> {
    if (!this.api) return [];

    const remediations: Remediation[] = [];
    const findings = await this.scan(agentDir);

    if (options?.dryRun) {
      return findings
        .filter((f) => f.autoFixable)
        .map((f) => ({
          findingId: f.id,
          description: `Would fix: ${f.title}`,
          filesModified: f.filePath ? [f.filePath] : [],
          rollbackAvailable: false,
        }));
    }

    const hasExposure = findings.some(f =>
      f.id === 'SLAI-001' || f.id === 'SLAI-003'
    );

    if (hasExposure) {
      try {
        const initResult = this.api.init(agentDir);

        if (initResult.toolsConfigured.length > 0 || initResult.filesCreated.length > 0) {
          const allFiles = [...initResult.filesCreated, ...initResult.filesModified];
          remediations.push({
            findingId: 'SLAI-001',
            description: `Blocked credential visibility for ${initResult.toolsConfigured.length} ` +
              `AI tool(s): ${initResult.toolsConfigured.join(', ')}`,
            filesModified: allFiles,
            rollbackAvailable: false,
          });
        }
      } catch (err) {
        if (this.aimCore) {
          this.aimCore.logEvent({
            plugin: 'secretless',
            action: 'fix.error',
            target: agentDir,
            result: 'error',
            metadata: { error: err instanceof Error ? err.message : String(err) },
          });
        }
      }
    }

    if (this.aimCore && remediations.length > 0) {
      for (const r of remediations) {
        this.aimCore.logEvent({
          plugin: 'secretless',
          action: 'fix.applied',
          target: r.findingId,
          result: 'allowed',
          metadata: { filesModified: r.filesModified },
        });
      }
    }

    return remediations;
  }

  async status(): Promise<PluginStatus> {
    return {
      name: metadata.displayName,
      version: metadata.version,
      active: this.api !== null,
      findingsCount: 0,
    };
  }

  async uninstall(): Promise<void> {
    // Secretless protection files are managed by secretless-ai itself
  }
}

export function createPlugin(): SecretlessPlugin {
  return new SecretlessPlugin();
}
