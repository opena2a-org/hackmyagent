/**
 * The plugin guide's built-in factories are exported, and the AIM capability
 * policy it describes is checked before each plugin's fix step (#992).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { AIMCore } from '@opena2a/aim-core';
import { tempDir } from '../helpers/temp-dir';
import * as hma from '../../src/index';
import { fixAllowedByPolicy } from '../../src/plugins/core';
import { CredVaultPlugin } from '../../src/plugins/credvault';
import { SecretlessPlugin } from '../../src/plugins/secretless';
import { SignCryptPlugin } from '../../src/plugins/signcrypt';
import { SkillGuardPlugin } from '../../src/plugins/skillguard';

/** A credential shape assembled at runtime, never spelled as source bytes. */
const ANTHROPIC_KEY = ['sk', '-ant-api03-abcdefghijklmnopqrstuvwxyz'].join('');

describe('plugin guide factories (#992)', () => {
  it('exports every factory the Built-in Plugins example imports', () => {
    for (const name of [
      'createCredVaultPlugin',
      'createSecretlessPlugin',
      'createSigncryptPlugin',
      'createSkillguardPlugin',
      'fixAllowedByPolicy',
    ] as const) {
      expect(typeof hma[name], name).toBe('function');
    }
    expect(hma.createSecretlessPlugin().metadata.displayName).toBe('AI Visibility Protection');
  });

  it('states the same built-in plugin count as the table it introduces', () => {
    const doc = fs.readFileSync(path.resolve(__dirname, '../../docs/PLUGIN_API.md'), 'utf-8');
    const section = doc.split('## Built-in Plugins')[1].split('\n## ')[0];
    const stated = /ships with (\d+) built-in plugins/.exec(section);
    const rows = section.split('\n').filter((l) => /^\| .* \| `create\w+Plugin\(\)` \|/.test(l));
    expect(stated).not.toBeNull();
    expect(Number(stated![1])).toBe(rows.length);
  });
});

describe('AIM capability policy before each fix step (#992)', () => {
  let agentDir: string;
  let dataDir: string;
  let aim: AIMCore;

  const writePolicy = (yaml: string) =>
    fs.writeFileSync(path.join(dataDir, 'policy.yaml'), yaml, 'utf-8');
  const denyFor = (plugin: string) =>
    writePolicy(
      'version: "1"\ndefaultAction: allow\nrules:\n' +
        `  - capability: file:write\n    action: deny\n    plugins: [${plugin}]\n`,
    );
  const denials = () => aim.readAuditLog().filter((e) => e.action === 'fix.denied');

  beforeEach(() => {
    agentDir = tempDir('hma-policy-agent-');
    dataDir = tempDir('hma-policy-aim-');
    aim = new AIMCore({ agentName: 'policy-test', dataDir });
  });

  it('restricts nothing without aim-core or without a policy file', () => {
    expect(fixAllowedByPolicy(undefined, 'credvault', agentDir)).toBe(true);
    // aim-core's built-in default denies everything; with no policy.yaml
    // written, that default must not stop a fix.
    expect(fixAllowedByPolicy(aim, 'credvault', agentDir)).toBe(true);
    expect(denials()).toEqual([]);
  });

  it('credvault still fixes under aim-core when no policy is written', async () => {
    const config = path.join(agentDir, 'config.json');
    fs.writeFileSync(config, JSON.stringify({ apiKey: ANTHROPIC_KEY }), 'utf-8');
    const plugin = new CredVaultPlugin();
    await plugin.init({ aimCore: aim });

    const remediations = await plugin.fix(agentDir);
    expect(remediations.map((r) => r.findingId)).toContain('CRED-001');
    expect(fs.readFileSync(config, 'utf-8')).not.toContain(ANTHROPIC_KEY);
  });

  it('a policy denying file:write to credvault stops its fix and records the denial', async () => {
    denyFor('credvault');
    const config = path.join(agentDir, 'config.json');
    const original = JSON.stringify({ apiKey: ANTHROPIC_KEY });
    fs.writeFileSync(config, original, 'utf-8');
    const plugin = new CredVaultPlugin();
    await plugin.init({ aimCore: aim });

    expect((await plugin.scan(agentDir)).map((f) => f.id)).toContain('CRED-001');
    expect(await plugin.fix(agentDir, { dryRun: true })).toEqual([]);
    expect(await plugin.fix(agentDir)).toEqual([]);
    expect(fs.readFileSync(config, 'utf-8')).toBe(original);
    expect(fs.existsSync(path.join(agentDir, '.env.example'))).toBe(false);
    expect(denials().map((e) => [e.plugin, e.result, e.metadata?.capability])).toContainEqual([
      'credvault',
      'denied',
      'file:write',
    ]);
  });

  it('a rule scoped to one plugin leaves the others fixing', async () => {
    denyFor('credvault');
    fs.writeFileSync(path.join(agentDir, 'SKILL.md'), '# My Skill\nSafe\n', 'utf-8');
    const plugin = new SkillGuardPlugin();
    await plugin.init({ aimCore: aim });

    const remediations = await plugin.fix(agentDir);
    expect(remediations.map((r) => r.findingId)).toEqual(['SKILL-UNPIN']);
    expect(fs.existsSync(path.join(agentDir, '.opena2a', 'skillguard', 'pins.json'))).toBe(true);
    expect(denials()).toEqual([]);
  });

  it('a policy denying signcrypt leaves skill files unsigned and unrecorded', async () => {
    denyFor('signcrypt');
    const skill = path.join(agentDir, 'SKILL.md');
    fs.writeFileSync(skill, '# My Skill\nDoes stuff\n', 'utf-8');
    const plugin = new SignCryptPlugin();
    await plugin.init({ aimCore: aim });

    expect(await plugin.fix(agentDir)).toEqual([]);
    expect(fs.readFileSync(skill, 'utf-8')).toBe('# My Skill\nDoes stuff\n');
    expect(fs.existsSync(path.join(agentDir, '.opena2a', 'signcrypt'))).toBe(false);
    expect(denials().map((e) => e.plugin)).toEqual(['signcrypt']);
  });

  it('a default-deny policy with an allow rule fixes only the allowed plugin', async () => {
    writePolicy(
      'version: "1"\ndefaultAction: deny\nrules:\n' +
        '  - capability: file:write\n    action: allow\n    plugins: [skillguard]\n',
    );
    fs.writeFileSync(path.join(agentDir, 'SKILL.md'), '# My Skill\nSafe\n', 'utf-8');
    const guard = new SkillGuardPlugin();
    await guard.init({ aimCore: aim });
    const sign = new SignCryptPlugin();
    await sign.init({ aimCore: aim });

    expect(await sign.fix(agentDir)).toEqual([]);
    expect((await guard.fix(agentDir)).map((r) => r.findingId)).toEqual(['SKILL-UNPIN']);
  });

  it('a policy denying secretless never reaches its init step', async () => {
    let initCalls = 0;
    const stubApi = {
      detectAITools: () => [{ tool: 'claude', configDir: '.claude', settingsFile: 'settings.json', hooksSupported: true }],
      verify: () => ({ envVars: {}, exposedInContext: [], exposedInTranscripts: [], passed: false }),
      scan: () => [],
      init: () => {
        initCalls++;
        return { toolsDetected: ['claude'], toolsConfigured: ['claude'], filesCreated: ['x'], filesModified: [], secretsFound: 0 };
      },
    };
    const plugin = new SecretlessPlugin();
    await plugin.init({ aimCore: aim });
    (plugin as unknown as { api: typeof stubApi }).api = stubApi;

    denyFor('secretless');
    expect((await plugin.scan(agentDir)).map((f) => f.id)).toEqual(['SLAI-003']);
    expect(await plugin.fix(agentDir)).toEqual([]);
    expect(initCalls).toBe(0);

    fs.rmSync(path.join(dataDir, 'policy.yaml'));
    expect((await plugin.fix(agentDir)).map((r) => r.findingId)).toEqual(['SLAI-001']);
    expect(initCalls).toBe(1);
  });
});
