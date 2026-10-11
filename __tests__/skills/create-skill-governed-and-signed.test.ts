/**
 * Regression (#989): `create-skill` describes its output as a secured skill
 * package with SOUL governance, so the tool's own analyzers have to agree
 * about a skill it has just written.
 *
 * Measured before the change, on "Summarise a Markdown file the user names":
 * `scan-soul` Governance 26/100; `harden-soul --dry-run` 9 sections and 61
 * controls to add; `secure` 76/100 with SKILL-001 (unsigned), AST-GOV-001 (two
 * governance domains with no constraint) and AST-PROMPT-004 (SKILL.md with no
 * trust hierarchy of its own). A skill that calls an external API also carried
 * AST-GOV-002 on a sentence the generator wrote.
 *
 * Pinned here:
 *   1. `scan-soul` scores the generated SOUL.md 100 with no tier or profile
 *      mismatch, for every shape of skill the generator branches on.
 *   2. `harden-soul` has nothing to add to it.
 *   3. No sentence the generator writes is rated a weak constraint, and the
 *      semantic pass reports no governance or trust-hierarchy finding.
 *   4. A signed write leaves SKILL.md verifying under an identity kept
 *      outside the output directory; an unsigned write creates none.
 *
 * Not pinned, because a generator cannot attest them: SUPPLY-001 (verified
 * publisher), SUPPLY-002 (registry attestation), SUPPLY-004 (installed hash)
 * and GIT-001 are still reported on a fresh skill.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { generateSkill, writeSkill, type SkillSpec } from '../../src/skills/builder';
import { HardeningScanner } from '../../src/hardening/scanner';
import { SoulScanner } from '../../src/soul/scanner';
import { DOMAIN_TEMPLATES } from '../../src/soul/templates';
import { extractDeclaredConstraints } from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { verifySigncryptSignature } from '../../src/plugins/signcrypt-block';
import { resolveProjectStore } from '../../src/store/project-store';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const PURPOSE = 'Summarise a Markdown file the user names';

/** One entry per branch the SOUL.md generator takes. */
const SHAPES: Array<{ label: string; spec: SkillSpec }> = [
  { label: 'read and process only', spec: { purpose: PURPOSE } },
  { label: 'external API, delete, messaging and customer data', spec: { purpose: 'Send customer emails through an API and delete old tickets' } },
  { label: 'write with external access declared', spec: { purpose: 'Save a weekly report', externalAccess: true } },
  { label: 'a name made of tier vocabulary', spec: { purpose: 'Orchestrate sub-agents with tools in a loop' } },
  { label: 'no capability to infer', spec: { purpose: 'greet' } },
];

function skillDirIn(parent: string): string {
  return path.join(parent, 'skill');
}

describe('create-skill output is governed (#989)', () => {
  it.each(SHAPES)('scan-soul scores SOUL.md 100 and harden-soul adds nothing: $label', async ({ spec }) => {
    const dir = skillDirIn(tempDir('hma-989-soul-'));
    writeSkill({ ...spec, outputDir: dir });
    const soul = new SoulScanner();

    const scanned = await soul.scanSoul(dir);
    expect(scanned.score).toBe(100);
    expect(scanned.tierMismatch).toBeUndefined();
    expect(scanned.profileMismatch).toBeUndefined();

    const hardened = await soul.hardenSoul(dir, { dryRun: true });
    expect(hardened.sectionsAdded).toEqual([]);
    expect(hardened.controlsAdded).toBe(0);
    expect(hardened.content).toBe('');
  });

  it.each(SHAPES)('no generated sentence is a weak constraint: $label', ({ spec }) => {
    const generated = generateSkill(spec);
    for (const [file, content] of [['SOUL.md', generated.soulMd], ['SKILL.md', generated.skillMd]] as const) {
      const weak = extractDeclaredConstraints(content).filter(c => c.enforceability < 0.6);
      expect(weak.map(c => `${file}: ${c.text}`)).toEqual([]);
    }
  });

  it.each(SHAPES)('the semantic pass reports no governance or trust-hierarchy finding: $label', async ({ spec }) => {
    const dir = skillDirIn(tempDir('hma-989-ast-'));
    writeSkill({ ...spec, outputDir: dir });
    const { astFindings } = await runNanoMindScan(dir, []);
    const reported = astFindings
      .filter(f => !f.passed && ['AST-GOV-001', 'AST-GOV-002', 'AST-PROMPT-004'].includes(f.checkId))
      .map(f => `${f.checkId}@${f.file}: ${f.message}`);
    expect(reported).toEqual([]);
  });

  it('SOUL.md carries every line of the harden-soul templates unchanged', () => {
    // scan-soul leaves harden-soul's own lines out when it infers a tier from
    // a file's words; a template line reworded on the way into SOUL.md would
    // count as the skill's words and could raise a tier mismatch.
    const lines = new Set(generateSkill({ purpose: PURPOSE }).soulMd.split('\n').map(l => l.trim()));
    const missing = Object.values(DOMAIN_TEMPLATES)
      .flatMap(t => t.content.split('\n'))
      .map(l => l.trim())
      .filter(l => l.length > 0 && !lines.has(l));
    expect(missing).toEqual([]);
  });

  it('the pinned tier is the one scan-soul infers when the output directory already declares more', async () => {
    const dir = skillDirIn(tempDir('hma-989-tier-'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"p","dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}\n');
    writeSkill({ purpose: PURPOSE, outputDir: dir });

    const scanned = await new SoulScanner().scanSoul(dir);
    expect(scanned.agentTier).toBe('TOOL-USING');
    expect(scanned.tierMismatch).toBeUndefined();
    expect(scanned.score).toBe(100);
  });
});

describe('create-skill signs SKILL.md with an identity outside the output directory (#989)', () => {
  let store: string;
  let previousStore: string | undefined;

  beforeEach(() => {
    previousStore = process.env.OPENA2A_HOME;
    store = tempDir('hma-989-store-');
    process.env.OPENA2A_HOME = store;
  });

  afterEach(() => {
    if (previousStore === undefined) delete process.env.OPENA2A_HOME;
    else process.env.OPENA2A_HOME = previousStore;
  });

  function isInside(parent: string, child: string): boolean {
    const rel = path.relative(fs.realpathSync(parent), child);
    return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
  }

  it('a signed write verifies, and secure no longer reports SKILL-001', async () => {
    const dir = skillDirIn(tempDir('hma-989-sign-'));
    const result = writeSkill({ purpose: PURPOSE, outputDir: dir, sign: true });

    expect(result.unsignedReason).toBeUndefined();
    const onDisk = fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf-8');
    const verdict = verifySigncryptSignature(onDisk);
    expect(verdict.signed).toBe(true);
    expect(verdict.signed && verdict.signer).toBe(result.signature?.signer);
    expect(result.skillMd).toBe(onDisk);

    const identityPath = result.signature!.identityPath;
    expect(result.signature!.identityCreated).toBe(true);
    expect(fs.existsSync(identityPath)).toBe(true);
    expect(isInside(store, identityPath)).toBe(true);
    expect(isInside(dir, identityPath)).toBe(false);
    // Nothing but the three generated files lands in the output directory.
    expect(fs.readdirSync(dir).sort()).toEqual(['SKILL.md', 'SOUL.md', 'manifest.json']);

    const scan = await new HardeningScanner().scan({ targetDir: dir });
    expect(scan.findings.filter(f => f.checkId === 'SKILL-001' && !f.passed)).toEqual([]);
  });

  it('a second signed write to the same directory reuses the identity', () => {
    const dir = skillDirIn(tempDir('hma-989-resign-'));
    const first = writeSkill({ purpose: PURPOSE, outputDir: dir, sign: true });
    const second = writeSkill({ purpose: PURPOSE, outputDir: dir, sign: true });

    expect(second.signature?.identityCreated).toBe(false);
    expect(second.signature?.signer).toBe(first.signature?.signer);
    expect(verifySigncryptSignature(fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf-8')).signed).toBe(true);
  });

  it('an unsigned write creates no identity and leaves SKILL.md without a block', () => {
    const dir = skillDirIn(tempDir('hma-989-unsigned-'));
    const result = writeSkill({ purpose: PURPOSE, outputDir: dir });

    expect(result.signature).toBeUndefined();
    expect(result.unsignedReason).toBeUndefined();
    expect(fs.readdirSync(store)).toEqual([]);
    expect(verifySigncryptSignature(fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf-8')))
      .toEqual({ signed: false, reason: 'no-block' });
  });

  it('an identity file that cannot be used is left as it is, and SKILL.md stays unsigned', () => {
    const dir = skillDirIn(tempDir('hma-989-badid-'));
    fs.mkdirSync(dir, { recursive: true });
    const identityPath = resolveProjectStore(dir).identityPath;
    fs.mkdirSync(path.dirname(identityPath), { recursive: true });
    fs.writeFileSync(identityPath, '{"publicKey":');

    const result = writeSkill({ purpose: PURPOSE, outputDir: dir, sign: true });

    expect(result.signature).toBeUndefined();
    expect(result.unsignedReason).toContain('cannot be used');
    expect(fs.readFileSync(identityPath, 'utf-8')).toBe('{"publicKey":');
    expect(verifySigncryptSignature(fs.readFileSync(path.join(dir, 'SKILL.md'), 'utf-8')))
      .toEqual({ signed: false, reason: 'no-block' });
  });

  it('a store that would sit inside the output directory is refused, and SKILL.md stays unsigned', () => {
    const dir = skillDirIn(tempDir('hma-989-inside-'));
    process.env.OPENA2A_HOME = path.join(dir, 'store');

    const result = writeSkill({ purpose: PURPOSE, outputDir: dir, sign: true });

    expect(result.signature).toBeUndefined();
    expect(result.unsignedReason).toContain('would sit inside the target');
    expect(fs.readdirSync(dir).sort()).toEqual(['SKILL.md', 'SOUL.md', 'manifest.json']);
  });
});

describe('create-skill command (#989)', () => {
  let root: string;

  beforeAll(() => {
    assertDistFresh();
    root = tempDir('hma-989-cli-');
  });

  // HOME and OPENA2A_HOME are isolated: without that a run writes a real
  // identity into the developer's own store.
  function run(name: string, extra: string[]) {
    const home = path.join(root, `${name}-home`);
    const opena2aHome = path.join(root, `${name}-store`);
    const out = path.join(root, `${name}-skill`);
    fs.mkdirSync(home, { recursive: true });
    const r = spawnSync(process.execPath, [BUILT_CLI, 'create-skill', PURPOSE, '-o', out, ...extra], {
      encoding: 'utf8',
      timeout: 120_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, OPENA2A_HOME: opena2aHome },
    });
    return { status: r.status, stdout: String(r.stdout ?? ''), out, opena2aHome };
  }

  it('signs by default and names the identity file it used', () => {
    const r = run('default', []);
    expect(r.status).toBe(0);
    expect(verifySigncryptSignature(fs.readFileSync(path.join(r.out, 'SKILL.md'), 'utf-8')).signed).toBe(true);

    const identityPath = resolveProjectStoreUnder(r.opena2aHome, r.out);
    expect(fs.existsSync(identityPath)).toBe(true);
    expect(r.stdout).toContain('Signed SKILL.md with a new signing identity for this directory:');
    expect(r.stdout).toContain(identityPath);
    expect(r.stdout).toContain(`fix-all ${r.out} --with-aim`);
  });

  it('--no-sign writes the skill unsigned, creates no identity, and says how to sign it', () => {
    const r = run('nosign', ['--no-sign']);
    expect(r.status).toBe(0);
    expect(verifySigncryptSignature(fs.readFileSync(path.join(r.out, 'SKILL.md'), 'utf-8')))
      .toEqual({ signed: false, reason: 'no-block' });
    expect(fs.existsSync(r.opena2aHome)).toBe(false);
    expect(r.stdout).toContain('SKILL.md is not signed (--no-sign).');
    expect(r.stdout).toMatch(/^Sign it with: /m);
    expect(r.stdout).toContain(`fix-all ${r.out} --with-aim`);
  });
});

/** The identity path `create-skill` reports for `target` when the store root is `storeRoot`. */
function resolveProjectStoreUnder(storeRoot: string, target: string): string {
  const previous = process.env.OPENA2A_HOME;
  process.env.OPENA2A_HOME = storeRoot;
  try {
    return resolveProjectStore(target).identityPath;
  } finally {
    if (previous === undefined) delete process.env.OPENA2A_HOME;
    else process.env.OPENA2A_HOME = previous;
  }
}
