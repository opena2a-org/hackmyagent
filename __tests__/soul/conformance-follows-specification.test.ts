/**
 * scan-soul's conformance level is the level agent-governance-spec defines
 * (opena2a-standards/agent-governance-spec#41).
 *
 * The specification (specification.md, conformance.md) makes each level a set
 * of applicable controls that must all pass, plus a score floor:
 *   Essential  every applicable CRITICAL control passes
 *   Standard   Essential, every applicable HIGH control passes, score >= 60
 *   Hardened   every applicable control passes, score >= 75
 * The scanner set Standard and Hardened from the score alone, so a file
 * scoring 99 with one HIGH control failing read hardened.
 *
 * `__tests__/fixtures/agent-governance-spec/` holds byte copies of the
 * specification's `controls.json` and its four templates at commit
 * 0f4b55dc10a9c9a58bf1d03585935402672bc2cc; `SPEC_BLOBS` pins each to its git
 * blob id there. To follow a newer specification, copy the files again and
 * update the pins: the severity test then fails until CONTROL_DEFS carries the
 * new severities.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CONTROL_DEFS, SoulScanner } from '../../src/soul/scanner';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

const SPEC_DIR = resolve(__dirname, '../fixtures/agent-governance-spec');
const CLI_PATH = resolve(__dirname, '../../dist/cli.js');

/** `git rev-parse 0f4b55dc:<path>` in opena2a-standards/agent-governance-spec. */
const SPEC_BLOBS: Record<string, string> = {
  'controls.json': 'bcdb173f613775d059370a5271ec8e670419f48f',
  'templates/basic.md': '3f2a05a44a85f1a7e55446190c1113f1977cda53',
  'templates/tool-using.md': '8cb6660e547564386ed796a7ff817287f9bd0346',
  'templates/agentic.md': 'f90a61b213dad4ba0e7277d67be7cc7a3a8617f0',
  'templates/multi-agent.md': '645b9db8bd687b8a978484b8adad313d3bc19855',
};

function gitBlobId(bytes: Buffer): string {
  return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

interface SpecControl { id: string; severity: string }

function specControls(): SpecControl[] {
  const doc = JSON.parse(readFileSync(join(SPEC_DIR, 'controls.json'), 'utf-8')) as { controls: SpecControl[] };
  return doc.controls;
}

describe('the specification files under test are the copies pinned at 0f4b55dc', () => {
  it.each(Object.entries(SPEC_BLOBS))('%s', (rel, blob) => {
    expect(gitBlobId(readFileSync(join(SPEC_DIR, rel)))).toBe(blob);
  });
});

describe('each control carries the severity controls.json gives it', () => {
  it('controls.json lists 72 controls: 2 CRITICAL, 12 HIGH, 39 MEDIUM, 19 LOW', () => {
    const counts: Record<string, number> = {};
    for (const c of specControls()) counts[c.severity] = (counts[c.severity] ?? 0) + 1;
    expect(specControls()).toHaveLength(72);
    expect(counts).toEqual({ CRITICAL: 2, HIGH: 12, MEDIUM: 39, LOW: 19 });
  });

  it('CONTROL_DEFS has the same 72 ids, each with the specification severity', () => {
    const spec = new Map(specControls().map((c) => [c.id, c.severity]));
    expect(CONTROL_DEFS.map((d) => d.id).sort()).toEqual([...spec.keys()].sort());
    for (const d of CONTROL_DEFS) {
      expect(d.severity, d.id).toBe(spec.get(d.id));
    }
  });

  it('critical is set exactly on the CRITICAL controls', () => {
    const flagged = CONTROL_DEFS.filter((d) => d.critical === true).map((d) => d.id).sort();
    const critical = CONTROL_DEFS.filter((d) => d.severity === 'CRITICAL').map((d) => d.id).sort();
    expect(flagged).toEqual(critical);
    expect(critical).toEqual(['SOUL-HB-001', 'SOUL-IH-003']);
  });
});

/**
 * One bullet per control applicable at the AGENTIC tier, each holding that
 * control's keywords. SOUL-IH-001 and SOUL-HB-002 count a keyword only in a
 * sentence that also refuses something, so their bullets carry the refusal;
 * the others carry none, which keeps SOUL-HB-002's "unauthorized" in
 * SOUL-HB-006's bullet from passing it once its own bullet is removed.
 */
const AGENTIC_DEFS = CONTROL_DEFS.filter((d) => d.tiers.includes('AGENTIC'));
const REFUSAL_FRAMED = new Set(['SOUL-IH-001', 'SOUL-HB-002']);

function constructedSoul(removed?: string): string {
  const bullets = AGENTIC_DEFS
    .filter((d) => d.id !== removed)
    .map((d) => `- ${REFUSAL_FRAMED.has(d.id) ? 'Never permitted' : 'Required'}: ${d.keywords.join(', ')}.`);
  return ['# Agent', '', '## Controls', '', ...bullets, ''].join('\n');
}

function dirWithSoul(content: string): string {
  const dir = tempDir('scan-soul-conformance-spec-');
  writeFileSync(join(dir, 'SOUL.md'), content, 'utf-8');
  return dir;
}

async function scanConstructed(removed?: string) {
  const result = await new SoulScanner().scanSoul(dirWithSoul(constructedSoul(removed)), { profile: 'autonomous' });
  const failing = result.domains.flatMap((d) => d.controls).filter((c) => !c.passed).map((c) => c.id);
  return { result, failing };
}

const ONE_HIGH_FAILING = ['SOUL-HB-002', 'SOUL-HB-005', 'SOUL-HB-008', 'SOUL-HO-008', 'SOUL-HV-001'];
const ONE_MEDIUM_OR_LOW_FAILING = ['SOUL-TH-006', 'SOUL-TH-007', 'SOUL-TH-008'];

describe('conformance over a constructed governance file (autonomous profile, AGENTIC tier)', () => {
  it('every applicable control passing reads hardened at 100', async () => {
    const { result, failing } = await scanConstructed();
    expect(result.agentTier).toBe('AGENTIC');
    expect(result.totalControls).toBe(AGENTIC_DEFS.length);
    expect(failing).toEqual([]);
    expect(result.score).toBe(100);
    expect(result.conformance).toBe('hardened');
  });

  it.each(ONE_HIGH_FAILING)('one HIGH control failing (%s) reads essential, not hardened', async (id) => {
    const { result, failing } = await scanConstructed(id);
    expect(CONTROL_DEFS.find((d) => d.id === id)?.severity).toBe('HIGH');
    expect(failing).toEqual([id]);
    // The score and the maturity level still say hardened; only the
    // conformance level reads the failing HIGH control.
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.level).toBe('hardened');
    expect(result.criticalMissing).toEqual([]);
    expect(result.conformance).toBe('essential');
  });

  it.each(ONE_MEDIUM_OR_LOW_FAILING)('one MEDIUM or LOW control failing (%s) reads standard, not hardened', async (id) => {
    const { result, failing } = await scanConstructed(id);
    expect(['MEDIUM', 'LOW']).toContain(CONTROL_DEFS.find((d) => d.id === id)?.severity);
    expect(failing).toEqual([id]);
    expect(result.score).toBeGreaterThanOrEqual(75);
    expect(result.level).toBe('hardened');
    expect(result.conformance).toBe('standard');
  });
});

describe('the four specification templates read essential', () => {
  it.each(['basic', 'tool-using', 'agentic', 'multi-agent'])('templates/%s.md', async (name) => {
    const result = await new SoulScanner().scanSoul(join(SPEC_DIR, 'templates', `${name}.md`));
    expect(result.conformance).toBe('essential');
  });
});

describe('scan-soul --json carries the level and keeps its exit code', () => {
  beforeAll(assertDistFresh);

  function runJson(dir: string): { conformance: unknown; level: unknown; status: number } {
    let stdout = '';
    let status = 0;
    try {
      stdout = execFileSync(process.execPath, [CLI_PATH, 'scan-soul', dir, '--json', '--profile', 'autonomous'], {
        stdio: ['ignore', 'pipe', 'pipe'],
        encoding: 'utf8',
        timeout: 20000,
        env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1' },
      });
    } catch (err) {
      const e = err as { status?: number; stdout?: string };
      stdout = e.stdout ?? '';
      status = e.status ?? 1;
    }
    const body = JSON.parse(stdout.slice(stdout.indexOf('{'))) as Record<string, unknown>;
    return { conformance: body.conformance, level: body.level, status };
  }

  it('a failing HIGH control: essential, exit 0', () => {
    expect(runJson(dirWithSoul(constructedSoul('SOUL-HB-002')))).toEqual({ conformance: 'essential', level: 'hardened', status: 0 });
  });

  it('a failing MEDIUM control: standard, exit 0', () => {
    expect(runJson(dirWithSoul(constructedSoul('SOUL-TH-007')))).toEqual({ conformance: 'standard', level: 'hardened', status: 0 });
  });
});
