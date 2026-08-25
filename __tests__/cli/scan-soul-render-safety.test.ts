/**
 * #595 — scan-soul printed a violation's evidence and fix unescaped.
 *
 * `v.evidence` is the matched line of the scanned SOUL.md, so an ESC sequence
 * inside that line reached the terminal raw: a governance file could clear the
 * screen or recolour the report describing it. The finding renderers and the
 * `Verify:` citations close this class (#324, #334); this site was blind to the
 * render-source gate because neither value is path-named.
 *
 * A carriage return is a sentence boundary in the extractor (it splits on
 * `[\r\u2028\u2029]+`) and a newline cannot sit inside a single-line span, so
 * neither can reach the evidence; any other control or format byte can, and
 * all are now escaped. The fixture carries a CSI and the assertion is on the
 * byte.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

/** The identity block of the permissive-overrides corpus fixture: owner "anyone-who-asks" is a violation with evidence. */
const SOUL = [
  '# SOUL — permissive',
  '',
  '## Identity',
  '',
  '- **Agent name:** super-helper',
  '- **Owner:** anyone-who-asks\x1b[2JFORGED-AFTER-CSI',
  '- **Public key fingerprint:** (omitted — identity is established by',
  '  trusting the caller\'s claim)',
  '',
  '## Surfaces',
  '',
  'The agent has full filesystem access, full network egress and full',
  'subprocess execution.',
  '',
].join('\n');

let root: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-595-'));
  fs.writeFileSync(path.join(root, 'SOUL.md'), SOUL);
});

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

function run(args: string[]): string {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    timeout: 240_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-')) },
  });
  return `${r.stdout ?? ''}${r.stderr ?? ''}`;
}

describe('#595 scan-soul renders evidence and fix through the display escape', () => {
  it('an invalid profile marker carrying a CSI renders escaped on every line that names it, and --json keeps the byte', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-595m-'));
    fs.writeFileSync(path.join(dir, 'SOUL.md'), `<!-- soul:profile=weird\x1b[2JFORGED-MARKER -->\n${SOUL}`);
    const out = run(['scan-soul', dir]);
    // Non-vacuity: the marker value has to be on screen (the extractor
    // lowercases it, which also turns the CSI's `J` into `j`).
    expect(out).toContain('forged-marker');
    // The line that names the attempted value (the verdict line names it only
    // when the SOUL carries no other violation).
    expect(out).toContain('Attempted marker value');
    expect(out).not.toContain('\x1b');
    expect(out).toContain('[2j');
    const json = run(['scan-soul', dir, '--json']);
    const body = JSON.parse(json.slice(json.indexOf('{')));
    // The data channel carries the value, not the rendering.
    expect(JSON.stringify(body)).toContain('\\u001b[2j');
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a CSI inside a matched line is printed as visible text, never as the byte', () => {
    const out = run(['scan-soul', root]);
    // Non-vacuity: the matched line must be on screen as evidence, or nothing is measured.
    expect(out).toMatch(/Evidence \(SOUL\.md:6\)/);
    expect(out).toContain('anyone-who-asks');
    expect(out).toContain('FORGED-AFTER-CSI');
    expect(out).not.toContain('\x1b');
    expect(out).toContain('[2J');
  });
});
