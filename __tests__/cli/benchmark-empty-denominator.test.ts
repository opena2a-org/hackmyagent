/**
 * #458 step 0 (the sentence in #513's title) — a benchmark level whose scored
 * denominator is 0 is `null`, renders "not assessed", and never feeds the
 * rating ladder.
 *
 * Before: `generateBenchmarkReport` set `l1/l2/l3Compliance` to 100 when no
 * scored control at that level produced a result, and `compliance` to 0 in
 * the same case, five lines apart. The two L3 controls (3.5, 8.4) have no
 * automated check, so every `L3=100%` ever printed was that default; an empty
 * directory at `-l L3 --scan-depth quick` read `Certified` with two of
 * forty-six controls measured; a category with no automatable control printed
 * `Rating: Certified` beside `Compliance: 0% (0/0 verified controls)` at exit
 * 0 — or exit 1 under `--fail-below 80`, because `0 < 80`.
 *
 * Ruling: CPO 2026-08-25 (COUNCIL_LEDGER, "#458 step 0"), on the CISO's
 * 2026-08-11 direction: zero denominator => `null`, "not assessed at this
 * level", never feeds the ladder, never `Not Passing`. A rung of the ladder
 * that reads a null level is skipped, not failed; when every rung reads a
 * null the rating is `Not Assessed` and the exit code is the unmeasured
 * floor (2), never 1 (1 = measured and failed).
 *
 * Cells tagged RED-ON-BASE fail on the 6d6685e build; the others pin
 * behaviour that must not move (a measured level still fails as before).
 *
 * Out of scope here, on purpose: the empty-dir-at-quick `-l L1` cell
 * (`Certified 100% (2/2)`) closes when absent-subject checks leave the
 * denominator (#458 steps 1-2, scanner-side); the MCP server's assessor
 * (0.33.0 hold condition); #513's rating redesign (deferred).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { assertDistFreshIfPresent, BUILT_CLI as CLI } from '../helpers/dist-freshness';

beforeAll(assertDistFreshIfPresent);

let root: string;
let empty: string;

let home: string;

function run(args: string[], env: Record<string, string> = {}) {
  const res = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf-8',
    timeout: 240_000,
    env: {
      ...process.env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      ...env,
    },
  });
  return {
    status: res.status,
    out: `${res.stdout ?? ''}${res.stderr ?? ''}`,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  };
}

function parseJson(stdout: string): any {
  return JSON.parse(stdout.slice(stdout.indexOf('{')));
}

const NO_CONTROL_CATEGORY = 'Identity & Provenance'; // no automatable control at any level
const L2_ONLY_CATEGORY = 'Agent-to-Agent Security'; // no L1 controls; 7.4 is automatable at L2

let mcpTree: string;

beforeAll(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-458-'));
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-home-'));
  empty = path.join(root, 'empty');
  fs.mkdirSync(empty);
  // An MCP-shaped tree: types as `mcp`, so 7.4 (Agent-to-Agent, L2) gets a
  // result while the category has no L1 control at all.
  mcpTree = path.join(root, 'mcp tree'); // the space is deliberate: cited commands must quote it
  fs.mkdirSync(path.join(mcpTree, 'src'), { recursive: true });
  fs.writeFileSync(path.join(mcpTree, 'package.json'), '{"name":"mcp458","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}\n');
  fs.writeFileSync(path.join(mcpTree, 'package-lock.json'), '{"name":"mcp458","lockfileVersion":3,"packages":{}}\n');
  fs.writeFileSync(path.join(mcpTree, '.gitignore'), 'node_modules\n');
  fs.writeFileSync(path.join(mcpTree, 'src', 'index.js'), 'const { Server } = require("@modelcontextprotocol/sdk/server");\n');
});

/** The first `Verify:` command on the line that starts with `prefix`, as printed. */
function citedCommand(out: string, prefix: string, label: 'Verify' | 'Fix'): string {
  const at = out.indexOf(prefix);
  expect(at).toBeGreaterThan(-1);
  const line = out.slice(at, out.indexOf('\n', at));
  const m = line.match(new RegExp(`${label}: (.*?)(?= Fix: |$)`));
  expect(m, `${label} on: ${line}`).not.toBeNull();
  return m![1];
}

function sh(command: string, cwd: string) {
  const res = spawnSync('/bin/sh', ['-c', command], {
    encoding: 'utf-8', cwd, timeout: 240_000,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, PATH: `${path.dirname(process.execPath)}:${process.env.PATH ?? ''}` },
  });
  return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
}

const hasJq = spawnSync('jq', ['--version']).status === 0;

afterAll(() => {
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
});

describe('#458 step 0: an unmeasured benchmark level is null and never feeds the ladder', () => {
  it('RED-ON-BASE json: -l L3 on an empty dir at quick depth carries null for L2/L3 and the ladder skips those rungs', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--format', 'json']);
    const body = parseJson(res.stdout);
    expect(body.l1Compliance).toBe(100);
    expect(body.l2Compliance).toBeNull();
    expect(body.l3Compliance).toBeNull();
    // The overall figure is over what WAS measured (2/2), not a default.
    expect(body.compliance).toBe(100);
    // Certified reads L3 and Compliant reads L2: both unavailable. Passing
    // reads L1 alone and holds. The text suffix never reaches json.
    expect(body.rating).toBe('Passing');
    expect(JSON.stringify(body)).not.toContain('not assessed)');
    expect(res.status).toBe(0);
  });

  it('RED-ON-BASE text: -l L3 prints Passing, one "Not assessed at" line per unmeasured level under Unverified:, and says so in the verbose line', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--verbose']);
    // The word never travels alone: the null scope rides in the same string.
    expect(res.out).toContain('Rating: Passing (L2, L3 not assessed)');
    expect(res.out).not.toContain('Rating: Certified');
    expect(res.out).toContain('Compliance by level: L1=100% L2=not assessed L3=not assessed');
    const unverifiedAt = res.out.indexOf('Unverified:');
    const l2At = res.out.indexOf('Not assessed at L2:');
    const l3At = res.out.indexOf('Not assessed at L3:');
    expect(unverifiedAt).toBeGreaterThan(-1);
    expect(l2At).toBeGreaterThan(unverifiedAt);
    expect(l3At).toBeGreaterThan(l2At);
    // The L3 catalogue has no automated control at all: the line says which
    // rating word that makes unawardable, and names the controls.
    const l3Line = res.out.slice(l3At, res.out.indexOf('\n', l3At));
    expect(l3Line).toContain('3.5');
    expect(l3Line).toContain('8.4');
    expect(l3Line).toContain('Certified is not awardable at L3');
    // The L2 line's Verify must not send the reader to `--verbose`, which
    // skips categories with 0 verified controls; `--json` lists every control.
    const l2Line = res.out.slice(l2At, res.out.indexOf('\n', l2At));
    expect(l2Line).toContain('Compliant and Certified are not awardable.');
    expect(l2Line).not.toContain('not awardable at L2');
    // The line names the automated L2 controls that produced nothing.
    // Catalogue pin, like the L3 IDs above: the three L2 controls with an automated check.
    expect(l2Line).toContain('0 of 3 automated L2 controls (2.5, 7.4, 9.4) produced a result');
    expect(l2Line).toMatch(/Verify: .*-l L2 --scan-depth quick --no-machine-posture --format json \| jq/);
    expect(l2Line).not.toContain('--json ');
    expect(res.status).toBe(0);
  });

  // skipIf, not a silent early return: a machine without jq shows the cell as skipped.
  it.skipIf(!hasJq)('RED-ON-BASE text: the printed Verify runs as printed and reproduces the population the line counts', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture']);
    const verify = citedCommand(res.out, 'Not assessed at L2:', 'Verify');
    // The cited command names the tool by its installed name; run it through the built CLI.
    const cmd = verify.replace(/^\S+ secure /, `${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} secure `);
    const ran = sh(cmd, root);
    expect(ran.status, ran.stderr).toBe(0);
    const controls = JSON.parse(ran.stdout);
    expect(Array.isArray(controls)).toBe(true);
    expect(controls.length).toBe(18); // every L2 control, as the line's population
    expect(controls.every((c: any) => c.level === 'L2')).toBe(true);
  });

  it('RED-ON-BASE text (T2): default depth -l L3 is Not Passing with the null scope in the same string, exit 1', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--no-machine-posture', '--verbose']);
    expect(res.out).toContain('Rating: Not Passing (L2, L3 not assessed)');
    expect(res.out).toContain('Compliance by level: L1=');
    expect(res.out).toContain('L2=not assessed L3=not assessed');
    expect(res.status).toBe(1);
  });

  it('RED-ON-BASE text: -l L2 prints the L2 line only — a level the run did not examine gets no line', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L2', '--scan-depth', 'quick', '--no-machine-posture', '--verbose']);
    expect(res.out).toContain('Rating: Passing (L2 not assessed)');
    expect(res.out).toContain('Not assessed at L2:');
    expect(res.out).not.toContain('Not assessed at L3:');
    expect(res.out).toContain('L2=not assessed');
    // The L2 footer used to cite `-l L3 for hardened requirements`, a command
    // that cannot change the rating while no L3 control has an automated
    // check. It now states the fact and cites no command.
    expect(res.out).toContain("L3 adds 2 controls (3.5, 8.4); none has an automated check in this version, so -l L3 cannot raise this rating.");
    expect(res.out).not.toContain("-l L3' for hardened requirements");
    // The verbose line covers the examined levels only; the Spec link prints once.
    expect(res.out).toContain('Compliance by level: L1=100% L2=not assessed\n');
    expect(res.out.split('https://oasb.ai/oasb-1').length - 1).toBe(1);
    expect(res.status).toBe(0);
  });

  it('RED-ON-BASE text: a run in which no control was measured is Not Assessed at exit 2, with a Verify and a Fix', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture']);
    // The word already says it: no `(L1 not assessed)` suffix on Not Assessed.
    expect(res.out).toContain('Rating: Not Assessed\n');
    expect(res.out).not.toContain('Rating: Certified');
    expect(res.out).toContain('Compliance: not measured (0/0 verified controls)');
    expect(res.stderr).toContain('Benchmark rating is Not Assessed: no scored control produced a result.');
    const l1At = res.out.indexOf('Not assessed at L1:');
    expect(l1At).toBeGreaterThan(-1);
    const l1Line = res.out.slice(l1At, res.out.indexOf('\n', l1At));
    expect(l1Line).toContain('no rating is awardable at L1');
    expect(l1Line).toContain('Verify:');
    // A --category that selects no automatable control is fixed by dropping
    // it; the Fix keeps the run's other flags and the requested level.
    const fix = citedCommand(res.out, 'Not assessed at L1:', 'Fix');
    // The target is quoted only when the shell needs it (#273 citationPath); this one has no space.
    expect(fix).toMatch(/^drop --category: \S+ secure \S+ -b oasb-1 -l L1 --no-machine-posture$/);
    expect(fix).not.toContain('-c ');
    expect(res.status).toBe(2);
  });

  // The two checks that produce the only L1 results on an empty directory at
  // quick depth (2.2 and 9.1). Ignoring them empties the L1 population — the
  // Verify must say so, and the Fix must name the flag, not the target.
  const QUICK_L1_CHECKS = 'PERM-001,PERM-002,SEM-PERM-001,SEM-PERM-002,SEM-MCP-001,PROC-001';

  it('RED-ON-BASE text: --ignore shapes the population, so the cited Verify repeats it and the Fix drops it', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '--scan-depth', 'quick', '--no-machine-posture', '--ignore', QUICK_L1_CHECKS]);
    // Guard: the fixture reaches the arm under test (L1 emptied by --ignore).
    expect(res.out).toContain('Rating: Not Assessed\n');
    expect(res.status).toBe(2);
    const l1At = res.out.indexOf('Not assessed at L1:');
    const l1Line = res.out.slice(l1At, res.out.indexOf('\n', l1At));
    expect(l1Line).toMatch(/^Not assessed at L1: 0 of \d+ automated L1 controls \(/);
    const verify = citedCommand(res.out, 'Not assessed at L1:', 'Verify');
    expect(verify).toMatch(new RegExp(`--ignore '?${QUICK_L1_CHECKS}'?( |$)`));
    const fix = citedCommand(res.out, 'Not assessed at L1:', 'Fix');
    expect(fix).toMatch(/^drop --ignore: \S+ secure \S+ -b oasb-1 -l L1 --scan-depth quick --no-machine-posture$/);
    expect(fix.slice('drop --ignore: '.length)).not.toContain('--ignore');
  });

  it.skipIf(!hasJq)('RED-ON-BASE text: the Verify cited beside an --ignore run reproduces the 0 the line counts', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '--scan-depth', 'quick', '--no-machine-posture', '--ignore', QUICK_L1_CHECKS]);
    expect(res.out).toContain('Rating: Not Assessed\n');
    const verify = citedCommand(res.out, 'Not assessed at L1:', 'Verify');
    const cmd = verify.replace(/^\S+ secure /, `${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} secure `);
    const ran = sh(cmd, root);
    expect(ran.status, ran.stderr).toBe(0);
    const controls = JSON.parse(ran.stdout);
    expect(controls.length).toBeGreaterThan(0); // the population, not an empty array
    expect(controls.filter((c: any) => c.status !== 'unverified').length).toBe(0);
  });

  it('RED-ON-BASE text: an --ignore that names no check of this population gets the project-root Fix, not "drop --ignore"', () => {
    // 10.1 (Monitoring & Response, L1) is measured by LOG-001/AUDIT-001; FOO-999 cannot have emptied it.
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', 'Monitoring & Response', '--no-machine-posture', '--ignore', 'FOO-999']);
    expect(res.out).toContain('Rating: Not Assessed\n');
    expect(res.status).toBe(2);
    const verify = citedCommand(res.out, 'Not assessed at L1:', 'Verify');
    expect(verify).toContain('--ignore FOO-999'); // the Verify still repeats the run
    const fix = citedCommand(res.out, 'Not assessed at L1:', 'Fix');
    expect(fix).toMatch(/^run against the project root/);
    expect(fix).not.toContain('drop --ignore');
  });

  it('RED-ON-BASE text: the cited Verify repeats --deep and --static-only', () => {
    const deep = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--deep']);
    expect(deep.out).toContain('Rating: Passing (L2, L3 not assessed)');
    expect(citedCommand(deep.out, 'Not assessed at L2:', 'Verify')).toContain(' --deep ');
    const stat = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--static-only']);
    expect(stat.out).toContain('Rating: Passing (L2, L3 not assessed)');
    expect(citedCommand(stat.out, 'Not assessed at L2:', 'Verify')).toContain(' --static-only ');
  });

  it('PIN: a -c that names no category exits 1 at the unknown-category gate, before any citation line exists', () => {
    // Why the cited `-c` value needs no display escaping: only a catalogue
    // name (case-insensitively) gets past this gate, and no catalogue name
    // carries a display hazard (pinned in calculate-rating-null-levels).
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', 'No Such Category', '--no-machine-posture']);
    expect(res.stderr).toContain("Error: Unknown category 'No Such Category'.");
    expect(res.out).not.toContain('Not assessed at');
    expect(res.status).toBe(1);
  });

  it('RED-ON-BASE text: a --category with no controls at an examined level says so instead of "none of the 0 controls ()"', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture']);
    expect(res.out).toContain('Not assessed at L3: the selected category has no L3 controls;');
    expect(res.out).not.toContain('none of the 0 ');
    expect(res.out).not.toContain('()');
    expect(res.status).toBe(2);
  });

  it('RED-ON-BASE text: a --category with L2 controls and no L1 controls is Not Assessed, and the reason counts the measured controls', () => {
    const res = run(['secure', mcpTree, '-b', 'oasb-1', '-l', 'L2', '-c', L2_ONLY_CATEGORY, '--no-machine-posture']);
    expect(res.out).toContain('Rating: Not Assessed\n');
    // The figure IS measured (over the L2 controls that produced a result).
    expect(res.out).toMatch(/Compliance: \d+% \(\d+\/[1-9]\d* verified controls\)/);
    expect(res.stderr).toMatch(/Benchmark rating is Not Assessed: no scored L1 control produced a result in this selection, so the rating ladder cannot be read; \d+ scored controls? at a higher level produced a result and (is|are) not rated\./);
    expect(res.stderr).not.toContain('no scored control produced a result.');
    expect(res.status).toBe(2);
  });

  it('RED-ON-BASE (this arm\'s recorded precedence): a measured --fail-below breach still exits 1 beside a Not Assessed rating, with both reasons on stderr', () => {
    const res = run(['secure', mcpTree, '-b', 'oasb-1', '-l', 'L2', '-c', L2_ONLY_CATEGORY, '--no-machine-posture', '--fail-below', '80']);
    expect(res.stderr).toContain('Benchmark rating is Not Assessed');
    // The printed reason must not misstate the precedence it applies.
    expect(res.stderr).toMatch(/Compliance \d+% is below threshold 80% — a measured breach outranks the not-measured floor above: exit 1/);
    expect(res.status).toBe(1);
  });

  it.skipIf(!hasJq)('RED-ON-BASE text: cited commands quote a target path that contains a space, and run', () => {
    const res = run(['secure', mcpTree, '-b', 'oasb-1', '-l', 'L2', '-c', L2_ONLY_CATEGORY, '--no-machine-posture']);
    const verify = citedCommand(res.out, 'Not assessed at L1:', 'Verify');
    expect(verify).toContain(`'${mcpTree}'`);
    expect(verify).toContain(`-c 'Agent-to-Agent Security'`);
    const cmd = verify.replace(/^\S+ secure /, `${JSON.stringify(process.execPath)} ${JSON.stringify(CLI)} secure `);
    const ran = sh(cmd, root);
    expect(ran.status, ran.stderr).toBe(0);
    const controls = JSON.parse(ran.stdout);
    expect(Array.isArray(controls)).toBe(true);
    expect(controls.length).toBe(0); // the category has no L1 controls: the line's own claim
  });

  it('RED-ON-BASE json: the Not Assessed run carries rating "Not Assessed" and null compliance at exit 2', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture', '--format', 'json']);
    const body = parseJson(res.stdout);
    expect(body.rating).toBe('Not Assessed');
    expect(body.compliance).toBeNull();
    expect(body.l1Compliance).toBeNull();
    expect(body.passedControls).toBe(0);
    expect(body.failedControls).toBe(0);
    expect(res.status).toBe(2);
  });

  it('RED-ON-BASE --fail-below is not evaluated against a NULL compliance: the Not Assessed exit 2 stands', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture', '--fail-below', '80']);
    expect(res.stderr).toContain('--fail-below 80 not evaluated: no compliance was measured (0 verified controls).');
    expect(res.stderr).not.toContain('below threshold');
    expect(res.status).toBe(2);
  });

  it('RED-ON-BASE html: the Not Assessed run prints no null% and carries the not-assessed line', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture', '--format', 'html']);
    expect(res.stdout).not.toMatch(/null%|NaN|undefined/);
    expect(res.stdout).toContain('not measured');
    expect(res.stdout).toContain('Not assessed at L1:');
    expect(res.stdout).toContain('>Not Assessed<');
    // The grade tile has its own null branch (grey 'not assessed'); a null
    // compliance must never fall through to the numeric ladder's bottom rung.
    expect(res.stdout).toContain('>not assessed<');
    expect(res.stdout).not.toContain('needs-attention');
    expect(res.status).toBe(2);
  });

  it('RED-ON-BASE asp + sarif (T5): the Not Assessed run carries the same rating and nulls on asp, and sarif still parses, both at exit 2', () => {
    const asp = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture', '--format', 'asp']);
    const body = parseJson(asp.stdout);
    expect(body.securityPosture.rating).toBe('Not Assessed');
    expect(body.securityPosture.compliance).toBeNull();
    expect(body.securityPosture.l1Compliance).toBeNull();
    expect(asp.stdout).not.toMatch(/null%|NaN|undefined/);
    expect(asp.status).toBe(2);
    const sarif = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '-c', NO_CONTROL_CATEGORY, '--no-machine-posture', '--format', 'sarif']);
    expect(Array.isArray(parseJson(sarif.stdout).runs)).toBe(true);
    expect(sarif.status).toBe(2);
  });

  it('RED-ON-BASE html: the badge carries the null scope at -l L3', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--format', 'html']);
    expect(res.stdout).toContain('Passing (L2, L3 not assessed)');
    // The document's title carries the same scope as its badge.
    expect(res.stdout).toContain('<title>OASB-1 Compliance Report | Passing (L2, L3 not assessed)</title>');
    expect(res.stdout).not.toMatch(/null%|NaN|undefined/);
    expect(res.status).toBe(0);
  });

  it('RED-ON-BASE asp: securityPosture carries the same null levels and rating as json', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--format', 'asp']);
    const body = parseJson(res.stdout);
    expect(body.securityPosture.l1Compliance).toBe(100);
    expect(body.securityPosture.l2Compliance).toBeNull();
    expect(body.securityPosture.l3Compliance).toBeNull();
    expect(body.securityPosture.compliance).toBe(100);
    expect(body.securityPosture.rating).toBe('Passing');
    expect(res.status).toBe(0);
  });

  it('RED-ON-BASE json: an L1 failure still reads Not Passing at -l L3 when L2/L3 are unmeasured (null rungs are skipped, not failed)', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--no-machine-posture', '--format', 'json']);
    const body = parseJson(res.stdout);
    expect(typeof body.l1Compliance).toBe('number');
    expect(body.l1Compliance).toBeLessThan(70);
    expect(body.l2Compliance).toBeNull();
    expect(body.l3Compliance).toBeNull();
    expect(body.rating).toBe('Not Passing');
    expect(res.status).toBe(1);
  });

  it('PIN sarif: still parses; the SARIF writer reads neither compliance nor rating', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--format', 'sarif']);
    const body = parseJson(res.stdout);
    expect(Array.isArray(body.runs)).toBe(true);
    expect(Array.isArray(body.runs[0].results)).toBe(true);
    expect(res.status).toBe(0);
  });

  it('PIN: a measured level below threshold still fails as before (-l L1 at default depth is Not Passing, exit 1, numeric l1Compliance)', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture', '--format', 'json']);
    const body = parseJson(res.stdout);
    expect(typeof body.l1Compliance).toBe('number');
    expect(typeof body.compliance).toBe('number');
    expect(body.rating).toBe('Not Passing');
    expect(res.status).toBe(1);
  });

  it('PIN: -l L1 on a measured tree prints the bare word and still cites -l L2 (L2 has automated controls)', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '--scan-depth', 'quick', '--no-machine-posture']);
    expect(res.out).toContain('Rating: Certified\n');
    expect(res.out).not.toContain('not assessed');
    expect(res.out).toContain("secure -b oasb-1 -l L2' for stricter checks");
    expect(res.status).toBe(0);
  });

  it('PIN (T4): --fail-below at -l L3 compares the measured figure; null L2/L3 do not enter it', () => {
    const ok = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--scan-depth', 'quick', '--no-machine-posture', '--fail-below', '80']);
    expect(ok.stderr).not.toContain('threshold');
    expect(ok.status).toBe(0);
    const low = run(['secure', empty, '-b', 'oasb-1', '-l', 'L3', '--no-machine-posture', '--fail-below', '80']);
    expect(low.stderr).toMatch(/Compliance \d+% is below threshold 80%/);
    expect(low.status).toBe(1);
  });

  it('PIN: --fail-below over a measured compliance still applies', () => {
    const res = run(['secure', empty, '-b', 'oasb-1', '-l', 'L1', '--no-machine-posture', '--fail-below', '80']);
    expect(res.stderr).toContain('below threshold 80%');
    expect(res.stderr).not.toContain('not evaluated');
    expect(res.status).toBe(1);
  });
});
