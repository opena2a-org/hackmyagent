/**
 * A choice in docs/chooser.json that carries an `example` names the committed
 * fixture its command runs in, the command with its operands filled in, the
 * exit code the run ends with, and a capture under docs/captures/ with a
 * sidecar beside it. A surface that shows a choice shows that capture as what
 * the command prints.
 *
 * This suite holds:
 *
 *  - each example, run on the build in a copy of its fixture, ends with the
 *    exit code the example declares, and its output, after the normalizers
 *    its sidecar lists, is byte-equal to the capture;
 *  - each sidecar is the record scripts/chooser-captures.mjs renders for its
 *    example, and docs/captures holds nothing else;
 *  - each choice without an example is listed below with the reason.
 *
 * A capture or sidecar that differs is regenerated with
 * `node scripts/chooser-captures.mjs --write`, which records no run whose
 * exit code differs from the declared one.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import { commandLine, validateChooser } from '../../scripts/chooser.mjs';
import {
  NORMALIZERS,
  compareText,
  examples,
  normalize,
  renderSidecar,
  runExample,
  sidecarPath,
} from '../../scripts/chooser-captures.mjs';
import { seedClassifier } from '../../scripts/use-case-samples.mjs';

const ROOT = path.resolve(__dirname, '../..');
const SCRIPT = path.join(ROOT, 'scripts', 'chooser-captures.mjs');
const DATA = JSON.parse(readFileSync(path.join(ROOT, 'docs', 'chooser.json'), 'utf8'));
const REGENERATE = 'regenerate with node scripts/chooser-captures.mjs --write';

/** The choices with no example yet, each with the reason. A choice that gains one leaves this list. */
const NO_EXAMPLE: Record<string, string> = {
  'agent-endpoint': 'attack needs a running agent endpoint to send its payloads to',
  'one-text': 'no committed fixture is a pull request body',
  'every-project':
    'detect adds machine-wide discovery (the host name and the assistants running on the machine) to every run, so its output is not a function of a fixture',
  'exposed-host': 'scan needs a host that serves MCP endpoints',
};

describe('docs/chooser.json examples', () => {
  it('every choice has an example or is listed here with the reason it has none', () => {
    const withExample = new Set(examples(DATA).map((e: { id: string }) => e.id));
    const without = [...DATA.options, ...DATA.more].map((e: { id: string }) => e.id).filter((id: string) => !withExample.has(id));
    expect(without.sort()).toEqual(Object.keys(NO_EXAMPLE).sort());
  });

  it('docs/captures holds a capture and a sidecar for each example, and nothing else', () => {
    const named = examples(DATA)
      .flatMap((e: { example: { capture: string } }) => [e.example.capture, sidecarPath(e.example.capture)])
      .map((p: string) => path.basename(p));
    expect(readdirSync(path.join(ROOT, 'docs', 'captures')).sort()).toEqual(named.sort());
  });

  it('validation refuses a fixture outside the test trees, a command that is not the choice filled in, an exit code outside 0 to 2 and a capture elsewhere (non-vacuity)', () => {
    const broken = structuredClone(DATA);
    const own = broken.options.find((o: { id: string }) => o.id === 'own-project');
    own.example.fixture = 'src';
    own.example.args = 'secure --fix';
    own.example.exit = 3;
    own.example.capture = 'docs/own-project.txt';
    // An option where the operand goes is not a filled-in operand.
    broken.options.find((o: { id: string }) => o.id === 'before-install').example.args = 'check --json';
    broken.more.find((m: { id: string }) => m.id === 'governance').example.fixture = 'test-fixtures/../src';
    expect(validateChooser(broken)).toEqual([
      'options[0].example.fixture: missing or not a folder under test-fixtures/ or test/',
      'options[0].example.args: "secure --fix" is not "secure" with each <operand> filled in',
      'options[0].example.exit: missing or not 0, 1 or 2',
      'options[0].example.capture: not docs/captures/own-project.txt',
      'options[1].example.args: "check --json" is not "check <target>" with each <operand> filled in',
      'more[0].example.fixture: missing or not a folder under test-fixtures/ or test/',
    ]);
  });

  it('each normalizer rewrites what it names and leaves the other lines alone', () => {
    const folder = path.join('/scratch', 'hma-chooser-AbC123');
    const raw = [
      '',
      `Scanning ${folder}${path.sep}insecure-library...`,
      'NanoMind: downloading the classifier model (3 file(s), 8.7 MB) into the model cache.',
      '  This happens once per cache; later runs use the cached copy.',
      'NanoMind: model downloaded and verified (8.7 MB).',
      '  Duration:           17ms',
      '  Duration: 17 findings',
      '  │ ',
      '  Scanned with hackmyagent v0.33.2',
      '',
    ].join('\n');
    expect(normalize(raw, NORMALIZERS.map((n: { id: string }) => n.id), { folders: [folder] })).toBe([
      '',
      'Scanning .../insecure-library...',
      '  Duration:           <n>ms',
      '  Duration: 17 findings',
      '  │',
      '  Scanned with hackmyagent v<version>',
      '',
    ].join('\n'));
    expect(normalize(raw, [], { folders: [folder] })).toBe(raw);
    expect(() => normalize(raw, ['no-such-normalizer'])).toThrow('unknown normalizer "no-such-normalizer"');
  });

  it('temp-folder replaces the longer of two folder spellings first', () => {
    // On macOS a temporary folder under /var is also reached as /private/var.
    const short = path.join('/var', 'hma-chooser-x');
    const long = path.join('/private', 'var', 'hma-chooser-x');
    expect(normalize(`${long}${path.sep}a ${short}${path.sep}b`, ['temp-folder'], { folders: [short, long] })).toBe('.../a .../b');
  });

  it('the comparison is byte for byte and names the first line that differs', () => {
    expect(compareText('a\nb\n', 'a\nb\n')).toBeNull();
    expect(compareText('a\nb\n', 'a\nc\n')).toEqual({ line: 2, have: 'b', want: 'c' });
    expect(compareText('a\nb\n', 'a\nb')).toEqual({ line: 3, have: '', want: undefined });
  });

  it('the script refuses an unknown argument with exit 2', () => {
    const run = spawnSync(process.execPath, [SCRIPT, '--no-such-argument'], { encoding: 'utf8' });
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('unexpected argument "--no-such-argument"');
  });

  describe('each example, run on the build in a copy of its fixture', () => {
    // Each case runs the built CLI; a missing or stale build fails by name.
    beforeAll(assertDistFresh);

    // One HOME for every run, so the classifier is fetched at most once.
    let home = '';
    beforeAll(() => {
      home = tempDir('hma-chooser-captures-home-');
      seedClassifier(home);
    });

    for (const entry of examples(DATA)) {
      const ex = entry.example;
      it(`${entry.id}: ${commandLine(DATA, ex.args)} in ${ex.fixture} exits ${ex.exit} and prints ${ex.capture}`, (ctx) => {
        const sidecar = readFileSync(path.join(ROOT, sidecarPath(ex.capture)), 'utf8');
        expect(sidecar, `${sidecarPath(ex.capture)} is not the record of this example; ${REGENERATE}`).toBe(renderSidecar(DATA, entry));

        const run = runExample(entry, { home });
        if (!run.classifier) ctx.skip('the NanoMind classifier could not be fetched; the captures are runs with it');
        expect(run.status, `the exit code docs/chooser.json declares for ${entry.id}`).toBe(ex.exit);

        const ids = JSON.parse(sidecar).normalizers.map((n: { id: string }) => n.id);
        const diff = compareText(readFileSync(path.join(ROOT, ex.capture), 'utf8'), normalize(run.raw, ids, run));
        expect(diff, diff ? `${ex.capture}:${diff.line} differs from the build; ${REGENERATE}` : '').toBeNull();
      });
    }
  });
});
