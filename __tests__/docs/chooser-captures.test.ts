/**
 * A choice in docs/chooser.json that carries an `example` names the committed
 * fixture its command runs in, the command with its operands filled in, the
 * exit code the run ends with, and a capture under docs/captures/ with a
 * sidecar beside it. A `nextExample` does the same for the choice's next
 * command. An example whose command has the operand `-` also names the file
 * of its fixture the run reads on standard input. A surface that shows a
 * choice shows that capture as what the command prints.
 *
 * This suite holds:
 *
 *  - each example, run on the build in a copy of its fixture, ends with the
 *    exit code the example declares, and its output, after the normalizers
 *    its sidecar lists, is byte-equal to the capture;
 *  - each sidecar is the record scripts/chooser-captures.mjs renders for its
 *    example, and docs/captures holds nothing else;
 *  - each choice without an example, and each next command without one, is
 *    listed below with the reason.
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
import { validateChooser } from '../../scripts/chooser.mjs';
import {
  NORMALIZERS,
  compareText,
  exampleCommand,
  examples,
  normalize,
  normalizersFor,
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
  'every-project':
    'detect adds machine-wide discovery (the host name and the assistants running on the machine) to every run, so its output is not a function of a fixture',
  'exposed-host': 'scan needs a host that serves MCP endpoints',
};

/** The next commands with no example yet, each with the reason. */
const NO_NEXT_EXAMPLE: Record<string, string> = {
  'agent-endpoint': 'attack needs a running agent endpoint to send its payloads to',
  'every-project':
    'it is secure on one project detect listed, the command of the own-project choice with the project named; docs/captures/own-project.txt shows what secure prints',
};

interface Item { entry: { id: string }; step: 'run' | 'next'; example: { fixture: string; args: string; stdin?: string; exit: number; capture: string } }
const ITEMS: Item[] = examples(DATA);

describe('docs/chooser.json examples', () => {
  it('every choice has an example or is listed here with the reason it has none', () => {
    const withExample = new Set(ITEMS.filter((i) => i.step === 'run').map((i) => i.entry.id));
    const without = [...DATA.options, ...DATA.more].map((e: { id: string }) => e.id).filter((id: string) => !withExample.has(id));
    expect(without.sort()).toEqual(Object.keys(NO_EXAMPLE).sort());
  });

  it('every next command has an example or is listed here with the reason it has none', () => {
    const withExample = new Set(ITEMS.filter((i) => i.step === 'next').map((i) => i.entry.id));
    const without = DATA.options.map((o: { id: string }) => o.id).filter((id: string) => !withExample.has(id));
    expect(without.sort()).toEqual(Object.keys(NO_NEXT_EXAMPLE).sort());
  });

  it('docs/captures holds a capture and a sidecar for each example, and nothing else', () => {
    const named = ITEMS.flatMap((i) => [i.example.capture, sidecarPath(i.example.capture)]).map((p: string) => path.basename(p));
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

  it('validation refuses a next example that is not the next command filled in or has its capture elsewhere, and one on an entry under more (non-vacuity)', () => {
    const broken = structuredClone(DATA);
    broken.options.find((o: { id: string }) => o.id === 'own-project').nextExample = {
      fixture: 'test-fixtures/insecure-library',
      args: 'secure',
      exit: 1,
      capture: 'docs/captures/own-project.txt',
    };
    // An option where the operand goes is not a filled-in operand.
    broken.options.find((o: { id: string }) => o.id === 'before-install').nextExample.args = 'secure --json --fix';
    broken.more.find((m: { id: string }) => m.id === 'governance').nextExample = {
      fixture: 'test/fixtures/governed-mcp',
      args: 'scan-soul',
      exit: 1,
      capture: 'docs/captures/governance-next.txt',
    };
    expect(validateChooser(broken)).toEqual([
      'options[0].nextExample.args: "secure" is not "secure --fix" with each <operand> filled in',
      'options[0].nextExample.capture: not docs/captures/own-project-next.txt',
      'options[1].nextExample.args: "secure --json --fix" is not "secure <dir> --fix" with each <operand> filled in',
      'more[0].nextExample: an entry under more has no next command',
    ]);
  });

  it('validation refuses an example that reads standard input with no stdin file, a stdin file on a command that does not read it, and a stdin path outside the fixture (non-vacuity)', () => {
    const broken = structuredClone(DATA);
    const text = broken.options.find((o: { id: string }) => o.id === 'one-text');
    delete text.nextExample.stdin;
    text.example.stdin = 'pr-body.md';
    broken.options.find((o: { id: string }) => o.id === 'own-project').example.stdin = '../insecure-api/config.json';
    expect(validateChooser(broken)).toEqual([
      'options[0].example.stdin: not the path of a file inside the fixture folder',
      'options[3].example.stdin: only a command with the operand - reads standard input',
      'options[3].nextExample.stdin: missing; the operand - reads standard input, so the example names the fixture file it reads',
    ]);
  });

  it('an example whose stdin file is not in its fixture is refused before anything runs', () => {
    const item = {
      entry: { id: 'one-text' },
      step: 'next',
      example: { fixture: 'test-fixtures/pr-body', args: 'scan-text - --json', stdin: 'no-such-file.md', exit: 1, capture: 'docs/captures/one-text-next.txt' },
    };
    expect(() => runExample(item, { home: tempDir('hma-chooser-captures-home-'), cli: path.join(ROOT, 'no-such-cli.js') })).toThrow(
      'one-text: the fixture test-fixtures/pr-body has no file no-such-file.md to read on standard input',
    );
  });

  it('the command of an example that reads standard input names the file it reads there, and the others are the command alone', () => {
    const text = DATA.options.find((o: { id: string }) => o.id === 'one-text');
    expect(exampleCommand(DATA, text.nextExample)).toBe('npx hackmyagent scan-text - --as pr-body --json < pr-body.md');
    expect(exampleCommand(DATA, text.example)).toBe('npx hackmyagent scan-text pr-body.md');
  });

  it('a run with --fix also takes home-folder and backup-store, a run with --json also takes json-version, and a run with neither takes the five it always took', () => {
    const always = ['classifier-download', 'temp-folder', 'tool-version', 'duration', 'trailing-space'];
    expect(normalizersFor('secure').map((n: { id: string }) => n.id)).toEqual(always);
    expect(normalizersFor('red-team SKILL.md').map((n: { id: string }) => n.id)).toEqual(always);
    expect(normalizersFor('secure malicious-skill --fix').map((n: { id: string }) => n.id)).toEqual([
      'classifier-download', 'temp-folder', 'home-folder', 'backup-store', 'tool-version', 'duration', 'trailing-space',
    ]);
    expect(normalizersFor('scan-text - --as pr-body --json').map((n: { id: string }) => n.id)).toEqual([
      'classifier-download', 'temp-folder', 'tool-version', 'json-version', 'duration', 'trailing-space',
    ]);
  });

  it('json-version prints the hackmyagentVersion value as <version> and leaves the other lines alone', () => {
    const raw = ['{', '  "hackmyagentVersion": "0.33.2",', '  "surface": "pr-body",', '  "note": "hackmyagentVersion 0.33.2"', '}'].join('\n');
    expect(normalize(raw, ['json-version'])).toBe(
      ['{', '  "hackmyagentVersion": "<version>",', '  "surface": "pr-body",', '  "note": "hackmyagentVersion 0.33.2"', '}'].join('\n'),
    );
  });

  it('home-folder and backup-store print the --fix backup lines without the run\'s HOME or the store\'s generated names', () => {
    const home = path.join('/scratch', 'hma-chooser-captures-home-XyZ');
    const store = `${home}${path.sep}.opena2a/backups/1-22-333`;
    const raw = [
      `Backup created: ${store}/2026-10-17-034824521-000-c0287b32`,
      `Backups: 1 --fix backup of this directory is kept outside it at ${store}. Delete it: rm -rf ${store}`,
      'Fixed 2 issues (2 verified):',
    ].join('\n');
    expect(normalize(raw, ['home-folder', 'backup-store'], { homes: [home] })).toBe([
      'Backup created: ~/.opena2a/backups/<directory>/<run>',
      'Backups: 1 --fix backup of this directory is kept outside it at ~/.opena2a/backups/<directory>. Delete it: rm -rf ~/.opena2a/backups/<directory>',
      'Fixed 2 issues (2 verified):',
    ].join('\n'));
    expect(normalize(raw, [], { homes: [home] })).toBe(raw);
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

    for (const item of ITEMS) {
      const ex = item.example;
      const id = `${item.entry.id}${item.step === 'next' ? ' (next)' : ''}`;
      it(`${id}: ${exampleCommand(DATA, ex)} in ${ex.fixture} exits ${ex.exit} and prints ${ex.capture}`, (ctx) => {
        const sidecar = readFileSync(path.join(ROOT, sidecarPath(ex.capture)), 'utf8');
        expect(sidecar, `${sidecarPath(ex.capture)} is not the record of this example; ${REGENERATE}`).toBe(renderSidecar(DATA, item));

        const run = runExample(item, { home });
        if (!run.classifier) ctx.skip('the NanoMind classifier could not be fetched; the captures are runs with it');
        expect(run.status, `the exit code docs/chooser.json declares for ${id}`).toBe(ex.exit);

        const ids = JSON.parse(sidecar).normalizers.map((n: { id: string }) => n.id);
        const diff = compareText(readFileSync(path.join(ROOT, ex.capture), 'utf8'), normalize(run.raw, ids, run));
        expect(diff, diff ? `${ex.capture}:${diff.line} differs from the build; ${REGENERATE}` : '').toBeNull();
      });
    }
  });
});
