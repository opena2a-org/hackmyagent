/**
 * HMA-16: the provider-token-shape backlog cannot regrow.
 *
 * Runs the token-shape guard (`__tests__/helpers/token-shape-guard.ts`) over
 * the whole repository on every `npm test`, and proves the guard non-vacuous
 * by planting in both polarities. Leaf test names carry their
 * acceptance-criterion id (HMA-16.ACn, HMA-80.ACn for the hardening that
 * anchored the skip names to the root and widened the convertible set) as
 * their first token.
 *
 * NOTHING in this file spells a token-shape value as a source literal: every
 * planted value is assembled at runtime by concatenation, so this file passes
 * the very scan it runs (it is inside the walk).
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { CredVaultPlugin } from '../../src/plugins/credvault';
import {
  TOKEN_SHAPE_PATTERN_SOURCE,
  REGISTRY_PATH,
  loadRegistry,
  scanRepository,
  validateRegistry,
  formatViolations,
  type ExemptionRegistry,
} from '../helpers/token-shape-guard';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const EMPTY_REGISTRY: ExemptionRegistry = { entries: [] };

/** A token-shape string that exists only at runtime, never as source bytes. */
function assembledPlantValue(): string {
  return ['gh', 'p_'].join('') + 'A'.repeat(36);
}

describe('token-shape guard (HMA-16)', () => {
  it('HMA-16.AC1 every token-shape line in the repository resolves to a registry entry, and 0 lines are unregistered', () => {
    const result = scanRepository(REPO_ROOT, loadRegistry(REPO_ROOT));
    expect(formatViolations(result)).toEqual([]);
    expect(result.unregisteredLineCount).toBe(0);
    expect(result.ok).toBe(true);
  });

  it('HMA-16.AC1 a nested checkout (a directory with its own .git) is not this repository', () => {
    // A git worktree inside the tree carries a `.git` gitfile; a nested clone
    // carries a `.git` directory. Neither's lines are this repository's.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma16-nested-'));
    try {
      for (const [dir, gitShape] of [['wt', 'file'], ['clone', 'dir']] as const) {
        fs.mkdirSync(path.join(tmp, dir), { recursive: true });
        if (gitShape === 'file') fs.writeFileSync(path.join(tmp, dir, '.git'), 'gitdir: /elsewhere\n');
        else fs.mkdirSync(path.join(tmp, dir, '.git'));
        fs.writeFileSync(path.join(tmp, dir, 'notes.txt'), `token: ${assembledPlantValue()}\n`);
      }
      // The same line at the root IS this repository's, so the walk still runs.
      fs.writeFileSync(path.join(tmp, 'notes.txt'), `token: ${assembledPlantValue()}\n`);
      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.matchedLineCount).toBe(1);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC1 a marker word exempts nothing: only a registry entry does', () => {
    // The repository push gate's marker allowlist would suppress a line
    // carrying FAKE or PLACEHOLDER. This guard must not: plant a line carrying both markers
    // and an assembled token, with an empty registry, and expect a hit.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma16-marker-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'notes.txt'),
        `FAKE PLACEHOLDER example token: ${assembledPlantValue()}\n`,
      );
      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.matchedLineCount).toBe(1);
      expect(result.ok).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC2 the registry rejects a convertible .ts/.js/.mjs/.tsx entry unless escalated with a public decision reference', () => {
    for (const ext of ['ts', 'js', 'mjs', 'tsx']) {
      const errors = validateRegistry({
        entries: [{ path: `some/new/file.${ext}`, expectedHits: 1, reason: 'byte-literal-fixture' }],
      });
      expect(errors.length, `.${ext} entry must be rejected`).toBeGreaterThan(0);
    }
    const escalated = validateRegistry({
      entries: [
        {
          path: 'some/new/file.ts',
          expectedHits: 1,
          reason: 'escalated',
          // Lexically valid; GitHub issue numbers start at 1, so /issues/0
          // can never name a real issue.
          decisionRef: 'https://github.com/opena2a-org/hackmyagent/issues/0',
        },
      ],
    });
    expect(escalated).toEqual([]);
    const badRef = validateRegistry({
      entries: [{ path: 'some/new/file.ts', expectedHits: 1, reason: 'escalated', decisionRef: 'not-a-url' }],
    });
    expect(badRef.length, 'escalated with a malformed decisionRef must be rejected').toBeGreaterThan(0);
  });

  it('HMA-16.AC2 the committed registry is drained: it carries no convertible-source entry at all', () => {
    const registry = loadRegistry(REPO_ROOT);
    expect(registry.entries.length).toBeGreaterThan(0);
    const convertible = registry.entries.filter((e) => /\.(ts|js|mjs|tsx)$/.test(e.path));
    expect(convertible).toEqual([]);
  });

  it('HMA-16.AC3 the walk starts at the repo root and reaches a token-shape line in a NEW directory', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma16-newdir-'));
    try {
      const nested = path.join(tmp, 'brand-new-dir', 'deeper');
      fs.mkdirSync(nested, { recursive: true });
      fs.writeFileSync(path.join(nested, 'config.json'), `{"token": "${assembledPlantValue()}"}\n`);
      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.unregisteredLineCount).toBe(1);
      expect(result.violations.map((v) => v.path)).toEqual(['brand-new-dir/deeper/config.json']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC4 plant proof, both polarities: one unregistered hit fails the scan, and removing the plant returns it to 0 and passing', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma16-plant-'));
    try {
      fs.writeFileSync(path.join(tmp, 'innocuous.md'), 'nothing to see here\n');
      const plant = path.join(tmp, 'planted.txt');
      fs.writeFileSync(plant, `value=${assembledPlantValue()}\n`);

      const red = scanRepository(tmp, EMPTY_REGISTRY);
      expect(red.matchedLineCount).toBe(1);
      expect(red.unregisteredLineCount).toBe(1);
      expect(red.violations).toEqual([{ kind: 'unregistered', path: 'planted.txt', lines: [1] }]);
      expect(red.ok).toBe(false);

      fs.rmSync(plant);
      const green = scanRepository(tmp, EMPTY_REGISTRY);
      expect(green.matchedLineCount).toBe(0);
      expect(green.unregisteredLineCount).toBe(0);
      expect(green.ok).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC5 a fixture rebuilt with the runtime-assembly idiom keeps its detection verdict and acquires no fixture marker', async () => {
    // The exact value __tests__/plugins/credvault/deep.test.ts asserts one
    // detection for ("detects valid Anthropic key"), assembled the way the
    // AC2 conversion assembles it. If the conversion had made the value
    // legible to isTestFixtureCredential's marker list, this count would be 0.
    const converted = ['sk', '-ant-api03-ZGbnD4IEg1WTciUzH6ntayxIp2nq0KNsKdv3LYTaVt8PLo64w70bLILy8M'].join('');
    for (const marker of ['FAKE', 'EXAMPLE', 'PLACEHOLDER', 'TEST', 'DUMMY', 'SAMPLE', 'XXX', 'YOUR_', '<YOUR']) {
      expect(converted.toUpperCase()).not.toContain(marker);
    }
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma16-verdict-'));
    try {
      fs.writeFileSync(path.join(tmp, 'config.json'), JSON.stringify({ key: converted }), 'utf-8');
      const plugin = new CredVaultPlugin();
      await plugin.init();
      const findings = await plugin.scan(tmp);
      const titles = findings.filter((f) => f.id === 'CRED-001').map((f) => f.title);
      expect(titles.length).toBe(1);
      expect(titles[0]).toContain('Anthropic');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC6 the guard scans its own implementation, its own test and the registry, and none carries a token-shape line', () => {
    const own = [
      '__tests__/helpers/token-shape-guard.ts',
      '__tests__/hardening/token-shape-guard.test.ts',
      REGISTRY_PATH,
    ];
    const pattern = new RegExp(TOKEN_SHAPE_PATTERN_SOURCE);
    for (const rel of own) {
      const content = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
      for (const [i, line] of content.split('\n').entries()) {
        expect(pattern.test(line), `${rel}:${i + 1} must not match the pattern set`).toBe(false);
      }
    }
  });

  it('HMA-16.AC6 registry entries key on path plus expected-hit count and carry zero matched text', () => {
    const registry = loadRegistry(REPO_ROOT);
    const pattern = new RegExp(TOKEN_SHAPE_PATTERN_SOURCE);
    for (const entry of registry.entries) {
      expect(typeof entry.path).toBe('string');
      expect(Number.isInteger(entry.expectedHits)).toBe(true);
      expect(pattern.test(JSON.stringify(entry))).toBe(false);
    }
  });

  it('HMA-16.AC7 public docs no longer model the --no-verify gate bypass', () => {
    const flag = ['--no-', 'verify'].join('');
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.isFile() && fs.readFileSync(full, 'utf8').includes(flag)) {
          offenders.push(path.relative(REPO_ROOT, full));
        }
      }
    };
    walk(path.join(REPO_ROOT, 'docs'));
    expect(offenders).toEqual([]);
  });

  it('HMA-80.AC1 a build-named directory below the root is walked: src/dist, src/build, src/coverage and src/.cache each surface their token-shape line', () => {
    for (const name of ['dist', 'build', 'coverage', '.cache']) {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma80-nested-skipname-'));
      try {
        const nested = path.join(tmp, 'src', name);
        fs.mkdirSync(nested, { recursive: true });
        fs.writeFileSync(path.join(nested, 'leak.json'), `{"token": "${assembledPlantValue()}"}\n`);
        const result = scanRepository(tmp, EMPTY_REGISTRY);
        expect(result.unregisteredLineCount, `src/${name}/leak.json must be reported`).toBe(1);
        expect(result.violations.map((v) => v.path)).toEqual([`src/${name}/leak.json`]);
        expect(result.violations[0].kind).toBe('unregistered');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    }
  });

  it('HMA-80.AC2 the root-level skips and the nested-checkout skip still hold, and a root-level src/ line is still reported', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma80-root-skips-'));
    try {
      const line = `{"token": "${assembledPlantValue()}"}\n`;
      // Root-level skip names: never walked.
      for (const rel of [['dist'], ['node_modules', 'pkg'], ['coverage']]) {
        fs.mkdirSync(path.join(tmp, ...rel), { recursive: true });
        fs.writeFileSync(path.join(tmp, ...rel, 'leak.json'), line);
      }
      // A subdirectory carrying its own `.git` entry is another checkout.
      fs.mkdirSync(path.join(tmp, 'vendor-checkout'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'vendor-checkout', '.git'), 'gitdir: /elsewhere\n');
      fs.writeFileSync(path.join(tmp, 'vendor-checkout', 'leak.json'), line);
      // The control: the same line under src/ IS reported, so this case
      // cannot pass on an empty walk.
      fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'src', 'leak.json'), line);

      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.matchedLineCount).toBe(1);
      expect(result.unregisteredLineCount).toBe(1);
      expect(result.violations.map((v) => v.path)).toEqual(['src/leak.json']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-80.AC3 the registry rejects a convertible .cjs/.cts/.mts/.jsx entry unless escalated with a public decision reference', () => {
    for (const ext of ['cjs', 'cts', 'mts', 'jsx']) {
      const errors = validateRegistry({
        entries: [{ path: `some/new/file.${ext}`, expectedHits: 1, reason: 'byte-literal-fixture' }],
      });
      expect(errors.length, `.${ext} entry must be rejected`).toBeGreaterThan(0);
      const escalated = validateRegistry({
        entries: [
          {
            path: `some/new/file.${ext}`,
            expectedHits: 1,
            reason: 'escalated',
            // Lexically valid; GitHub issue numbers start at 1, so /issues/0
            // can never name a real issue.
            decisionRef: 'https://github.com/opena2a-org/hackmyagent/issues/0',
          },
        ],
      });
      expect(escalated, `escalated .${ext} entry with a decisionRef must be accepted`).toEqual([]);
    }
  });

  it('HMA-80.AC4 the repository stays clean under the hardened guard: 0 unregistered lines, a valid registry, and no entry for any of the eight script extensions', () => {
    const registry = loadRegistry(REPO_ROOT);
    expect(validateRegistry(registry)).toEqual([]);
    const result = scanRepository(REPO_ROOT, registry);
    expect(formatViolations(result)).toEqual([]);
    expect(result.unregisteredLineCount).toBe(0);
    expect(result.ok).toBe(true);
    const scriptExt = /\.(ts|js|mjs|tsx|cjs|cts|mts|jsx)$/;
    expect(registry.entries.filter((e) => scriptExt.test(e.path))).toEqual([]);
  });

  it('HMA-80.AC5 a file with a NUL byte in its first 8 KiB is binary and not scanned; a NUL beyond 8 KiB does not hide a line', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma80-binary-'));
    try {
      const line = `token: ${assembledPlantValue()}\n`;
      // NUL at byte 0: binary, skipped despite the token-shape line after it.
      fs.writeFileSync(path.join(tmp, 'early-nul.bin'), Buffer.concat([Buffer.from([0]), Buffer.from(line)]));
      // NUL only after the first 8 KiB: text as far as the guard is
      // concerned, so the token-shape line before it is reported.
      const padding = ('a'.repeat(79) + '\n').repeat(110); // 8800 bytes, past the 8192-byte window
      fs.writeFileSync(path.join(tmp, 'late-nul.txt'), Buffer.concat([Buffer.from(line), Buffer.from(padding), Buffer.from([0])]));
      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.matchedLineCount).toBe(1);
      expect(result.violations.map((v) => v.path)).toEqual(['late-nul.txt']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('HMA-80.AC5 symbolic links to a file and to a directory are not followed', () => {
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'hma80-symlink-target-'));
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma80-symlink-root-'));
    try {
      const line = `token: ${assembledPlantValue()}\n`;
      fs.writeFileSync(path.join(outside, 'leak.json'), line);
      fs.mkdirSync(path.join(outside, 'leakdir'));
      fs.writeFileSync(path.join(outside, 'leakdir', 'leak.json'), line);
      fs.symlinkSync(path.join(outside, 'leak.json'), path.join(tmp, 'file-link.json'));
      fs.symlinkSync(path.join(outside, 'leakdir'), path.join(tmp, 'dir-link'), 'dir');
      // The control: a regular file with the same line is reported.
      fs.writeFileSync(path.join(tmp, 'regular.json'), line);
      const result = scanRepository(tmp, EMPTY_REGISTRY);
      expect(result.matchedLineCount).toBe(1);
      expect(result.violations.map((v) => v.path)).toEqual(['regular.json']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('HMA-16.AC8 the pattern set is exactly the seven provider-token alternates the repository push gate enforces: URL-userinfo and private-key alternates stay deferred', () => {
    // Byte-identical to the provider-token pattern set the repository push
    // gate enforces. Written out again here so a drive-by edit to
    // the helper cannot silently narrow or widen the guard.
    expect(TOKEN_SHAPE_PATTERN_SOURCE).toBe(
      '(gh[posru]_[A-Za-z0-9]{20,})|(github_pat_[A-Za-z0-9_]{20,})|(xox[baprs]-[A-Za-z0-9-]{10,})|((AKIA|ASIA)[0-9A-Z]{16})|(sk-[A-Za-z0-9_-]{20,})|(AIza[0-9A-Za-z_-]{35})|(npm_[A-Za-z0-9]{36})',
    );
    // Deferred scope (measured 2026-08-31: 100 URL-userinfo lines, 11
    // private-key lines on origin/main). Adding either would be red on
    // arrival, which is the state that gets a gate disabled.
    expect(TOKEN_SHAPE_PATTERN_SOURCE).not.toContain('://');
    expect(TOKEN_SHAPE_PATTERN_SOURCE).not.toContain('BEGIN');
  });
});
