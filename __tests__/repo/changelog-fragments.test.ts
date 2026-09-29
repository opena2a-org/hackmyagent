/**
 * `scripts/changelog.mjs`: CHANGELOG entries live as one file per change under
 * `changelog.d/`, and CHANGELOG.md is written only by the release command.
 *
 * Every case runs the real script as a child process against a throwaway git
 * repository, so what is asserted is what CI and a release run see: exit
 * status, the files on disk, and the bytes of CHANGELOG.md.
 *
 * Coverage map:
 *   new             naming, front-matter, refusals, collision-free parallel adds
 *   check R1        fragment name and content rules, fence-aware headings
 *   check R2        no entries under `## [Unreleased]`
 *   check R3        CHANGELOG.md changes only by assembly (a) or amendment (b)
 *   check R4        a version bump always assembles
 *   check R5        a change to the script lands alone
 *   check R6        the conversion change preserves every entry line
 *   preview         the section alone, and the whole file with --virtual
 *   release         layout, order, bump rules, date rules
 *   verify-release  the tag-time proof
 *   convert         a branch's additions become fragments; edits are refused
 *   convert --legacy
 */
import { describe, it, expect } from 'vitest';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync, rmSync, existsSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as yaml from 'js-yaml';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

const REPO_ROOT = path.join(__dirname, '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'changelog.mjs');

const POINTER = 'Entries for the next release are files in `changelog.d/`.';

const RELEASED = [
  '## [0.5.0] - 2026-01-10',
  '',
  '### Fixed',
  '',
  '- an old fix (#1)',
  '',
].join('\n');

const CONVERTED = ['# Changelog', '', 'Notable changes.', '', '## [Unreleased]', '', POINTER, '', RELEASED].join('\n');

interface Run { status: number | null; stdout: string; stderr: string }

function run(dir: string, args: string[], input = ''): Run {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: dir, env: gitFreeEnv(), input, encoding: 'utf8' });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', args, { cwd: dir, env: gitFreeEnv(), encoding: 'utf8' }).trim();
}

function write(dir: string, rel: string, text: string): void {
  mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  writeFileSync(path.join(dir, rel), text);
}

function read(dir: string, rel: string): string {
  return readFileSync(path.join(dir, rel), 'utf8');
}

function commitAll(dir: string, msg: string): string {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '--allow-empty', '-m', msg);
  return git(dir, 'rev-parse', 'HEAD');
}

function fragment(type: string, body: string, extra: string[] = []): string {
  return ['---', `type: ${type}`, ...extra, '---', body, ''].join('\n');
}

function fragments(dir: string, sub = 'changelog.d'): string[] {
  const d = path.join(dir, sub);
  return existsSync(d) ? readdirSync(d).filter(n => n !== 'README.md').sort() : [];
}

/**
 * A converted repository at commit B: CHANGELOG.md with the pointer, a
 * changelog.d/README.md, a package.json at `version`, and a copy of the script.
 * The working branch `work` is checked out at B.
 */
function convertedRepo(version = '0.5.0', changelog = CONVERTED): { dir: string; base: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-changelog-'));
  initThrowawayRepo(dir);
  write(dir, 'CHANGELOG.md', changelog.replace('0.5.0', version));
  write(dir, 'changelog.d/README.md', 'Add an entry: `node scripts/changelog.mjs new --type fixed < entry.md`\n');
  write(dir, 'package.json', JSON.stringify({ name: 'fx', version }, null, 2) + '\n');
  write(dir, 'scripts/changelog.mjs', readFileSync(SCRIPT, 'utf8'));
  const base = commitAll(dir, 'base');
  git(dir, 'checkout', '-q', '-b', 'work');
  return { dir, base };
}

/** The same repository with fragments committed at B. */
function repoWithFragments(files: Record<string, string>, version = '0.5.0'): { dir: string; base: string } {
  const { dir } = convertedRepo(version);
  for (const [name, text] of Object.entries(files)) write(dir, `changelog.d/${name}`, text);
  const base = commitAll(dir, 'fragments');
  return { dir, base };
}

function bumpPackage(dir: string, version: string): void {
  write(dir, 'package.json', JSON.stringify({ name: 'fx', version }, null, 2) + '\n');
}

const cleanup = (dir: string) => rmSync(dir, { recursive: true, force: true });

describe('changelog.mjs is present and uses the standard library only', () => {
  it('exists at scripts/changelog.mjs', () => {
    expect(existsSync(SCRIPT)).toBe(true);
  });

  it('imports nothing outside node:fs, node:path, node:crypto and node:child_process', () => {
    const src = readFileSync(SCRIPT, 'utf8');
    const imports = [...src.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map(m => m[1]);
    expect(imports.length).toBeGreaterThan(0);
    for (const spec of imports) expect(['node:fs', 'node:path', 'node:crypto', 'node:child_process']).toContain(spec);
    expect(src).not.toMatch(/\brequire\(/);
  });
});

describe('new', () => {
  it('writes <branch-slug>-<hex6>.md with the front-matter and prints its path', () => {
    const { dir } = convertedRepo();
    try {
      git(dir, 'checkout', '-q', '-b', 'fleet/HMA-761_Scoped.skill');
      const r = run(dir, ['new', '--type', 'fixed', '--issue', '761, 762', '--breaking'], '- a fix (#761)\n');
      expect(r.status, r.stderr).toBe(0);
      const names = fragments(dir);
      expect(names).toHaveLength(1);
      expect(names[0]).toMatch(/^hma-761-scoped-skill-[0-9a-f]{6}\.md$/);
      expect(r.stdout.trim()).toBe(path.join('changelog.d', names[0]));
      expect(read(dir, `changelog.d/${names[0]}`)).toBe('---\ntype: fixed\nissue: 761, 762\nbreaking: true\n---\n- a fix (#761)\n');
      expect(run(dir, ['check']).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('uses --name as the slug', () => {
    const { dir } = convertedRepo();
    try {
      const r = run(dir, ['new', '--type', 'added', '--name', 'scan-text'], '- a feature\n');
      expect(r.status, r.stderr).toBe(0);
      expect(fragments(dir)[0]).toMatch(/^scan-text-[0-9a-f]{6}\.md$/);
    } finally { cleanup(dir); }
  });

  it('caps a long branch slug at 60 characters and keeps the name within 80', () => {
    const { dir } = convertedRepo();
    try {
      git(dir, 'checkout', '-q', '-b', `fleet/${'a-very-long-branch-name-'.repeat(5)}end`);
      const r = run(dir, ['new', '--type', 'fixed'], '- x\n');
      expect(r.status, r.stderr).toBe(0);
      const name = fragments(dir)[0];
      expect(name.length).toBeLessThanOrEqual(80);
      expect(name.replace(/-[0-9a-f]{6}\.md$/, '').length).toBeLessThanOrEqual(60);
      expect(name).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{6}\.md$/);
    } finally { cleanup(dir); }
  });

  it('refuses an unknown type, an empty entry, a level 1-3 heading and a bad slug, and writes nothing', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['new', '--type', 'bugfix'], '- x\n').status).not.toBe(0);
      expect(run(dir, ['new'], '- x\n').status).not.toBe(0);
      expect(run(dir, ['new', '--type', 'fixed'], '\n\n').status).not.toBe(0);
      expect(run(dir, ['new', '--type', 'fixed'], '### A title\n\n- x\n').status).not.toBe(0);
      expect(run(dir, ['new', '--type', 'fixed', '--name', 'Bad Name'], '- x\n').status).not.toBe(0);
      expect(run(dir, ['new', '--type', 'fixed', '--issue', 'abc'], '- x\n').status).not.toBe(0);
      expect(fragments(dir)).toEqual([]);
    } finally { cleanup(dir); }
  });

  it('refuses where the changelog is not converted (no changelog.d/README.md)', () => {
    const { dir } = convertedRepo();
    try {
      unlinkSync(path.join(dir, 'changelog.d', 'README.md'));
      const r = run(dir, ['new', '--type', 'fixed'], '- x\n');
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/README\.md/);
    } finally { cleanup(dir); }
  });

  it('never reuses a name: twenty entries from one branch are twenty files', () => {
    const { dir } = convertedRepo();
    try {
      for (let i = 0; i < 20; i++) expect(run(dir, ['new', '--type', 'fixed', '--name', 'same'], `- entry ${i}\n`).status).toBe(0);
      expect(new Set(fragments(dir)).size).toBe(20);
    } finally { cleanup(dir); }
  });

  it('two branches that each add an entry merge without a conflict', () => {
    const { dir, base } = convertedRepo();
    try {
      git(dir, 'checkout', '-q', '-b', 'fleet/one', base);
      expect(run(dir, ['new', '--type', 'fixed'], '- one\n').status).toBe(0);
      commitAll(dir, 'one');
      git(dir, 'checkout', '-q', '-b', 'fleet/two', base);
      expect(run(dir, ['new', '--type', 'fixed'], '- two\n').status).toBe(0);
      commitAll(dir, 'two');
      const merge = spawnSync('git', ['merge-tree', '--write-tree', 'fleet/one', 'fleet/two'], { cwd: dir, env: gitFreeEnv() });
      expect(merge.status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R1: every file in changelog.d is a valid fragment', () => {
  const bad: Array<[string, string, string]> = [
    ['a file name without the hex suffix', 'fix.md', fragment('fixed', '- x')],
    ['an uppercase file name', 'Fix-abc123.md', fragment('fixed', '- x')],
    ['a non-markdown file', 'notes-abc123.txt', fragment('fixed', '- x')],
    ['no front-matter', 'x-abc123.md', '- x\n'],
    ['an unknown key', 'x-abc123.md', fragment('fixed', '- x', ['scope: cli'])],
    ['a duplicate key', 'x-abc123.md', fragment('fixed', '- x', ['type: added'])],
    ['a missing type', 'x-abc123.md', '---\nissue: 4\n---\n- x\n'],
    ['an unknown type', 'x-abc123.md', fragment('bugfix', '- x')],
    ['a non-numeric issue', 'x-abc123.md', fragment('fixed', '- x', ['issue: #4'])],
    ['a non-boolean breaking', 'x-abc123.md', fragment('fixed', '- x', ['breaking: yes'])],
    ['an empty entry', 'x-abc123.md', fragment('fixed', '')],
    ['CRLF line endings', 'x-abc123.md', fragment('fixed', '- x').replace(/\n/g, '\r\n')],
    ['a level 3 heading', 'x-abc123.md', fragment('fixed', '### A title\n\n- x')],
    ['a level 1 heading after a closed fence', 'x-abc123.md', fragment('fixed', '```sh\n# comment\n```\n# Title')],
    ['a setext heading', 'x-abc123.md', fragment('fixed', 'A title\n=====')],
    ['invalid UTF-8', 'x-abc123.md', '---\ntype: fixed\n---\n- \u0000'],
  ];

  for (const [what, name, text] of bad) {
    it(`fails on ${what}`, () => {
      const { dir } = convertedRepo();
      try {
        if (what === 'invalid UTF-8') writeFileSync(path.join(dir, 'changelog.d', name), Buffer.from([0x2d, 0x2d, 0x2d, 0x0a, 0x74, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x66, 0x69, 0x78, 0x65, 0x64, 0x0a, 0x2d, 0x2d, 0x2d, 0x0a, 0x2d, 0x20, 0xff, 0xfe, 0x0a]));
        else write(dir, `changelog.d/${name}`, text);
        const r = run(dir, ['check']);
        expect(r.status, `check passed on ${what}`).not.toBe(0);
        expect(r.stderr).toContain(name);
      } finally { cleanup(dir); }
    });
  }

  it('fails on a subdirectory inside changelog.d', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'changelog.d/nested/x-abc123.md', fragment('fixed', '- x'));
      expect(run(dir, ['check']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes a #### title, a short bullet, a paragraph, and # lines inside a fence', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'changelog.d/long-form-abc123.md', fragment('fixed', '#### A title (#9)\n\n- detail\n\n```sh\n# shell comment\n## another\n```\n\n~~~\n# tilde fence\n~~~', ['issue: 9']));
      write(dir, 'changelog.d/short-def456.md', fragment('added', '- a short entry (#10).', ['issue: 10', 'breaking: false']));
      write(dir, 'changelog.d/para-0a1b2c.md', fragment('known-issue', 'A paragraph entry.'));
      const r = run(dir, ['check']);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('a README-only changelog.d passes', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['check']).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R2: the Unreleased block holds no entries', () => {
  it('fails on a list item under ## [Unreleased]', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', CONVERTED.replace(POINTER, `${POINTER}\n\n- a stray entry`));
      const r = run(dir, ['check']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/Unreleased/);
    } finally { cleanup(dir); }
  });

  it('fails on a heading under ## [Unreleased]', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', CONVERTED.replace(POINTER, `${POINTER}\n\n### Fixed`));
      expect(run(dir, ['check']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when ## [Unreleased] is missing', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', CONVERTED.replace(`## [Unreleased]\n\n${POINTER}\n\n`, ''));
      expect(run(dir, ['check']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes the pointer paragraph alone', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['check']).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R3: CHANGELOG.md changes only by assembly or by amendment', () => {
  const two = {
    'a-111111.md': fragment('fixed', '- fix a (#5)', ['issue: 5']),
    'b-222222.md': fragment('added', '#### New thing (#3)\n\nIt does a thing.', ['issue: 3']),
  };

  it('(a) passes a release commit that assembles every fragment', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      bumpPackage(dir, '0.5.1');
      expect(run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']).status).toBe(0);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('(a) fails when the assembled text is edited after release', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      bumpPackage(dir, '0.5.1');
      run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('fix a', 'fix A'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(a) fails when a consumed fragment is left behind', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      bumpPackage(dir, '0.5.1');
      run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      write(dir, 'changelog.d/a-111111.md', two['a-111111.md']);
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(a) fails when a fragment is added in the release change', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      bumpPackage(dir, '0.5.1');
      run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      write(dir, 'changelog.d/c-333333.md', fragment('fixed', '- late'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(a) fails when the package.json beside the changelog carries another version', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      bumpPackage(dir, '0.5.2');
      run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/package\.json/);
    } finally { cleanup(dir); }
  });

  it('(a) fails when the assembly breaks the bump rules', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('removed', '- gone') });
    try {
      bumpPackage(dir, '0.5.1');
      // Hand-assembled: `release` itself refuses this bump.
      const text = read(dir, 'CHANGELOG.md').replace('## [0.5.0]', '## [0.5.1] - 2026-02-01\n\n### Removed\n\n- gone\n\n## [0.5.0]');
      write(dir, 'CHANGELOG.md', text);
      unlinkSync(path.join(dir, 'changelog.d', 'a-111111.md'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(b) passes an amendment to a released section', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'an old fix, corrected (#1)'));
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('(b) fails when the amendment also changes the text above the newest release', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'amended (#1)').replace('Notable changes.', 'Changes.'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(b) fails when the amendment also changes a fragment', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'amended (#1)'));
      write(dir, 'changelog.d/a-111111.md', fragment('fixed', '- fix a, reworded (#5)', ['issue: 5']));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('(b) fails when the amendment changes the list of release versions', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('## [0.5.0] - 2026-01-10', '## [0.4.9] - 2026-01-10'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes a change that only adds a fragment', () => {
    const { dir, base } = repoWithFragments(two);
    try {
      write(dir, 'changelog.d/c-333333.md', fragment('fixed', '- another'));
      expect(run(dir, ['check', '--base', base]).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R3(c): a rewording of the preamble or the pointer', () => {
  const REWORDED = 'The next release is assembled from the files in `changelog.d/`.';

  it('passes a rewording of the pointer paragraph alone', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, REWORDED));
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes a rewording of the preamble alone', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('Notable changes.', 'Every notable change.'));
      expect(run(dir, ['check', '--base', base]).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when the new pointer is two paragraphs', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, `${REWORDED}\n\nA second paragraph.`));
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/pointer/);
    } finally { cleanup(dir); }
  });

  it('fails when the new pointer no longer names changelog.d', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, 'Nothing here yet.'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when a release section changes with the rewording', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, REWORDED).replace('an old fix (#1)', 'an old fix (#2)'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when a fragment changes with the rewording', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, REWORDED));
      write(dir, 'changelog.d/a-111111.md', fragment('fixed', '- y'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R3(d): the import of a release cut on another branch', () => {
  const S051 = '## [0.5.1] - 2026-02-01\n\n### Fixed\n\n- a patch fix cut on the release branch (#8)\n\n';
  const OLDER = '## [0.4.0] - 2025-12-01\n\n### Fixed\n\n- an older fix (#0)\n';
  const S041 = '## [0.4.1] - 2025-12-15\n\n### Fixed\n\n- a patch on the 0.4 line (#6)\n\n';

  /**
   * A converted repository whose main is at B, and a tag cut on a release branch
   * from B whose CHANGELOG.md carries `section` inserted above `above`.
   */
  function taggedRepo(opts: { tag: string; section: string; above: string; changelog?: string; sub?: string }): { dir: string; base: string } {
    const sub = opts.sub ?? '';
    const dir = mkdtempSync(path.join(tmpdir(), 'hma-changelog-import-'));
    initThrowawayRepo(dir);
    const cl = opts.changelog ?? CONVERTED;
    write(dir, `${sub}CHANGELOG.md`, cl);
    write(dir, `${sub}changelog.d/README.md`, 'Add an entry with `node scripts/changelog.mjs new`.\n');
    write(dir, `${sub}changelog.d/main-entry-abcdef.md`, fragment('fixed', '- an entry waiting on main'));
    write(dir, `${sub}package.json`, JSON.stringify({ name: 'fx', version: '0.5.0' }, null, 2) + '\n');
    const base = commitAll(dir, 'main');
    git(dir, 'checkout', '-q', '-b', 'release/cut', base);
    write(dir, `${sub}CHANGELOG.md`, cl.replace(opts.above, opts.section + opts.above));
    commitAll(dir, 'release cut');
    git(dir, 'tag', opts.tag);
    git(dir, 'checkout', '-q', '-b', 'work', base);
    return { dir, base };
  }

  const importInto = (dir: string, section: string, above: string, rel = 'CHANGELOG.md') =>
    write(dir, rel, read(dir, rel).replace(above, section + above));

  it('passes the byte-identical section of the release tag, placed above the newest release', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      importInto(dir, S051, RELEASED);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes a section imported between two older releases, in descending order', () => {
    const cl = CONVERTED + '\n' + OLDER;
    const { dir, base } = taggedRepo({ tag: 'v0.4.1', section: S041, above: OLDER, changelog: cl });
    try {
      importInto(dir, S041, OLDER);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('fetches the tag from origin when it is not present locally', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    const origin = mkdtempSync(path.join(tmpdir(), 'hma-changelog-origin-'));
    try {
      execFileSync('git', ['init', '-q', '--bare', origin], { env: gitFreeEnv() });
      git(dir, 'push', '-q', origin, 'refs/tags/v0.5.1');
      git(dir, 'tag', '-d', 'v0.5.1');
      git(dir, 'remote', 'add', 'origin', origin);
      importInto(dir, S051, RELEASED);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
      expect(git(dir, 'tag', '--list', 'v0.5.1')).toBe('v0.5.1');
    } finally { cleanup(dir); cleanup(origin); }
  });

  it('fails on a one-byte edit of the imported section', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      importInto(dir, S051.replace('patch fix', 'patch fiX'), RELEASED);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/v0\.5\.1/);
    } finally { cleanup(dir); }
  });

  it('fails closed when the tag does not exist', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      git(dir, 'tag', '-d', 'v0.5.1');
      importInto(dir, S051, RELEASED);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/tag v0\.5\.1 does not exist/);
    } finally { cleanup(dir); }
  });

  it('fails when the imported section breaks the descending order', () => {
    const cl = CONVERTED + '\n' + OLDER;
    const { dir, base } = taggedRepo({ tag: 'v0.4.1', section: S041, above: OLDER, changelog: cl });
    try {
      importInto(dir, S041, RELEASED);
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when the pointer also changes', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      importInto(dir, S051, RELEASED);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace(POINTER, 'The next release is assembled from `changelog.d/`.'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when another release section also changes', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      importInto(dir, S051, RELEASED);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'an old fix (#2)'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when a fragment also changes', () => {
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: S051, above: RELEASED });
    try {
      importInto(dir, S051, RELEASED);
      unlinkSync(path.join(dir, 'changelog.d', 'main-entry-abcdef.md'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when the imported heading carries a placeholder date', () => {
    const placeholder = S051.replace('2026-02-01', 'YYYY-MM-DD');
    const { dir, base } = taggedRepo({ tag: 'v0.5.1', section: placeholder, above: RELEASED });
    try {
      importInto(dir, placeholder, RELEASED);
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('uses --tag-prefix for a changelog whose tags carry a package prefix', () => {
    const { dir, base } = taggedRepo({ tag: 'pkg-v0.5.1', section: S051, above: RELEASED, sub: 'pkg/' });
    try {
      importInto(dir, S051, RELEASED, 'pkg/CHANGELOG.md');
      const without = run(dir, ['check', '--base', base]);
      expect(without.status, 'the import passed against a v0.5.1 tag that does not exist').not.toBe(0);
      const r = run(dir, ['check', '--base', base, '--tag-prefix', 'pkg-v']);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R4: a version bump always assembles', () => {
  it('fails a package.json version change with no assembly', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      bumpPackage(dir, '0.5.1');
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/version/);
    } finally { cleanup(dir); }
  });

  it('passes a package.json change that leaves the version alone', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'package.json', JSON.stringify({ name: 'fx', version: '0.5.0', description: 'd' }, null, 2) + '\n');
      expect(run(dir, ['check', '--base', base]).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('check R5: a change to the script lands alone', () => {
  it('fails a script change that also changes CHANGELOG.md', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'scripts/changelog.mjs', read(dir, 'scripts/changelog.mjs') + '\n// tweak\n');
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'amended (#1)'));
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/changelog\.mjs/);
    } finally { cleanup(dir); }
  });

  it('fails a script change that deletes a fragment', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'scripts/changelog.mjs', read(dir, 'scripts/changelog.mjs') + '\n// tweak\n');
      unlinkSync(path.join(dir, 'changelog.d', 'a-111111.md'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes a script change alone', () => {
    const { dir, base } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      write(dir, 'scripts/changelog.mjs', read(dir, 'scripts/changelog.mjs') + '\n// tweak\n');
      expect(run(dir, ['check', '--base', base]).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

const LEGACY = [
  '# Changelog',
  '',
  'Notable changes.',
  '',
  '## [Unreleased]',
  '',
  'A lead paragraph with no heading.',
  '',
  '### `scan-text` scans one text (#12)',
  '',
  '- **New command.** It reads a file.',
  '  A continuation line.',
  '',
  '```sh',
  '# a shell comment inside a fence',
  '```',
  '',
  '### Breaking: check carries the full shape',
  '',
  'A paragraph about the break (#40).',
  '',
  '## [0.6.0] - YYYY-MM-DD',
  '',
  '### Fixed',
  '',
  '- a placeholder-dated fix (#7)',
  '- a second fix',
  '',
  RELEASED,
].join('\n');

function legacyRepo(): { dir: string; base: string } {
  const dir = mkdtempSync(path.join(tmpdir(), 'hma-changelog-legacy-'));
  initThrowawayRepo(dir);
  write(dir, 'CHANGELOG.md', LEGACY);
  write(dir, 'package.json', JSON.stringify({ name: 'fx', version: '0.5.0' }, null, 2) + '\n');
  const base = commitAll(dir, 'legacy base');
  git(dir, 'checkout', '-q', '-b', 'chore/convert');
  write(dir, 'scripts/changelog.mjs', readFileSync(SCRIPT, 'utf8'));
  write(dir, 'changelog.d/README.md', 'Add an entry with `node scripts/changelog.mjs new`.\n');
  return { dir, base };
}

describe('convert --legacy', () => {
  it('moves the undated region into fragments and leaves the pointer', () => {
    const { dir } = legacyRepo();
    try {
      const r = run(dir, ['convert', '--legacy', '--type', 'changed']);
      expect(r.status, r.stderr).toBe(0);
      const names = fragments(dir);
      expect(names).toHaveLength(4);
      const texts = names.map(n => read(dir, `changelog.d/${n}`));
      const scan = texts.find(t => t.includes('scan-text'))!;
      expect(scan).toBe('---\ntype: changed\nissue: 12\n---\n#### `scan-text` scans one text (#12)\n\n- **New command.** It reads a file.\n  A continuation line.\n\n```sh\n# a shell comment inside a fence\n```\n');
      expect(texts.find(t => t.includes('placeholder-dated'))).toMatch(/^---\ntype: fixed\n---\n- a placeholder-dated fix \(#7\)\n- a second fix\n$/);
      expect(texts.find(t => t.includes('lead paragraph'))).toBe('---\ntype: changed\n---\nA lead paragraph with no heading.\n');
      const cl = read(dir, 'CHANGELOG.md');
      expect(cl.startsWith('# Changelog\n\nNotable changes.\n\n## [Unreleased]\n\n')).toBe(true);
      expect(cl).not.toContain('YYYY-MM-DD');
      expect(cl.endsWith(RELEASED)).toBe(true);
      expect(cl.slice(cl.indexOf('## [Unreleased]') + '## [Unreleased]'.length, cl.indexOf('## [0.5.0]'))).not.toMatch(/^(- |#)/m);
      for (const n of names) expect(n).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{6}\.md$/);
    } finally { cleanup(dir); }
  });

  it('refuses an untyped entry without --type and writes nothing', () => {
    const { dir } = legacyRepo();
    try {
      const r = run(dir, ['convert', '--legacy']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/--type/);
      expect(fragments(dir)).toEqual([]);
      expect(read(dir, 'CHANGELOG.md')).toBe(LEGACY);
    } finally { cleanup(dir); }
  });
});

describe('check R6: the conversion change preserves every entry line', () => {
  it('passes the output of convert --legacy', () => {
    const { dir, base } = legacyRepo();
    try {
      expect(run(dir, ['convert', '--legacy', '--type', 'changed']).status).toBe(0);
      const r = run(dir, ['check', '--base', base]);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes with fragment types edited by hand after conversion', () => {
    const { dir, base } = legacyRepo();
    try {
      run(dir, ['convert', '--legacy', '--type', 'changed']);
      const scan = fragments(dir).find(n => read(dir, `changelog.d/${n}`).includes('scan-text'))!;
      write(dir, `changelog.d/${scan}`, read(dir, `changelog.d/${scan}`).replace('type: changed', 'type: added'));
      expect(run(dir, ['check', '--base', base]).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when a fragment drops a line', () => {
    const { dir, base } = legacyRepo();
    try {
      run(dir, ['convert', '--legacy', '--type', 'changed']);
      const scan = fragments(dir).find(n => read(dir, `changelog.d/${n}`).includes('scan-text'))!;
      write(dir, `changelog.d/${scan}`, read(dir, `changelog.d/${scan}`).replace('  A continuation line.\n', ''));
      const r = run(dir, ['check', '--base', base]);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/A continuation line/);
    } finally { cleanup(dir); }
  });

  it('fails when a fragment rewords a line', () => {
    const { dir, base } = legacyRepo();
    try {
      run(dir, ['convert', '--legacy', '--type', 'changed']);
      const lead = fragments(dir).find(n => read(dir, `changelog.d/${n}`).includes('lead paragraph'))!;
      write(dir, `changelog.d/${lead}`, read(dir, `changelog.d/${lead}`).replace('lead paragraph', 'leading paragraph'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when a released section changes in the conversion', () => {
    const { dir, base } = legacyRepo();
    try {
      run(dir, ['convert', '--legacy', '--type', 'changed']);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('an old fix (#1)', 'an old fix (#2)'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when the Unreleased block is more than the pointer', () => {
    const { dir, base } = legacyRepo();
    try {
      run(dir, ['convert', '--legacy', '--type', 'changed']);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('## [0.5.0]', 'A second paragraph.\n\n## [0.5.0]'));
      expect(run(dir, ['check', '--base', base]).status).not.toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('preview', () => {
  const set = {
    'z-aaaaaa.md': fragment('fixed', '- no issue fix'),
    'b-bbbbbb.md': fragment('fixed', '- fix nine (#9)', ['issue: 9']),
    'a-cccccc.md': fragment('fixed', '- fix nine, second by name (#9)', ['issue: 9, 20']),
    'c-dddddd.md': fragment('fixed', '- fix two (#2)', ['issue: 30, 2']),
    'k-eeeeee.md': fragment('known-issue', 'A known issue paragraph.'),
    'n-ffffff.md': fragment('added', '#### New (#4)\n\nBody.', ['issue: 4']),
    's-0a0a0a.md': fragment('security', '- tightened'),
  };
  const SECTION = [
    '## [0.6.0] - 2026-03-01',
    '',
    '### Added',
    '',
    '#### New (#4)',
    '',
    'Body.',
    '',
    '### Fixed',
    '',
    '- fix two (#2)',
    '',
    '- fix nine, second by name (#9)',
    '',
    '- fix nine (#9)',
    '',
    '- no issue fix',
    '',
    '### Security',
    '',
    '- tightened',
    '',
    '### Known issues',
    '',
    'A known issue paragraph.',
    '',
  ].join('\n');

  it('--version --date prints the section in type order, issue order, one blank line after each entry', () => {
    const { dir } = repoWithFragments(set);
    try {
      const r = run(dir, ['preview', '--version', '0.6.0', '--date', '2026-03-01']);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toBe(SECTION);
    } finally { cleanup(dir); }
  });

  it('--virtual prints the whole file with the fragments inside ## [Unreleased]', () => {
    const { dir } = repoWithFragments(set);
    try {
      const r = run(dir, ['preview', '--virtual']);
      expect(r.status, r.stderr).toBe(0);
      const groups = SECTION.split('\n').slice(2).join('\n');
      expect(r.stdout).toBe(CONVERTED.replace(RELEASED, groups + '\n' + RELEASED));
      expect(read(dir, 'CHANGELOG.md')).toBe(CONVERTED);
    } finally { cleanup(dir); }
  });

  it('--virtual with no fragments prints the file unchanged', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['preview', '--virtual']).stdout).toBe(CONVERTED);
    } finally { cleanup(dir); }
  });

  it('--virtual never applies the release refusals: zero fragments and a stray entry still print, exit 0', () => {
    const { dir } = convertedRepo();
    try {
      const stray = CONVERTED.replace(POINTER, `${POINTER}\n\n- a stray entry`);
      write(dir, 'CHANGELOG.md', stray);
      const r = run(dir, ['preview', '--virtual']);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toBe(stray);
    } finally { cleanup(dir); }
  });

  it('--virtual with a breaking fragment needs no version and exits 0', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('removed', '- gone', ['breaking: true']) });
    try {
      const r = run(dir, ['preview', '--virtual']);
      expect(r.status, r.stderr).toBe(0);
      expect(r.stdout).toContain('### Removed\n\n- gone\n');
    } finally { cleanup(dir); }
  });
});

describe('release', () => {
  it('writes the section below the Unreleased block and deletes the fragments it consumed', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- fix (#5)', ['issue: 5']) });
    try {
      const r = run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      expect(r.status, r.stderr).toBe(0);
      expect(read(dir, 'CHANGELOG.md')).toBe(CONVERTED.replace(RELEASED, '## [0.5.1] - 2026-02-01\n\n### Fixed\n\n- fix (#5)\n\n' + RELEASED));
      expect(fragments(dir)).toEqual([]);
      expect(existsSync(path.join(dir, 'changelog.d', 'README.md'))).toBe(true);
    } finally { cleanup(dir); }
  });

  it('defaults the date to today in UTC', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- fix') });
    try {
      expect(run(dir, ['release', '--version', '0.5.1']).status).toBe(0);
      expect(read(dir, 'CHANGELOG.md')).toContain(`## [0.5.1] - ${new Date().toISOString().slice(0, 10)}\n`);
    } finally { cleanup(dir); }
  });

  const refusals: Array<[string, Record<string, string>, string[], string?]> = [
    ['no fragments', {}, ['--version', '0.5.1', '--date', '2026-02-01']],
    ['a version equal to the newest', { 'a-111111.md': fragment('fixed', '- x') }, ['--version', '0.5.0', '--date', '2026-02-01']],
    ['a version below the newest', { 'a-111111.md': fragment('fixed', '- x') }, ['--version', '0.4.9', '--date', '2026-02-01']],
    ['a non-semver version', { 'a-111111.md': fragment('fixed', '- x') }, ['--version', '0.6', '--date', '2026-02-01']],
    ['a missing version', { 'a-111111.md': fragment('fixed', '- x') }, ['--date', '2026-02-01']],
    ['a placeholder date', { 'a-111111.md': fragment('fixed', '- x') }, ['--version', '0.5.1', '--date', 'YYYY-MM-DD']],
    ['an impossible date', { 'a-111111.md': fragment('fixed', '- x') }, ['--version', '0.5.1', '--date', '2026-02-30']],
    ['breaking on a patch bump', { 'a-111111.md': fragment('changed', '- x', ['breaking: true']) }, ['--version', '0.5.1', '--date', '2026-02-01']],
    ['removed on a patch bump', { 'a-111111.md': fragment('removed', '- x') }, ['--version', '0.5.1', '--date', '2026-02-01']],
    ['breaking below 1.0.0 without a minor rise', { 'a-111111.md': fragment('changed', '- x', ['breaking: true']) }, ['--version', '0.5.9', '--date', '2026-02-01']],
    ['breaking from 1.0.0 without a major rise', { 'a-111111.md': fragment('changed', '- x', ['breaking: true']) }, ['--version', '1.3.0', '--date', '2026-02-01'], '1.2.0'],
    ['removed from 1.0.0 without a major rise', { 'a-111111.md': fragment('removed', '- x') }, ['--version', '1.2.1', '--date', '2026-02-01'], '1.2.0'],
  ];

  for (const [what, files, args, version] of refusals) {
    it(`refuses ${what} and changes nothing`, () => {
      const { dir } = repoWithFragments(files, version);
      try {
        const before = read(dir, 'CHANGELOG.md');
        const count = fragments(dir).length;
        const r = run(dir, ['release', ...args]);
        expect(r.status, `release accepted ${what}`).not.toBe(0);
        expect(read(dir, 'CHANGELOG.md')).toBe(before);
        expect(fragments(dir)).toHaveLength(count);
      } finally { cleanup(dir); }
    });
  }

  it('accepts breaking below 1.0.0 with a minor rise', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('changed', '- x', ['breaking: true']) });
    try {
      expect(run(dir, ['release', '--version', '0.6.0', '--date', '2026-02-01']).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('accepts removed from 1.0.0 with a major rise', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('removed', '- x') }, '1.2.0');
    try {
      expect(run(dir, ['release', '--version', '2.0.0', '--date', '2026-02-01']).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('refuses when a fragment is invalid', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('fixed', '### Heading') });
    try {
      expect(run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('verify-release', () => {
  it('passes after release for the released version', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      run(dir, ['release', '--version', '0.5.1', '--date', '2026-02-01']);
      const r = run(dir, ['verify-release', '--version', '0.5.1']);
      expect(r.status, r.stderr).toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when fragments remain', () => {
    const { dir } = repoWithFragments({ 'a-111111.md': fragment('fixed', '- x') });
    try {
      const r = run(dir, ['verify-release', '--version', '0.5.0']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/fragment/);
    } finally { cleanup(dir); }
  });

  it('fails when the newest release heading is another version', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['verify-release', '--version', '0.5.1']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('fails when the newest release heading carries a placeholder date', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'CHANGELOG.md', CONVERTED.replace('## [0.5.0] - 2026-01-10', '## [0.5.0] - YYYY-MM-DD'));
      expect(run(dir, ['verify-release', '--version', '0.5.0']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('passes for the newest heading with no fragments', () => {
    const { dir } = convertedRepo();
    try {
      expect(run(dir, ['verify-release', '--version', '0.5.0']).status).toBe(0);
    } finally { cleanup(dir); }
  });
});

describe('convert: a branch moves its CHANGELOG.md additions into fragments', () => {
  const OLD = [
    '# Changelog',
    '',
    '## [Unreleased]',
    '',
    '### Fixed',
    '',
    '- an existing unreleased fix',
    '',
    RELEASED,
  ].join('\n');

  function branchRepo(): { dir: string; base: string } {
    const dir = mkdtempSync(path.join(tmpdir(), 'hma-changelog-convert-'));
    initThrowawayRepo(dir);
    write(dir, 'CHANGELOG.md', OLD);
    const base = commitAll(dir, 'old main');
    git(dir, 'branch', '-q', '-M', 'main');
    git(dir, 'checkout', '-q', '-b', 'fleet/hma-761-scoped');
    return { dir, base };
  }

  it('turns an added bullet under ### Fixed and an added ### title into fragments, and resets CHANGELOG.md to the merge base', () => {
    const { dir } = branchRepo();
    try {
      write(dir, 'CHANGELOG.md', OLD
        .replace('- an existing unreleased fix\n', '- an existing unreleased fix\n- a new fix (#761)\n')
        .replace('## [Unreleased]\n\n', '## [Unreleased]\n\n### A new title (#762)\n\nThe body.\n\n'));
      commitAll(dir, 'branch work');
      const r = run(dir, ['convert', '--base', 'main', '--type', 'added']);
      expect(r.status, r.stderr).toBe(0);
      expect(read(dir, 'CHANGELOG.md')).toBe(OLD);
      const names = fragments(dir);
      expect(names).toHaveLength(2);
      for (const n of names) expect(n).toMatch(/^hma-761-scoped-[0-9a-f]{6}\.md$/);
      for (const n of names) expect(r.stdout).toContain(path.join('changelog.d', n));
      const texts = names.map(n => read(dir, `changelog.d/${n}`)).sort();
      expect(texts).toEqual([
        '---\ntype: added\nissue: 762\n---\n#### A new title (#762)\n\nThe body.\n',
        '---\ntype: fixed\n---\n- a new fix (#761)\n',
      ]);
    } finally { cleanup(dir); }
  });

  it('refuses a hunk that edits an existing line, and writes nothing', () => {
    const { dir } = branchRepo();
    try {
      const edited = OLD.replace('- an existing unreleased fix', '- an existing unreleased fix, reworded');
      write(dir, 'CHANGELOG.md', edited);
      commitAll(dir, 'edit');
      const r = run(dir, ['convert', '--base', 'main', '--type', 'fixed']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/refus/);
      expect(read(dir, 'CHANGELOG.md')).toBe(edited);
      expect(fragments(dir)).toEqual([]);
    } finally { cleanup(dir); }
  });

  it('refuses a hunk that deletes a line', () => {
    const { dir } = branchRepo();
    try {
      write(dir, 'CHANGELOG.md', OLD.replace('- an existing unreleased fix\n', ''));
      commitAll(dir, 'delete');
      expect(run(dir, ['convert', '--base', 'main', '--type', 'fixed']).status).not.toBe(0);
    } finally { cleanup(dir); }
  });

  it('refuses a line added under a dated heading', () => {
    const { dir } = branchRepo();
    try {
      write(dir, 'CHANGELOG.md', OLD.replace('- an old fix (#1)\n', '- an old fix (#1)\n- sneaked into a release\n'));
      commitAll(dir, 'dated add');
      const r = run(dir, ['convert', '--base', 'main', '--type', 'fixed']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/0\.5\.0/);
      expect(fragments(dir)).toEqual([]);
    } finally { cleanup(dir); }
  });

  it('refuses an addition with no enclosing type heading when --type is absent', () => {
    const { dir } = branchRepo();
    try {
      write(dir, 'CHANGELOG.md', OLD.replace('## [Unreleased]\n\n', '## [Unreleased]\n\n### A new title\n\nBody.\n\n'));
      commitAll(dir, 'untyped');
      const r = run(dir, ['convert', '--base', 'main']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/--type/);
      expect(fragments(dir)).toEqual([]);
    } finally { cleanup(dir); }
  });

  it('a branch with no CHANGELOG.md additions converts nothing and exits 0', () => {
    const { dir } = branchRepo();
    try {
      write(dir, 'src.txt', 'code\n');
      commitAll(dir, 'code only');
      const r = run(dir, ['convert', '--base', 'main', '--type', 'fixed']);
      expect(r.status, r.stderr).toBe(0);
      expect(fragments(dir)).toEqual([]);
    } finally { cleanup(dir); }
  });
});

describe('usage', () => {
  it('an unknown command exits non-zero with a usage line', () => {
    const { dir } = convertedRepo();
    try {
      const r = run(dir, ['frobnicate']);
      expect(r.status).not.toBe(0);
      expect(r.stderr).toMatch(/usage/i);
    } finally { cleanup(dir); }
  });
});

/**
 * The "Changelog fragments" step of .github/workflows/test-matrix.yml, lifted
 * from the committed workflow and run with bash the way the runner runs it,
 * against throwaway repositories. It chooses the base, chooses which copy of
 * the script judges, and enforces R5 itself when the script under change is
 * the judge.
 */
describe('CI step: base selection and R5 live in the workflow, not in the script under change', () => {
  const STEP = (() => {
    const wf = yaml.load(readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'test-matrix.yml'), 'utf8')) as {
      jobs: { test: { steps: Array<{ name?: string; run?: string }> } };
    };
    const step = wf.jobs.test.steps.find(s => s.name === 'Changelog fragments');
    if (!step?.run) throw new Error('no "Changelog fragments" step in test-matrix.yml');
    return step.run;
  })();

  /** A script that accepts anything: what a change to the judge could ship. */
  const PERMISSIVE = 'process.exit(0);\n';

  function ciStep(dir: string, event: string, extra: Record<string, string> = {}): Run {
    const runnerTemp = mkdtempSync(path.join(tmpdir(), 'hma-changelog-runner-'));
    try {
      const env = {
        ...gitFreeEnv(),
        PATH: `${path.dirname(process.execPath)}${path.delimiter}${process.env.PATH ?? ''}`,
        EVENT: event,
        BEFORE: '',
        MERGE_GROUP_BASE: '',
        GITHUB_SHA: git(dir, 'rev-parse', 'HEAD'),
        RUNNER_TEMP: runnerTemp,
        ...extra,
      };
      const r = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', '-c', STEP], { cwd: dir, env, encoding: 'utf8' });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr };
    } finally { rmSync(runnerTemp, { recursive: true, force: true }); }
  }

  /** Commit the working tree on `work`, then check out the merge of `work` into B, as a pull request runs. */
  function mergeCommit(dir: string, base: string): void {
    commitAll(dir, 'head');
    git(dir, 'checkout', '-q', '--detach', base);
    git(dir, 'merge', '-q', '--no-ff', '--no-edit', 'work');
  }

  const out = (r: Run) => r.stdout + r.stderr;

  it('pull_request, script unchanged: a fragment add passes, judged by the base copy', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'changelog.d/fix-abc123.md', fragment('fixed', '- a fix'));
      mergeCommit(dir, base);
      const r = ciStep(dir, 'pull_request');
      expect(r.status, out(r)).toBe(0);
    } finally { cleanup(dir); }
  });

  it('pull_request: a head that is not the two-parent merge commit fails closed', () => {
    const { dir } = convertedRepo();
    try {
      write(dir, 'changelog.d/fix-abc123.md', fragment('fixed', '- a fix'));
      commitAll(dir, 'head');
      const r = ciStep(dir, 'pull_request');
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/expected the pull-request merge commit/);
    } finally { cleanup(dir); }
  });

  it('R5 in the workflow: a script change that also changes CHANGELOG.md fails, even when the new script accepts everything', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'scripts/changelog.mjs', PERMISSIVE);
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('Notable changes.', 'Notable changes, reworded.'));
      mergeCommit(dir, base);
      const r = ciStep(dir, 'pull_request');
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/R5: scripts\/changelog\.mjs changed/);
      expect(out(r)).toMatch(/M\tCHANGELOG\.md/);
    } finally { cleanup(dir); }
  });

  for (const [what, mutate, shown] of [
    ['modified', (d: string) => write(d, 'changelog.d/old-fix-abc123.md', fragment('changed', '- an old fix')), /M\tchangelog\.d\/old-fix-abc123\.md/],
    ['deleted', (d: string) => unlinkSync(path.join(d, 'changelog.d/old-fix-abc123.md')), /D\tchangelog\.d\/old-fix-abc123\.md/],
    ['renamed', (d: string) => git(d, 'mv', 'changelog.d/old-fix-abc123.md', 'changelog.d/new-fix-def456.md'), /R\d*\tchangelog\.d\/old-fix-abc123\.md\tchangelog\.d\/new-fix-def456\.md/],
    ['renamed out of changelog.d', (d: string) => git(d, 'mv', 'changelog.d/old-fix-abc123.md', 'docs/old-fix.md'), /R\d*\tchangelog\.d\/old-fix-abc123\.md\tdocs\/old-fix\.md/],
  ] as const) {
    it(`R5 in the workflow: a script change with a fragment ${what} fails, even when the new script accepts everything`, () => {
      const { dir, base } = repoWithFragments({ 'old-fix-abc123.md': fragment('fixed', '- an old fix') });
      try {
        mkdirSync(path.join(dir, 'docs'), { recursive: true });
        write(dir, 'scripts/changelog.mjs', PERMISSIVE);
        mutate(dir);
        mergeCommit(dir, base);
        const r = ciStep(dir, 'pull_request');
        expect(r.status).toBe(1);
        expect(out(r)).toMatch(/R5: scripts\/changelog\.mjs changed/);
        expect(out(r)).toMatch(shown);
      } finally { cleanup(dir); }
    });
  }

  it('R5 in the workflow admits a script change with a fragment add or an edit of changelog.d/README.md', () => {
    const { dir, base } = convertedRepo();
    try {
      write(dir, 'scripts/changelog.mjs', PERMISSIVE);
      write(dir, 'changelog.d/README.md', read(dir, 'changelog.d/README.md') + 'One more line.\n');
      write(dir, 'changelog.d/fix-abc123.md', fragment('fixed', '- a fix'));
      mergeCommit(dir, base);
      const r = ciStep(dir, 'pull_request');
      expect(r.status, out(r)).toBe(0);
    } finally { cleanup(dir); }
  });

  /** A repository whose origin is itself, with main at B, so a manual run can fetch main. */
  function dispatchRepo(): { dir: string; base: string } {
    const { dir, base } = convertedRepo();
    git(dir, 'branch', '-f', 'main', base);
    git(dir, 'remote', 'add', 'origin', dir);
    return { dir, base };
  }

  it('workflow_dispatch is judged against its merge base with main: a version bump without assembly fails', () => {
    const { dir } = dispatchRepo();
    try {
      bumpPackage(dir, '0.5.1');
      commitAll(dir, 'head');
      const r = ciStep(dir, 'workflow_dispatch');
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/R4: package\.json version changed/);
    } finally { cleanup(dir); }
  });

  it('workflow_dispatch passes a head that only adds a fragment', () => {
    const { dir } = dispatchRepo();
    try {
      write(dir, 'changelog.d/fix-abc123.md', fragment('fixed', '- a fix'));
      commitAll(dir, 'head');
      const r = ciStep(dir, 'workflow_dispatch');
      expect(r.status, out(r)).toBe(0);
    } finally { cleanup(dir); }
  });

  it('workflow_dispatch applies R5 in the workflow when the head changes the script', () => {
    const { dir } = dispatchRepo();
    try {
      write(dir, 'scripts/changelog.mjs', PERMISSIVE);
      bumpPackage(dir, '0.5.1');
      write(dir, 'CHANGELOG.md', read(dir, 'CHANGELOG.md').replace('Notable changes.', 'Notable changes, reworded.'));
      commitAll(dir, 'head');
      const r = ciStep(dir, 'workflow_dispatch');
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/R5: scripts\/changelog\.mjs changed/);
    } finally { cleanup(dir); }
  });

  it('workflow_dispatch with no main to find a merge base against fails closed', () => {
    const { dir } = convertedRepo();
    try {
      commitAll(dir, 'head');
      const r = ciStep(dir, 'workflow_dispatch');
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/cannot fetch main/);
    } finally { cleanup(dir); }
  });

  it('a push event with no previous commit fails closed instead of checking without a base', () => {
    const { dir } = convertedRepo();
    try {
      const r = ciStep(dir, 'push', { BEFORE: '0000000000000000000000000000000000000000' });
      expect(r.status).toBe(1);
      expect(out(r)).toMatch(/push event without a previous commit/);
    } finally { cleanup(dir); }
  });
});

/**
 * `changelog.d/README.md` shows a captured run of `new` and lists the types
 * `--type` accepts. Both are re-derived from the script here, at every commit,
 * so the README cannot drift from what the script does: a script change that
 * alters either output turns these red, and the same change updates the README.
 */
describe('changelog.d/README.md matches the script it documents', () => {
  const README = readFileSync(path.join(REPO_ROOT, 'changelog.d', 'README.md'), 'utf8');

  /** The body of the one fenced block opened with ```<info>, without its trailing newline. */
  function fenced(info: string): string {
    const blocks = [...README.matchAll(new RegExp('^```' + info + '\\n([\\s\\S]*?)\\n```$', 'gm'))].map(m => m[1]);
    expect(blocks, `exactly one \`\`\`${info} block in changelog.d/README.md`).toHaveLength(1);
    return blocks[0];
  }

  it('the example: `new` run as the sh block shows, on the branch the label names, prints the path and writes the file shown', () => {
    const sh = fenced('sh');
    const m = /^node scripts\/changelog\.mjs (new(?: [^\s<]+)+) <<'EOF'\n([\s\S]*)\nEOF$/.exec(sh);
    expect(m, 'the sh block is `node scripts/changelog.mjs new ... <<\'EOF\'`, an entry, and `EOF`').not.toBeNull();
    const args = m![1].split(' ');
    expect(args).toContain('--type');
    expect(args).toContain('--issue');
    const entry = m![2] + '\n';

    const label = /on a branch named `([^`]+)`/.exec(README);
    expect(label, 'the capture label names the branch').not.toBeNull();
    const printed = fenced('text');
    expect(printed).toMatch(/^changelog\.d\/761-example-[0-9a-f]{6}\.md$/);
    const written = fenced('markdown') + '\n';

    const { dir } = convertedRepo();
    try {
      write(dir, 'changelog.d/README.md', README);
      commitAll(dir, 'the README as shipped');
      git(dir, 'checkout', '-q', '-b', label![1]);
      const r = run(dir, args, entry);
      expect(r.status, r.stderr).toBe(0);
      const out = r.stdout.trim();
      // The six hex characters are random on each run; everything else is the capture.
      const shape = new RegExp('^' + printed.replace(/[0-9a-f]{6}\.md$/, '').replace(/[.]/g, '\\.') + '[0-9a-f]{6}\\.md$');
      expect(out).toMatch(shape);
      expect(out).toMatch(/^changelog\.d\/761-example-[0-9a-f]{6}\.md$/);
      expect(read(dir, out)).toBe(written);
      expect(run(dir, ['check']).status).toBe(0);
    } finally { cleanup(dir); }
  });

  it('the `--type` bullet names the types the script accepts, in the order the script lists them', () => {
    const bullet = /^- `--type` is one of ([^.]*)\./m.exec(README);
    expect(bullet, 'the README has a `--type` bullet').not.toBeNull();
    const documented = [...bullet![1].matchAll(/`([^`]+)`/g)].map(x => x[1]);

    const { dir } = convertedRepo();
    try {
      const r = run(dir, ['new', '--type', 'x'], '- x\n');
      expect(r.status).not.toBe(0);
      const listed = /type "x" is not one of ([^\n]+)/.exec(r.stderr);
      expect(listed, r.stderr).not.toBeNull();
      expect(documented).toEqual(listed![1].trim().split(', '));
    } finally { cleanup(dir); }
  });
});
