/**
 * scripts/source-census.mjs — the census that reads each pinned dependency's
 * own repository advisories next to the aggregators' counts.
 *
 * The case it exists for: a pinned version inside a range its maintainers
 * published, while every aggregator still reads zero at that version. That
 * row, the unparseable-range row, and the blind-control row are each run
 * through the full census against recorded responses, so the suite needs no
 * network and pins the exit code each one must produce.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  parseRange,
  rangeContains,
  parseVersion,
  compareVersions,
  registryLine,
  pinnedDependencies,
  githubRepository,
  readUpstreamAdvisories,
  createClient,
  runCensus,
  renderText,
  HAND_READINGS,
  DEFAULT_CONTROL,
} from '../../scripts/source-census.mjs';
import { tempDir } from '../helpers/temp-dir';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'source-census.mjs');

type Advisory = {
  ghsa_id: string;
  severity?: string;
  published_at?: string;
  html_url?: string;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string } | null;
    vulnerable_version_range?: string | null;
    patched_versions?: string | null;
  }>;
};

type Pkg = {
  versions: string[];
  repository: unknown;
  /** Pages of the upstream repository's published advisories. */
  upstream?: Advisory[][];
  osv?: string[];
  githubReviewed?: string[];
  npmAudit?: string[];
  failRegistry?: boolean;
};

function adv(id: string, name: string, range: string | null, severity = 'high'): Advisory {
  return {
    ghsa_id: id,
    severity,
    published_at: '2026-09-29T00:00:00Z',
    html_url: `https://github.com/example/advisories/${id}`,
    vulnerabilities: [{ package: { ecosystem: 'npm', name }, vulnerable_version_range: range, patched_versions: null }],
  };
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

/** A fetch that answers registry, GitHub and OSV requests from a table of packages. */
function recorded(world: Record<string, Pkg>) {
  const calls: string[] = [];
  const byRepo = new Map<string, Pkg>();
  for (const pkg of Object.values(world)) {
    const repo = githubRepository(pkg.repository);
    if (repo) byRepo.set(repo, pkg);
  }
  const fetch = async (url: string, init: { method?: string; body?: string } = {}) => {
    calls.push(`${init.method ?? 'GET'} ${url}`);
    const u = new URL(url);
    if (u.host === 'registry.npmjs.org' && u.pathname === '/-/npm/v1/security/advisories/bulk') {
      const body = JSON.parse(init.body ?? '{}');
      const name = Object.keys(body)[0];
      return json({ [name]: (world[name]?.npmAudit ?? []).map((id) => ({ id })) });
    }
    if (u.host === 'registry.npmjs.org') {
      const segments = decodeURIComponent(u.pathname.slice(1)).split('/');
      const name = segments[0].startsWith('@') ? `${segments[0]}/${segments[1]}` : segments[0];
      const version = segments[0].startsWith('@') ? segments[2] : segments[1];
      const pkg = world[name];
      if (!pkg) return json({ error: 'not found' }, 404);
      if (pkg.failRegistry) return json({ error: 'down' }, 500);
      if (version) return json({ name, version, repository: pkg.repository });
      return json({ name, 'dist-tags': { latest: pkg.versions[pkg.versions.length - 1] }, versions: Object.fromEntries(pkg.versions.map((v) => [v, {}])) });
    }
    if (u.host === 'api.osv.dev') {
      const body = JSON.parse(init.body ?? '{}');
      const ids = world[body.package.name]?.osv ?? [];
      return json(ids.length ? { vulns: ids.map((id) => ({ id })) } : {});
    }
    if (u.host === 'api.github.com' && u.pathname === '/advisories') {
      const affects = u.searchParams.get('affects') ?? '';
      const name = affects.slice(0, affects.lastIndexOf('@'));
      return json((world[name]?.githubReviewed ?? []).map((id) => ({ ghsa_id: id })));
    }
    const repoMatch = /^\/repos\/([^/]+\/[^/]+)\/security-advisories$/.exec(u.pathname);
    if (u.host === 'api.github.com' && repoMatch) {
      const pages = byRepo.get(repoMatch[1])?.upstream ?? [[]];
      const page = Number(u.searchParams.get('page') ?? '1');
      const headers: Record<string, string> = {};
      if (page < pages.length) {
        headers.link = `<https://api.github.com/repos/${repoMatch[1]}/security-advisories?state=published&per_page=100&page=${page + 1}>; rel="next"`;
      }
      return json(pages[page - 1] ?? [], 200, headers);
    }
    return json({ message: `no route for ${url}` }, 404);
  };
  return { fetch, calls };
}

const control = (): Pkg => ({
  versions: ['4.0.0', '4.3.2'],
  repository: { type: 'git', url: 'git+https://github.com/nodeca/js-yaml.git' },
  upstream: [[adv('GHSA-ctrl-0000-0000', 'js-yaml', '>= 4.0.0, < 4.3.2')]],
  osv: ['GHSA-ctrl-0000-0000'],
  githubReviewed: ['GHSA-ctrl-0000-0000'],
  npmAudit: ['1000001'],
});

const manifest = {
  name: 'demo-artifact',
  version: '1.0.0',
  dependencies: { widget: '^1.2.0', '@opena2a/first': '0.1.0' },
};
const lock = {
  lockfileVersion: 3,
  packages: {
    '': { name: 'demo-artifact', version: '1.0.0' },
    'node_modules/widget': { version: '1.2.3' },
    'node_modules/@opena2a/first': { version: '0.1.0' },
  },
};

async function census(world: Record<string, Pkg>, m: object = manifest, l: object = lock) {
  const { fetch, calls } = recorded(world);
  const report = await runCensus({
    manifest: m,
    lock: l,
    client: createClient({ fetch: fetch as unknown as typeof globalThis.fetch }),
    now: new Date('2026-10-05T00:00:00Z'),
  });
  return { report, text: renderText(report), calls };
}

describe('source census: a pin inside an upstream-published range', () => {
  const world = (): Record<string, Pkg> => ({
    'js-yaml': control(),
    widget: {
      versions: ['1.0.0', '1.2.3', '1.2.4', '1.3.0', '2.0.0'],
      repository: 'github:acme/widget',
      upstream: [[
        adv('GHSA-aaaa-aaaa-aaaa', 'widget', '>= 1.0.0, < 1.2.4'),
        adv('GHSA-bbbb-bbbb-bbbb', 'widget', '< 1.0.0', 'medium'),
        adv('GHSA-dddd-dddd-dddd', 'widget-cli', '< 9.0.0'),
      ]],
      osv: [],
      githubReviewed: [],
      npmAudit: [],
    },
  });

  it('reads non-zero upstream while every aggregator reads zero, and exits 1', async () => {
    const { report, text } = await census(world());
    const row = report.rows.find((r: { name: string }) => r.name === 'widget');
    expect(row.version).toBe('1.2.3');
    expect(row.upstream.repository).toBe('acme/widget');
    expect(row.upstream.containing.map((a: { id: string }) => a.id)).toEqual(['GHSA-aaaa-aaaa-aaaa']);
    expect(row.upstream.notContaining).toBe(1);
    expect(row.upstream.otherPackage).toBe(1);
    expect(row.aggregators.osv.count).toBe(0);
    expect(row.aggregators.githubReviewed.count).toBe(0);
    expect(row.aggregators.npmAudit.count).toBe(0);
    expect(report.summary).toMatchObject({ pinned: 1, insideUpstreamRange: 1, exitCode: 1 });
    expect(text).toContain('GHSA-aaaa-aaaa-aaaa  range ">= 1.0.0, < 1.2.4"');
    expect(text).toContain('aggregators  osv 0  githubReviewed 0  npmAudit 0');
  });

  it('records the registry version list for the pinned line', async () => {
    const { report, text } = await census(world());
    const row = report.rows.find((r: { name: string }) => r.name === 'widget');
    expect(row.registry).toEqual({ line: '1.x', versions: ['1.0.0', '1.2.3', '1.2.4', '1.3.0'], newer: ['1.2.4', '1.3.0'], latest: '2.0.0' });
    expect(text).toContain('line 1.x: 4 versions, 2 newer than the pin: 1.2.4, 1.3.0 (latest 2.0.0)');
  });

  it('leaves first-party packages out of the census', async () => {
    const { report } = await census(world());
    expect(report.rows.map((r: { name: string }) => r.name)).toEqual(['widget']);
  });

  it('exits 0 when no pinned version is inside a published range', async () => {
    const w = world();
    w.widget.upstream = [[adv('GHSA-bbbb-bbbb-bbbb', 'widget', '< 1.0.0')]];
    const { report } = await census(w);
    expect(report.summary).toMatchObject({ insideUpstreamRange: 0, unparseableRanges: 0, exitCode: 0 });
  });

  it('follows every page of the upstream advisory list', async () => {
    const w = world();
    w.widget.upstream = [
      [adv('GHSA-bbbb-bbbb-bbbb', 'widget', '< 1.0.0')],
      [adv('GHSA-eeee-eeee-eeee', 'widget', '1.2.3')],
    ];
    const { report } = await census(w);
    const row = report.rows.find((r: { name: string }) => r.name === 'widget');
    expect(row.upstream.read).toBe(2);
    expect(row.upstream.containing.map((a: { id: string }) => a.id)).toEqual(['GHSA-eeee-eeee-eeee']);
  });
});

describe('source census: unparseable ranges are printed and read, never dropped', () => {
  it('prints the advisory id and the raw range, counts it, and exits 1 on it alone', async () => {
    const w: Record<string, Pkg> = {
      'js-yaml': control(),
      widget: {
        versions: ['1.2.3'],
        repository: 'acme/widget',
        upstream: [[adv('GHSA-cccc-cccc-cccc', 'widget', '1.x'), adv('GHSA-ffff-ffff-ffff', 'widget', null)]],
      },
    };
    const { report, text } = await census(w);
    const row = report.rows.find((r: { name: string }) => r.name === 'widget');
    expect(row.upstream.containing).toEqual([]);
    expect(row.upstream.unparseable.map((a: { id: string; range: string | null }) => [a.id, a.range])).toEqual([
      ['GHSA-cccc-cccc-cccc', '1.x'],
      ['GHSA-ffff-ffff-ffff', null],
    ]);
    expect(report.summary).toMatchObject({ insideUpstreamRange: 0, unparseableRanges: 2, exitCode: 1 });
    expect(text).toContain('UNPARSEABLE GHSA-cccc-cccc-cccc  range "1.x"');
    expect(text).toContain('UNPARSEABLE GHSA-ffff-ffff-ffff  range (none)  no range stated');
  });

  it('lists an advisory that names no affected package instead of skipping it', () => {
    const result = readUpstreamAdvisories([{ ghsa_id: 'GHSA-gggg-gggg-gggg', vulnerabilities: [] }], 'widget', '1.2.3');
    expect(result.unparseable).toHaveLength(1);
    expect(result.unparseable[0]).toMatchObject({ id: 'GHSA-gggg-gggg-gggg', reason: 'names no affected package' });
  });

  it('applies a hand reading only to the exact range text it was written for', () => {
    const readings = [{ id: 'GHSA-hhhh-hhhh-hhhh', range: '1.0.0 < 1.5.0', readAs: '>= 1.0.0, < 1.5.0', reason: 'test' }];
    const read = readUpstreamAdvisories([adv('GHSA-hhhh-hhhh-hhhh', 'widget', '1.0.0 < 1.5.0')], 'widget', '1.2.3', readings);
    expect(read.containing).toEqual([expect.objectContaining({ id: 'GHSA-hhhh-hhhh-hhhh', readAs: '>= 1.0.0, < 1.5.0' })]);
    expect(read.readByHand).toBe(1);
    // Upstream edits the range: the reading no longer applies, and the new text is unparseable again.
    const edited = readUpstreamAdvisories([adv('GHSA-hhhh-hhhh-hhhh', 'widget', '1.0.0 < 1.6.0')], 'widget', '1.2.3', readings);
    expect(edited.containing).toEqual([]);
    expect(edited.unparseable.map((a: { range: string }) => a.range)).toEqual(['1.0.0 < 1.6.0']);
  });

  it('every recorded hand reading restates a range the parser cannot read, in a form it can', () => {
    expect(HAND_READINGS.length).toBeGreaterThan(0);
    for (const reading of HAND_READINGS) {
      expect(parseRange(reading.range).ok, reading.id).toBe(false);
      expect(parseRange(reading.readAs).ok, reading.id).toBe(true);
    }
  });
});

describe('source census: positive control', () => {
  const clean = (): Record<string, Pkg> => ({
    'js-yaml': control(),
    widget: { versions: ['1.2.3'], repository: 'acme/widget', upstream: [[]] },
  });

  it('takes the control through the same requests as every pin, first', async () => {
    const { report, calls } = await census(clean());
    expect(report.control).toMatchObject({ name: DEFAULT_CONTROL.name, version: DEFAULT_CONTROL.version, ok: true, blind: [] });
    expect(calls[0]).toContain('registry.npmjs.org/js-yaml');
    expect(calls).toContain('GET https://api.github.com/repos/nodeca/js-yaml/security-advisories?state=published&per_page=100');
    expect(report.summary.exitCode).toBe(0);
  });

  it('a source that reads zero on the control is blind for the run: exit 2, named in the output', async () => {
    const w = clean();
    w['js-yaml'].upstream = [[]];
    const { report, text } = await census(w);
    expect(report.control).toMatchObject({ ok: false, blind: ['upstream'] });
    expect(report.summary.exitCode).toBe(2);
    expect(text).toContain('BLIND: upstream read zero on a version known to be inside a published range');
  });

  it('an aggregator that reads zero on the control is blind, and its zeros below are marked', async () => {
    const w = clean();
    w['js-yaml'].osv = [];
    const { report, text } = await census(w);
    expect(report.control.blind).toEqual(['osv']);
    expect(report.summary.exitCode).toBe(2);
    expect(text).toContain('osv 0 (blind this run)');
  });
});

describe('source census: what cannot be read is reported, not skipped', () => {
  it('a failed request is printed and exits 2', async () => {
    const w: Record<string, Pkg> = {
      'js-yaml': control(),
      widget: { versions: ['1.2.3'], repository: 'acme/widget', upstream: [[]], failRegistry: true },
    };
    const { report, text } = await census(w);
    expect(report.summary).toMatchObject({ failed: 1, exitCode: 2 });
    expect(text).toMatch(/ERROR {8}registry: 500 from https:\/\/registry\.npmjs\.org\/widget/);
  });

  it('an upstream repository that is not on GitHub is undecided', async () => {
    const w: Record<string, Pkg> = {
      'js-yaml': control(),
      widget: { versions: ['1.2.3'], repository: 'https://gitlab.com/acme/widget.git' },
    };
    const { report, text } = await census(w);
    expect(report.summary).toMatchObject({ undecided: 1, exitCode: 1 });
    expect(text).toContain('UNDECIDED    upstream repository not located on GitHub (manifest states "https://gitlab.com/acme/widget.git")');
  });
});

describe('pinnedDependencies', () => {
  it('reads dependencies at their top-level copy and overrides at every non-dev copy', () => {
    const rows = pinnedDependencies(
      {
        dependencies: { widget: '^1.2.0', '@opena2a/first': '0.1.0', pinned: '2.0.0', loose: '^3.0.0' },
        overrides: { gadget: '^3.0.0', 'tool@1.x': '1.4.0', parent: { '.': '5.0.0', child: '6.1.0' }, devonly: '^1.0.0' },
      },
      {
        packages: {
          'node_modules/widget': { version: '1.2.3' },
          'node_modules/other/node_modules/widget': { version: '0.9.0' },
          'node_modules/gadget': { version: '3.1.0' },
          'node_modules/foo/node_modules/gadget': { version: '3.0.4' },
          'node_modules/tool': { version: '1.4.0' },
          'node_modules/parent': { version: '5.0.0' },
          'node_modules/child': { version: '6.1.0' },
          'node_modules/devonly': { version: '1.0.2', dev: true },
        },
      },
    );
    expect(rows.map((r: { name: string; version: string | null }) => `${r.name}@${r.version}`)).toEqual([
      'child@6.1.0',
      'devonly@null',
      'gadget@3.0.4',
      'gadget@3.1.0',
      'loose@null',
      'parent@5.0.0',
      'pinned@2.0.0',
      'tool@1.4.0',
      'widget@1.2.3',
    ]);
    expect(rows.find((r: { name: string }) => r.name === 'devonly').devOnly).toBe(true);
    expect(rows.find((r: { name: string }) => r.name === 'loose').devOnly).toBe(false);
  });

  it('a dev-only override is skipped and named; an unresolved pin is undecided', async () => {
    const { report, text } = await census(
      { 'js-yaml': control() },
      { name: 'demo', version: '1.0.0', dependencies: { loose: '^3.0.0' }, overrides: { devonly: '^1.0.0' } },
      { packages: { 'node_modules/devonly': { version: '1.0.2', dev: true } } },
    );
    expect(report.summary).toMatchObject({ pinned: 1, skipped: 1, undecided: 1, exitCode: 1 });
    expect(text).toContain('SKIPPED      pinned in the dev tree only');
    expect(text).toContain('UNDECIDED    the lockfile resolves no version for this pin');
  });
});

describe('ranges and versions', () => {
  it.each([
    ['>= 4.0.0, < 4.3.2', '4.0.0', true],
    ['>= 4.0.0, < 4.3.2', '4.3.2', false],
    ['>= 5.0.0, <=5.4.0', '5.4.0', true],
    ['<1.25.2', '1.25.1', true],
    ['<= 0.6.0', '0.6.1', false],
    ['0.6.0', '0.6.0', true],
    ['0.6.0', '0.6.1', false],
    ['>=4.0.0 <4.1.1', '4.1.0', true],
    ['< 1.20.6; >= 2.0.0, < 2.3.0', '2.2.9', true],
    ['< 1.20.6; >= 2.0.0, < 2.3.0', '2.3.0', false],
    ['< 1.0.0 || >= 2.0.0, < 2.1.0', '2.0.5', true],
    ['> 1.1.0', '4.13.0', true],
    ['< 2.0.0', '2.0.0-rc.1', true],
  ])('%s contains %s: %s', (range, version, expected) => {
    const parsed = parseRange(range);
    expect(parsed.ok).toBe(true);
    expect(rangeContains(parsed, version)).toBe(expected);
  });

  it.each([
    ['4.x', 'cannot read "4.x" as a version'],
    ['^1.2.0', 'cannot read "^1.2.0" as a version constraint'],
    ['> = 1.19.10, < 2.1.3', 'as a version constraint'],
    ['', 'no range stated'],
    ['all versions', 'as a version constraint'],
    // A bare version beside a bound is a span start, not an exact version:
    // reading it as `=` would match 3.0.0 and miss 3.0.1 through 3.1.2.
    ['3.0.0 <= 3.1.2', 'a bare version next to another bound states no operator'],
    ['3.0.0<= 3.1.0', 'a bare version next to another bound states no operator'],
  ])('%j is unparseable', (range, reason) => {
    const parsed = parseRange(range);
    expect(parsed.ok).toBe(false);
    expect(parsed.reason).toContain(reason);
  });

  it('orders prereleases below their release', () => {
    const v = (s: string) => parseVersion(s)!;
    expect(compareVersions(v('1.0.0-rc.1'), v('1.0.0'))).toBe(-1);
    expect(compareVersions(v('1.0.0-rc.2'), v('1.0.0-rc.10'))).toBe(-1);
    expect(compareVersions(v('1.0.0-alpha'), v('1.0.0-1'))).toBe(1);
    expect(compareVersions(v('1.2.3'), v('1.2.3'))).toBe(0);
  });

  it('takes the caret-compatible line on 0.x and 0.0.x', () => {
    expect(registryLine(['0.5.0', '0.6.0', '0.6.1', '0.7.0'], '0.6.0')).toMatchObject({ line: '0.6.x', newer: ['0.6.1'] });
    expect(registryLine(['0.0.3', '0.0.4'], '0.0.3')).toMatchObject({ line: '0.0.3', versions: ['0.0.3'], newer: [] });
  });

  it.each([
    ['git+https://github.com/nodeca/js-yaml.git', 'nodeca/js-yaml'],
    ['https://github.com/tj/commander.js.git', 'tj/commander.js'],
    ['https://github.com/tj/commander.js', 'tj/commander.js'],
    ['git@github.com:owner/repo.git', 'owner/repo'],
    ['git+ssh://git@github.com/owner/repo.git', 'owner/repo'],
    ['https://github.com/microsoft/onnxruntime/tree/main/js/node', 'microsoft/onnxruntime'],
    ['github:owner/repo', 'owner/repo'],
    ['owner/repo', 'owner/repo'],
    ['gitlab:owner/repo', null],
    ['https://gitlab.com/owner/repo.git', null],
    ['', null],
  ])('repository %j is %j on GitHub', (url, expected) => {
    expect(githubRepository({ type: 'git', url })).toBe(expected);
  });
});

describe('source census CLI', () => {
  it('refuses an unknown argument with usage and exit 2, before any request', () => {
    const run = spawnSync(process.execPath, [SCRIPT, '--bogus'], { encoding: 'utf8', timeout: 30_000 });
    expect(run.status).toBe(2);
    expect(run.stderr).toContain('unknown argument "--bogus"');
    expect(run.stderr).toContain('usage: node scripts/source-census.mjs');
  });

  it('exits 2 when --root has no package.json', () => {
    const empty = tempDir('census-');
    try {
      const run = spawnSync(process.execPath, [SCRIPT, '--root', empty], { encoding: 'utf8', timeout: 30_000 });
      expect(run.status).toBe(2);
      expect(run.stderr).toContain('no package.json at');
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });
});
