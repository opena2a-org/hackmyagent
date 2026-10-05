#!/usr/bin/env node
/**
 * Source census: for every pinned third-party dependency of the published
 * package, read what the dependency's own repository has published, next to
 * what the aggregators say about the same version.
 *
 * ## Why read upstream at all
 *
 * `npm audit`, the GitHub advisory database and OSV are aggregators. A zero
 * from one of them is a statement about what that aggregator has ingested, not
 * about the dependency. Maintainers publish a repository security advisory
 * first, and the aggregators pick it up days to weeks later. A pin admitted as
 * "the first fixed version" on aggregator zeros alone can already sit inside a
 * range its maintainers published a week earlier, and every instrument that
 * reads only aggregators reports that pin as clean. This repository's
 * dependency audit and `scripts/audit-consumer-resolution.mjs` both read
 * aggregators only.
 *
 * So for each pinned dependency this script records, side by side:
 *
 *   - the registry's version list for the pinned line (the caret-compatible
 *     set), and which versions in it are newer than the pin;
 *   - every advisory the upstream repository has published whose vulnerable
 *     range contains the pinned version;
 *   - the count each aggregator reports at the pinned version.
 *
 * ## What "pinned" means here
 *
 * Every entry in `dependencies`, `optionalDependencies` and `overrides` that
 * is not first-party, at the version `package-lock.json` resolves. A direct
 * dependency is read at its top-level copy; an override is read at every copy
 * it applies to outside the dev tree. Which versions a consumer resolves from
 * the published tarball, where `overrides` do not apply, is
 * `scripts/audit-consumer-resolution.mjs`'s question, not this one's.
 *
 * ## Nothing is dropped
 *
 * A range this script cannot parse is printed with its advisory id and its raw
 * text, and counts as undecided. So does a dependency whose upstream
 * repository cannot be located, and a pin the lockfile does not resolve. A
 * census that silently skips what it cannot read reports a zero it never
 * measured.
 *
 * ## Positive control
 *
 * Every run first takes the census of a version known to be inside published
 * ranges, through the same requests and the same range matcher as the real
 * rows. Every source has to read non-zero on it. A source that reads zero on
 * the control is blind for this run, so its zeros below mean nothing, and the
 * run says so and exits 2.
 *
 * Exit codes: 0 when no pinned version is inside an upstream-published range
 * and nothing is undecided; 1 when at least one is inside a range or is
 * undecided; 2 when the census could not be taken (a blind source on the
 * control, or a request that failed).
 *
 * Usage:
 *   node scripts/source-census.mjs [--root <dir>] [--json <file>] [--control <name@version>]
 *
 * `--root` takes the census of another npm package checkout. Requests to
 * api.github.com carry `GITHUB_TOKEN` when it is set. Each pin, and the
 * control, costs two GitHub requests, so without a token the unauthenticated
 * limit of 60 requests an hour covers about two runs of this repository.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const FIRST_PARTY_SCOPES = ['@opena2a/'];

/**
 * js-yaml 4.0.0 sits inside several ranges nodeca/js-yaml published on its
 * own repository, and all three aggregators carry them (read 2026-10-05:
 * upstream 5, OSV 5, GitHub reviewed 5, npm audit 5). Published advisories
 * are not withdrawn as a matter of course, so the control stays non-zero for
 * as long as the sources are readable.
 */
export const DEFAULT_CONTROL = { name: 'js-yaml', version: '4.0.0' };

export const AGGREGATORS = ['osv', 'githubReviewed', 'npmAudit'];

/**
 * Upstream ranges this script cannot parse, read by hand. Each entry is keyed
 * by the advisory id AND the exact range text, and `readAs` is that range
 * restated in the grammar `parseRange` reads, checked against the advisory's
 * stated patched versions. The matcher then runs on `readAs` for every pin,
 * so a pin that moves into the range still reads non-zero. If upstream edits
 * the range, the text no longer matches and the entry is unparseable again
 * until someone reads the new text.
 */
export const HAND_READINGS = [
  {
    id: 'GHSA-rmxm-3fg6-px4f',
    range: '> = 1.19.10, < 2.1.3',
    readAs: '>= 1.19.10, < 2.1.3',
    reason: '"> =" read as ">="; patched 2.1.3',
  },
  {
    id: 'GHSA-7p8r-x3mc-p8w7',
    range: '4.0.0 < 4.1.2; 3.0.0 < 3.1.5; < 2.4.4',
    readAs: '>= 4.0.0, < 4.1.2; >= 3.0.0, < 3.1.5; < 2.4.4',
    reason: 'a bare lower bound read as ">="; patched 4.1.2, 3.1.5, 2.4.4',
  },
  {
    id: 'GHSA-4c8g-83qw-93j6',
    range: '>= 2.3.1 <2.4.2; 3.0.0 <= 3.1.2; 4.0.0',
    readAs: '>= 2.3.1, < 2.4.2; >= 3.0.0, <= 3.1.2; = 4.0.0',
    reason: 'a bare lower bound read as ">=", the lone "4.0.0" as that version only; patched 2.4.2, 3.1.3, 4.0.1',
  },
  {
    id: 'GHSA-q3j6-qgpj-74h6',
    range: '<=2.4.0; 3.0.0<= 3.1.0',
    readAs: '<= 2.4.0; >= 3.0.0, <= 3.1.0',
    reason: 'a bare lower bound read as ">="; patched 2.4.1, 3.1.1',
  },
  {
    id: 'GHSA-v39h-62p7-jpjc',
    range: '<= 2.4.0; v3.0.0 <= 3.1.1',
    readAs: '<= 2.4.0; >= 3.0.0, <= 3.1.1',
    reason: 'a bare lower bound read as ">="; patched 2.4.1, 3.1.2',
  },
];

const NPM_REGISTRY = 'https://registry.npmjs.org';
const GITHUB_API = 'https://api.github.com';
const OSV_API = 'https://api.osv.dev';
const MAX_PAGES = 10;

// ---------------------------------------------------------------------------
// Versions and ranges
// ---------------------------------------------------------------------------

const VERSION_RE = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** A semver version, with missing minor or patch read as 0. Null when it is not one. */
export function parseVersion(text) {
  if (typeof text !== 'string') return null;
  const m = VERSION_RE.exec(text.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2] ?? 0),
    patch: Number(m[3] ?? 0),
    pre: m[4] ? m[4].split('.') : [],
  };
}

function comparePre(a, b) {
  if (a.length === 0 && b.length === 0) return 0;
  // A release sorts above every prerelease of the same version.
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]);
    const bn = /^\d+$/.test(b[i]);
    if (an && bn) {
      const d = Number(a[i]) - Number(b[i]);
      if (d !== 0) return Math.sign(d);
    } else if (an !== bn) {
      return an ? -1 : 1;
    } else if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}

/** Semver precedence of two parsed versions: -1, 0 or 1. */
export function compareVersions(a, b) {
  for (const k of ['major', 'minor', 'patch']) {
    if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  }
  return comparePre(a.pre, b.pre);
}

const CONSTRAINT_RE = /\s*(<=|>=|<|>|=)?\s*(v?\d[0-9A-Za-z.+-]*)\s*,?/y;

function parseAlternative(text) {
  const trimmed = text.trim();
  if (trimmed === '') return { reason: 'empty alternative' };
  const found = [];
  let pos = 0;
  while (pos < trimmed.length) {
    CONSTRAINT_RE.lastIndex = pos;
    const m = CONSTRAINT_RE.exec(trimmed);
    if (!m) return { reason: `cannot read "${trimmed.slice(pos).trim()}" as a version constraint` };
    const version = parseVersion(m[2]);
    if (!version) return { reason: `cannot read "${m[2]}" as a version` };
    found.push({ op: m[1] ?? null, version });
    pos = CONSTRAINT_RE.lastIndex;
  }
  // `3.0.0 <= 3.1.2` means "from 3.0.0", not "exactly 3.0.0". Reading the bare
  // version as `=` would match one version of the span and miss the rest, so a
  // bare version is only read when it stands alone.
  if (found.length > 1 && found.some((c) => c.op === null)) {
    return { reason: 'a bare version next to another bound states no operator' };
  }
  return { constraints: found.map((c) => ({ op: c.op ?? '=', version: c.version })) };
}

/**
 * Parse a vulnerable range as advisories state it: comma- or space-separated
 * constraints (`>= 4.0.0, < 4.3.2`, `<=5.4.0`, `>=4.0.0 <4.1.1`), a bare
 * version standing alone meaning exactly that version, and `||` or `;`
 * between alternatives. Anything else (`4.x`, `^1.2.0`, `> = 1.0.0`, prose)
 * is returned as unparseable with the reason, for the caller to print.
 */
export function parseRange(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    return { ok: false, reason: 'no range stated' };
  }
  const alternatives = [];
  for (const alt of text.split(/\|\||;/)) {
    const parsed = parseAlternative(alt);
    if (parsed.reason) return { ok: false, reason: parsed.reason };
    alternatives.push(parsed.constraints);
  }
  return { ok: true, alternatives };
}

/** Whether a parsed range contains a version (a string or a parsed version). */
export function rangeContains(parsed, version) {
  const v = typeof version === 'string' ? parseVersion(version) : version;
  if (!parsed.ok || !v) return false;
  return parsed.alternatives.some((constraints) =>
    constraints.every(({ op, version: bound }) => {
      const c = compareVersions(v, bound);
      switch (op) {
        case '<': return c < 0;
        case '<=': return c <= 0;
        case '>': return c > 0;
        case '>=': return c >= 0;
        default: return c === 0;
      }
    }),
  );
}

/**
 * The registry's versions on the pinned version's caret-compatible line:
 * same major from 1.0.0 on, same minor on 0.x, the version itself on 0.0.x.
 */
export function registryLine(versions, pinned, distTags = {}) {
  const p = parseVersion(pinned);
  if (!p) return { line: null, versions: [], newer: [], latest: distTags.latest ?? null };
  const sameLine = (v) =>
    p.major > 0 ? v.major === p.major
      : p.minor > 0 ? v.major === 0 && v.minor === p.minor
        : v.major === 0 && v.minor === 0 && v.patch === p.patch;
  const label = p.major > 0 ? `${p.major}.x` : p.minor > 0 ? `0.${p.minor}.x` : `0.0.${p.patch}`;
  const inLine = versions
    .map((text) => ({ text, v: parseVersion(text) }))
    .filter((e) => e.v && sameLine(e.v))
    .sort((a, b) => compareVersions(a.v, b.v));
  return {
    line: label,
    versions: inLine.map((e) => e.text),
    newer: inLine.filter((e) => compareVersions(e.v, p) > 0).map((e) => e.text),
    latest: distTags.latest ?? null,
  };
}

// ---------------------------------------------------------------------------
// The pinned set
// ---------------------------------------------------------------------------

function overrideName(key) {
  // An override key may carry a selector, `name@1.x`; the name ends at the
  // last `@` that is not the scope marker.
  const at = key.lastIndexOf('@');
  return at > 0 ? key.slice(0, at) : key;
}

function* flattenOverrides(overrides, parent = null) {
  for (const [key, value] of Object.entries(overrides ?? {})) {
    if (key === '.') {
      if (parent && typeof value === 'string') yield [parent, value];
      continue;
    }
    const name = overrideName(key);
    if (typeof value === 'string') yield [name, value];
    else if (value && typeof value === 'object') yield* flattenOverrides(value, name);
  }
}

/**
 * Every pinned third-party (name, version) of a package, from its manifest and
 * lockfile. A pin the lockfile does not resolve is kept with `version: null`,
 * and with `devOnly` when the only copies it applies to are in the dev tree.
 */
export function pinnedDependencies(manifest, lock, { firstPartyScopes = FIRST_PARTY_SCOPES } = {}) {
  const packages = lock?.packages ?? {};
  const byName = new Map();
  const declare = (name, spec, source) => {
    if (firstPartyScopes.some((scope) => name.startsWith(scope))) return;
    if (!byName.has(name)) byName.set(name, { name, declared: [], versions: new Set(), devCopies: 0 });
    const entry = byName.get(name);
    entry.declared.push({ source, spec });
    const resolved = [];
    if (source === 'overrides') {
      for (const [p, meta] of Object.entries(packages)) {
        if (!(p === `node_modules/${name}` || p.endsWith(`/node_modules/${name}`)) || !meta.version) continue;
        if (meta.dev) entry.devCopies++;
        else resolved.push(meta.version);
      }
    } else if (packages[`node_modules/${name}`]?.version) {
      resolved.push(packages[`node_modules/${name}`].version);
    }
    if (resolved.length === 0 && typeof spec === 'string' && parseVersion(spec)) resolved.push(spec.trim());
    for (const v of resolved) entry.versions.add(v);
  };
  for (const [name, spec] of Object.entries(manifest.dependencies ?? {})) declare(name, spec, 'dependencies');
  for (const [name, spec] of Object.entries(manifest.optionalDependencies ?? {})) declare(name, spec, 'optionalDependencies');
  for (const [name, spec] of flattenOverrides(manifest.overrides)) declare(name, spec, 'overrides');

  const rows = [];
  for (const entry of byName.values()) {
    const versions = [...entry.versions];
    if (versions.length === 0) {
      rows.push({ name: entry.name, version: null, declared: entry.declared, devOnly: entry.devCopies > 0 });
    }
    for (const version of versions) rows.push({ name: entry.name, version, declared: entry.declared });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
}

/** `owner/repo` of a manifest `repository` field when it is on GitHub, else null. */
export function githubRepository(repository) {
  const url = typeof repository === 'string' ? repository : repository?.url;
  if (typeof url !== 'string' || url.trim() === '') return null;
  const text = url.trim();
  const shorthand = /^(?:github:)?([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?$/.exec(text);
  if (shorthand && (text.startsWith('github:') || !text.includes(':'))) return `${shorthand[1]}/${shorthand[2]}`;
  const full = /github\.com[/:]([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[#?/].*)?$/.exec(text);
  return full ? `${full[1]}/${full[2]}` : null;
}

// ---------------------------------------------------------------------------
// Reading the sources
// ---------------------------------------------------------------------------

function appliesTo(vulnerability, name) {
  const pkg = vulnerability?.package;
  if (!pkg) return true;
  if (pkg.ecosystem && String(pkg.ecosystem).toLowerCase() !== 'npm') return false;
  return !pkg.name || pkg.name === name;
}

function advisorySummary(advisory) {
  return {
    id: advisory.ghsa_id ?? advisory.id ?? null,
    cveId: advisory.cve_id ?? null,
    severity: advisory.severity ?? null,
    publishedAt: advisory.published_at ?? null,
    url: advisory.html_url ?? null,
  };
}

/** The range to match: the stated one, or its hand reading when one is recorded for this exact text. */
function rangeFor(advisoryId, stated, readings) {
  const reading = readings.find((r) => r.id === advisoryId && r.range === stated);
  return reading
    ? { parsed: parseRange(reading.readAs), readAs: reading.readAs }
    : { parsed: parseRange(stated), readAs: null };
}

/**
 * Classify a repository's published advisories against one pinned version.
 * Each vulnerability entry naming the package is read on its own; an
 * advisory counts as containing the pin when any of them does, and every
 * entry whose range cannot be parsed is listed regardless.
 */
export function readUpstreamAdvisories(advisories, name, version, readings = HAND_READINGS) {
  const result = {
    read: advisories.length,
    otherPackage: 0,
    notContaining: 0,
    readByHand: 0,
    containing: [],
    unparseable: [],
  };
  for (const advisory of advisories) {
    const all = Array.isArray(advisory.vulnerabilities) ? advisory.vulnerabilities : [];
    if (all.length === 0) {
      result.unparseable.push({ ...advisorySummary(advisory), range: null, reason: 'names no affected package' });
      continue;
    }
    const mine = all.filter((v) => appliesTo(v, name));
    if (mine.length === 0) {
      result.otherPackage++;
      continue;
    }
    const summary = advisorySummary(advisory);
    let containing = null;
    let unreadable = false;
    for (const v of mine) {
      const { parsed, readAs } = rangeFor(summary.id, v.vulnerable_version_range, readings);
      if (readAs) result.readByHand++;
      if (!parsed.ok) {
        unreadable = true;
        result.unparseable.push({ ...summary, range: v.vulnerable_version_range ?? null, reason: parsed.reason });
      } else if (!containing && rangeContains(parsed, version)) {
        containing = { range: v.vulnerable_version_range, readAs, patched: v.patched_versions ?? null };
      }
    }
    if (containing) result.containing.push({ ...summary, ...containing });
    else if (!unreadable) result.notContaining++;
  }
  return result;
}

function encodePackage(name) {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

function nextLink(header) {
  if (!header) return null;
  const m = /<([^>]+)>;\s*rel="next"/.exec(header);
  return m ? m[1] : null;
}

/** HTTP helpers over an injected `fetch`, so the census can run against recorded responses. */
export function createClient({ fetch: fetchImpl = globalThis.fetch, githubToken = null } = {}) {
  const headersFor = (url, extra = {}) => {
    const headers = { 'user-agent': 'hackmyagent-source-census', ...extra };
    if (url.startsWith(GITHUB_API)) {
      headers.accept = 'application/vnd.github+json';
      if (githubToken) headers.authorization = `Bearer ${githubToken}`;
    }
    return headers;
  };
  const request = async (url, init = {}) => {
    const res = await fetchImpl(url, { ...init, headers: headersFor(url, init.headers) });
    if (!res.ok) {
      let detail = '';
      try {
        const body = await res.json();
        detail = body?.message ? `: ${body.message}` : '';
      } catch {
        // A non-JSON error body adds nothing the status does not say.
      }
      throw new Error(`${res.status} from ${url.split('?')[0]}${detail}`);
    }
    return res;
  };
  return {
    async getJson(url, headers = {}) {
      return (await request(url, { headers })).json();
    },
    async postJson(url, body) {
      return (await request(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })).json();
    },
    /** Every page of a GitHub list endpoint, following `Link: rel="next"`. */
    async getAllPages(url) {
      const items = [];
      let next = url;
      for (let page = 0; next && page < MAX_PAGES; page++) {
        const res = await request(next);
        const body = await res.json();
        if (!Array.isArray(body)) throw new Error(`expected a list from ${next.split('?')[0]}`);
        items.push(...body);
        next = nextLink(res.headers.get('link'));
      }
      if (next) throw new Error(`more than ${MAX_PAGES} pages from ${url.split('?')[0]}`);
      return items;
    },
  };
}

async function readAggregator(errors, source, read) {
  try {
    const ids = await read();
    return { count: ids.length, ids };
  } catch (err) {
    errors.push(`${source}: ${err.message}`);
    return { count: null, ids: [], error: err.message };
  }
}

/** Take the census of one pinned (name, version). */
export async function censusOne(client, pin) {
  const { name, version } = pin;
  const row = {
    name,
    version,
    declared: pin.declared ?? [],
    registry: null,
    upstream: null,
    aggregators: {},
    undecided: [],
    errors: [],
    skipped: null,
  };
  if (!version && pin.devOnly) {
    row.skipped = 'pinned in the dev tree only; the published package does not carry it';
    return row;
  }
  if (!version) {
    row.undecided.push('the lockfile resolves no version for this pin');
    return row;
  }

  try {
    const packument = await client.getJson(`${NPM_REGISTRY}/${encodePackage(name)}`, {
      accept: 'application/vnd.npm.install-v1+json',
    });
    row.registry = registryLine(Object.keys(packument.versions ?? {}), version, packument['dist-tags'] ?? {});
  } catch (err) {
    row.errors.push(`registry: ${err.message}`);
  }

  let repository = null;
  try {
    const manifest = await client.getJson(`${NPM_REGISTRY}/${encodePackage(name)}/${encodeURIComponent(version)}`);
    repository = githubRepository(manifest.repository);
    if (!repository) {
      const stated = typeof manifest.repository === 'string' ? manifest.repository : manifest.repository?.url;
      row.undecided.push(`upstream repository not located on GitHub (manifest states ${stated ? `"${stated}"` : 'none'})`);
    }
  } catch (err) {
    row.errors.push(`manifest: ${err.message}`);
  }
  if (repository) {
    try {
      const advisories = await client.getAllPages(
        `${GITHUB_API}/repos/${repository}/security-advisories?state=published&per_page=100`,
      );
      row.upstream = { repository, ...readUpstreamAdvisories(advisories, name, version) };
    } catch (err) {
      row.errors.push(`upstream ${repository}: ${err.message}`);
    }
  }

  row.aggregators.osv = await readAggregator(row.errors, 'osv', async () => {
    const ids = [];
    let pageToken;
    for (let page = 0; page < MAX_PAGES; page++) {
      const body = await client.postJson(`${OSV_API}/v1/query`, {
        version,
        package: { name, ecosystem: 'npm' },
        ...(pageToken ? { page_token: pageToken } : {}),
      });
      ids.push(...(body.vulns ?? []).map((v) => v.id));
      pageToken = body.next_page_token;
      if (!pageToken) return ids;
    }
    throw new Error(`more than ${MAX_PAGES} pages`);
  });
  row.aggregators.githubReviewed = await readAggregator(row.errors, 'githubReviewed', async () => {
    const affects = encodeURIComponent(`${name}@${version}`);
    const list = await client.getAllPages(`${GITHUB_API}/advisories?ecosystem=npm&affects=${affects}&per_page=100`);
    return list.map((a) => a.ghsa_id);
  });
  row.aggregators.npmAudit = await readAggregator(row.errors, 'npmAudit', async () => {
    const body = await client.postJson(`${NPM_REGISTRY}/-/npm/v1/security/advisories/bulk`, { [name]: [version] });
    return (body[name] ?? []).map((a) => String(a.id));
  });
  return row;
}

/** A source that reads zero on the control is blind for the run. */
export function evaluateControl(row) {
  const blind = [];
  if (!row.upstream || row.upstream.containing.length === 0) blind.push('upstream');
  for (const source of AGGREGATORS) {
    const reading = row.aggregators[source];
    if (!reading || reading.error || !reading.count) blind.push(source);
  }
  return { ok: blind.length === 0, blind };
}

/** Take the whole census: the control first, then every pin. */
export async function runCensus({ manifest, lock, client, control = DEFAULT_CONTROL, now = new Date() }) {
  const controlRow = await censusOne(client, { ...control, declared: [] });
  const controlVerdict = evaluateControl(controlRow);
  const rows = [];
  for (const pin of pinnedDependencies(manifest, lock)) rows.push(await censusOne(client, pin));

  const censused = rows.filter((r) => !r.skipped);
  const inside = rows.filter((r) => r.upstream?.containing.length);
  const unparseable = rows.reduce((n, r) => n + (r.upstream?.unparseable.length ?? 0), 0);
  const undecided = rows.filter((r) => r.undecided.length);
  const failed = rows.filter((r) => r.errors.length);
  let exitCode = 0;
  if (inside.length || unparseable || undecided.length) exitCode = 1;
  if (!controlVerdict.ok || failed.length) exitCode = 2;
  return {
    schema: 'source-census/1',
    takenAt: now.toISOString(),
    artifact: { name: manifest.name ?? null, version: manifest.version ?? null },
    control: { name: control.name, version: control.version, ...controlVerdict, row: controlRow },
    rows,
    summary: {
      pinned: censused.length,
      skipped: rows.length - censused.length,
      insideUpstreamRange: inside.length,
      unparseableRanges: unparseable,
      undecided: undecided.length,
      failed: failed.length,
      exitCode,
    },
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function aggregatorLine(row, blind = []) {
  return AGGREGATORS.map((source) => {
    const reading = row.aggregators[source];
    const value = !reading || reading.error ? 'error' : String(reading.count);
    return `${source} ${value}${blind.includes(source) ? ' (blind this run)' : ''}`;
  }).join('  ');
}

function listSome(items, max = 8) {
  return items.length > max ? `${items.slice(0, max).join(', ')}, +${items.length - max} more` : items.join(', ');
}

function renderRow(row, lines, blind = []) {
  const declared = row.declared.map((d) => `${d.source} ${d.spec}`).join('; ');
  lines.push(`${row.name} ${row.version ?? '(unresolved)'}${declared ? `  [${declared}]` : ''}`);
  if (row.registry) {
    const r = row.registry;
    const newer = r.newer.length ? `${r.newer.length} newer than the pin: ${listSome(r.newer)}` : 'none newer than the pin';
    lines.push(`  registry     line ${r.line}: ${r.versions.length} versions, ${newer} (latest ${r.latest ?? 'unknown'})`);
  }
  if (row.upstream) {
    const u = row.upstream;
    lines.push(
      `  upstream     ${u.repository}: ${u.read} published advisories read, ${u.containing.length} contain ${row.version}` +
      `${u.otherPackage ? `, ${u.otherPackage} name another package` : ''}` +
      `${u.readByHand ? `, ${u.readByHand} ranges read by hand` : ''}${blind.includes('upstream') ? ' (blind this run)' : ''}`,
    );
    for (const a of u.containing) {
      const readAs = a.readAs ? ` (read by hand as "${a.readAs}")` : '';
      lines.push(`    ${String(a.severity ?? 'unrated').toUpperCase().padEnd(8)} ${a.id}  range "${a.range}"${readAs}  patched ${a.patched ?? 'none stated'}  published ${a.publishedAt ?? 'unknown'}`);
    }
    for (const a of u.unparseable) {
      lines.push(`    UNPARSEABLE ${a.id}  range ${a.range === null ? '(none)' : `"${a.range}"`}  ${a.reason}; read it by hand: ${a.url ?? 'no url'}`);
    }
  }
  if (row.version) lines.push(`  aggregators  ${aggregatorLine(row, blind)}`);
  if (row.skipped) lines.push(`  SKIPPED      ${row.skipped}`);
  for (const reason of row.undecided) lines.push(`  UNDECIDED    ${reason}`);
  for (const error of row.errors) lines.push(`  ERROR        ${error}`);
}

export function renderText(report) {
  const lines = [];
  const { artifact, control, summary } = report;
  lines.push(`Source census of ${artifact.name ?? 'package'}@${artifact.version ?? '?'}: ${summary.pinned} pinned third-party versions, taken ${report.takenAt}`);
  lines.push('');
  lines.push(`Positive control ${control.name}@${control.version}: ${control.ok ? 'every source reads non-zero' : `BLIND: ${control.blind.join(', ')} read zero on a version known to be inside a published range`}`);
  renderRow(control.row, lines, control.blind);
  lines.push('');
  for (const row of report.rows) {
    renderRow(row, lines, control.blind);
    lines.push('');
  }
  lines.push(
    `Summary: ${summary.insideUpstreamRange} of ${summary.pinned} pinned versions inside an upstream-published range; ` +
    `${summary.unparseableRanges} unparseable ranges; ${summary.undecided} undecided; ${summary.failed} with failed requests; ` +
    `${summary.skipped} skipped as dev-only; ` +
    `control ${control.ok ? 'ok' : 'blind'}. Exit ${summary.exitCode}.`,
  );
  return `${lines.join('\n')}\n`;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE = 'usage: node scripts/source-census.mjs [--root <dir>] [--json <file>] [--control <name@version>]';

export function parseArgs(argv) {
  const opts = { root: REPO_ROOT, json: null, control: DEFAULT_CONTROL };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = argv[i + 1];
    if ((arg === '--root' || arg === '--json' || arg === '--control') && (value === undefined || value.startsWith('--'))) {
      throw new Error(`${arg} needs a value`);
    }
    if (arg === '--root') opts.root = path.resolve(argv[++i]);
    else if (arg === '--json') opts.json = path.resolve(argv[++i]);
    else if (arg === '--control') {
      const spec = argv[++i];
      const at = spec.lastIndexOf('@');
      const name = at > 0 ? spec.slice(0, at) : '';
      const version = at > 0 ? spec.slice(at + 1) : '';
      if (!name || !parseVersion(version)) throw new Error(`--control takes name@version, got "${spec}"`);
      opts.control = { name, version };
    } else throw new Error(`unknown argument "${arg}"`);
  }
  return opts;
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n${USAGE}\n`);
    process.exit(2);
  }
  const manifestPath = path.join(opts.root, 'package.json');
  const lockPath = path.join(opts.root, 'package-lock.json');
  if (!existsSync(manifestPath)) {
    process.stderr.write(`no package.json at ${opts.root}\n`);
    process.exit(2);
  }
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const lock = existsSync(lockPath) ? JSON.parse(readFileSync(lockPath, 'utf8')) : null;
  if (lock && !lock.packages) {
    process.stderr.write('package-lock.json has no "packages" map (lockfileVersion 1); regenerate it with npm 7 or later\n');
    process.exit(2);
  }
  const client = createClient({ githubToken: process.env.GITHUB_TOKEN || null });
  const report = await runCensus({ manifest, lock, client, control: opts.control });
  process.stdout.write(renderText(report));
  if (opts.json) writeFileSync(opts.json, `${JSON.stringify(report, null, 2)}\n`);
  process.exit(report.summary.exitCode);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    process.stderr.write(`source census failed: ${err.stack ?? err.message}\n`);
    process.exit(2);
  });
}
