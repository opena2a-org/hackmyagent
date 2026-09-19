/**
 * QGF-254 — the known-open record for `GHSA-vwc7-r8mq-g2x9`, and the readings
 * that keep it from going stale unwitnessed.
 *
 * Neither of this repository's advisory instruments can see this finding:
 * `.github/workflows/dependency-audit.yml` gates at `high` and
 * `scripts/audit-consumer-resolution.mjs` drops everything below `high` before
 * it looks at a waiver. A finding no instrument reports is one that exists in
 * prose or not at all, and prose rots. So the record states its evidence inline
 * and this suite re-reads that evidence out of the files it cites.
 *
 * Two halves:
 *
 *   - the record says what it must say, and every file:line it cites really
 *     carries what it says it carries;
 *   - the four lockfile readings it states still match `package-lock.json`,
 *     with a planted fault per reading to prove the comparison is doing work.
 *
 * That second half is the rule `scripts/audit-consumer-resolution.mjs` already
 * applies to its own waiver list — an entry that stops matching fails rather
 * than rots — applied to a finding that instrument's severity floor cannot
 * reach.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const RECORD_PATH = 'docs/security/adm-zip-ghsa-vwc7-r8mq-g2x9.md';

const record = fs.readFileSync(path.join(REPO_ROOT, RECORD_PATH), 'utf8');
/**
 * The record with every run of whitespace flattened to one space. The
 * assertions below are about WORDS, and markdown rewraps prose at will; an
 * assertion that also pins where the paragraph breaks is one that fails on a
 * reflow and teaches the next reader to loosen it.
 */
const flat = record.replace(/\s+/g, ' ');
const lines = (rel: string): string[] =>
  fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8').split('\n');

/**
 * Two of the cited extraction sites are spelled through this rather than as
 * text. Written out, they would be call-site shapes that
 * `adm-zip-call-sites.test.ts` walks the tree for, and this suite would make
 * that one report a first-party call site that is a quotation in a test.
 */
const call = (name: string, args: string): string => `${name}(${args})`;

describe('the adm-zip advisory is recorded as known-open, with its evidence inline', () => {
  it('QGF-254.AC3 the record lives on a surface the attribution gate walks', () => {
    // The repository is public, so this record is covered by the tree's own
    // no-internal-attribution gate rather than by a rule restated here. The
    // surfaces are read out of that gate so the two cannot drift apart.
    const gate = fs
      .readFileSync(path.join(REPO_ROOT, '__tests__', 'gate', 'no-internal-attribution.test.ts'), 'utf8')
      .match(/const SURFACES = \[(.+?)\]/s);
    expect(gate, 'the attribution gate no longer declares its surfaces').not.toBeNull();
    const surfaces = (gate as RegExpMatchArray)[1]
      .split(',')
      .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
      .filter(Boolean);
    expect(surfaces).toContain('docs');
    expect(surfaces).toContain(RECORD_PATH.split('/')[0]);
  });

  it('QGF-254.AC3 it names the advisory and states the verdict in the words that were ruled', () => {
    expect(flat).toContain('GHSA-vwc7-r8mq-g2x9');
    expect(flat).toContain(
      "not reachable through first-party code; reachable inside onnxruntime-node's " +
        'postinstall under the stated conditions',
    );
  });

  it('QGF-254.AC3 it never calls the advisory settled and never calls it out of reach', () => {
    // Both words would be false. There is no patched version to move to, and
    // the postinstall path IS reached — just not from first-party code.
    expect(record.toLowerCase()).not.toContain('unreachable');
    expect(record.toLowerCase()).not.toContain('fixed');
  });

  it('QGF-254.AC3 it states the single edge into this tree, inline', () => {
    expect(flat).toContain('onnxruntime-node@1.27.0');
    expect(flat).toContain('adm-zip: ^0.5.16');
    expect(flat).toContain('package-lock.json:2628');
    expect(flat).toContain('"hasInstallScript": true');
  });

  it('QGF-254.AC3 it states that this tree pins the package and that the pin reaches no consumer', () => {
    expect(flat).toContain('adm-zip: ^0.6.0');
    expect(flat).toContain('package.json:69');
    expect(flat).toContain('package-lock.json:1244-1246');
    expect(flat).toContain('0.6.1');
    expect(flat).toContain('only to the tree that declares it');
    expect(flat).toContain('`overrides` are not published');
    // The consumer's resolution is MEASURED by the script, never asserted here.
    expect(flat).toContain('scripts/audit-consumer-resolution.mjs');
    expect(flat).toContain('it is not asserted by this file');
  });

  it('QGF-254.AC3 it states that no first-party module calls the package', () => {
    expect(flat).toContain('No module under `src/` imports, requires, dynamically imports or calls');
    expect(flat).toContain('__tests__/supply-chain/adm-zip-call-sites.test.ts');
  });

  it('QGF-254.AC3 it states that the postinstall requires the package before any early exit', () => {
    expect(flat).toContain('script/install.js:22');
    expect(flat).toContain('install-utils.js:11');
    expect(flat).toContain('before any early exit');
  });

  it('QGF-254.AC3 it states the extraction, its overwrite and its predictable destination', () => {
    expect(flat).toContain('install-utils.js:156');
    expect(flat).toContain(call('new AdmZip', 'packageFilePath'));
    expect(flat).toContain('install-utils.js:183');
    expect(flat).toContain(call('extractEntryTo', 'zipEntry, extractDir, false, true'));
    expect(flat).toContain('overwrite, and it is true');
    expect(flat).toContain('os.tmpdir()');
    expect(flat).toContain('recursive mkdir');
  });

  it('QGF-254.AC3 it states the conditions the extraction runs under, and who the actor is', () => {
    expect(flat).toContain('default linux/x64 install');
    expect(flat).toContain('cuda12');
    expect(flat).toContain('not bundled in the npm');
    expect(flat).toContain('--onnxruntime-node-install');
    expect(flat).toContain('ONNXRUNTIME_NODE_INSTALL');
    expect(flat).toContain('local user of the same host');
  });

  it('QGF-254.AC3 it states why neither instrument can report the finding', () => {
    expect(flat).toContain('.github/workflows/dependency-audit.yml:81');
    expect(flat).toContain('npm audit --package-lock-only --audit-level=high');
    expect(flat).toContain('scripts/audit-consumer-resolution.mjs:139');
    expect(flat).toContain("if (v.severity !== 'high' && v.severity !== 'critical') continue;");
    expect(flat).toContain('holds zero entries');
    expect(flat).toContain('.github/workflows/dependency-audit.yml:24-28');
  });

  it('QGF-254.AC3 the two instrument citations really are those lines today', () => {
    expect(lines('.github/workflows/dependency-audit.yml')[80].trim()).toBe(
      'run: npm audit --package-lock-only --audit-level=high',
    );
    expect(lines('scripts/audit-consumer-resolution.mjs')[138].trim()).toBe(
      "if (v.severity !== 'high' && v.severity !== 'critical') continue;",
    );
  });

  it('QGF-254.AC3 the waiver list it says is empty really is empty', () => {
    const script = fs.readFileSync(
      path.join(REPO_ROOT, 'scripts', 'audit-consumer-resolution.mjs'),
      'utf8',
    );
    const block = script.match(/const ALLOWED = \[(.*?)\n\];/s);
    expect(block, 'the waiver list is no longer declared as an array literal').not.toBeNull();
    const entries = (block as RegExpMatchArray)[1]
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && l.indexOf('//') !== 0);
    expect(entries, `the waiver list now holds: ${entries.join(' | ')}`).toEqual([]);
  });

  it('QGF-254.AC3 the three manifest citations really are those lines today', () => {
    expect(lines('package.json')[68].trim()).toBe('"adm-zip": "^0.6.0",');
    expect(lines('package-lock.json')[2627].trim()).toBe('"adm-zip": "^0.5.16",');
    expect(lines('package-lock.json')[1243].trim()).toBe('"node_modules/adm-zip": {');
    expect(lines('package-lock.json')[1244].trim()).toBe('"version": "0.6.1",');
  });

  it('QGF-254.AC3 it carries the advisory facts only beside their read date and re-read command', () => {
    expect(flat).toContain('are not derivable from this repository');
    expect(flat).toContain('read a live advisory');
    expect(flat).toContain('Read on **2026-09-19**');
    expect(flat).toContain('CVE-2026-76845');
    expect(flat).toContain('medium, CVSS 3.1 6.5');
    expect(flat).toContain('AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N');
    expect(flat).toContain('>= 0.5.9, <= 0.6.0');
    expect(flat).toContain('patched version in the database: none');
    expect(flat).toContain(
      'gh api /advisories/GHSA-vwc7-r8mq-g2x9 ' +
        '--jq \'.vulnerabilities[]|select(.package.name=="adm-zip")|.first_patched_version\'',
    );
    expect(flat).toContain('A non-null answer from that command reopens this entry');
  });

  it('QGF-254.AC3 it cites the ruling behind these readings by its stamp', () => {
    expect(flat).toContain('2026-09-19T18:08:05Z');
  });
});

// ---------------------------------------------------------------------------
// QGF-254.AC4 — the four readings cannot go stale unwitnessed
// ---------------------------------------------------------------------------

interface Readings {
  'declarer count': string;
  'declaring path': string;
  'declared range': string;
  'resolved version': string;
}

const FIELDS: ReadonlyArray<keyof Readings> = [
  'declarer count',
  'declaring path',
  'declared range',
  'resolved version',
];

const DEPENDENCY_FIELDS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

/** What the record states, read out of the record itself. */
function statedReadings(text: string): Readings {
  const out = {} as Readings;
  for (const field of FIELDS) {
    const found = text.match(new RegExp(`^- ${field}: \`(.+)\`$`, 'm'));
    expect(found, `the record no longer states a "${field}"`).not.toBeNull();
    out[field] = (found as RegExpMatchArray)[1];
  }
  return out;
}

/** What `package-lock.json` carries. */
function lockfileReadings(lock: any): Readings {
  const declarers: Array<[string, string]> = [];
  for (const [where, entry] of Object.entries(lock.packages ?? {})) {
    for (const field of DEPENDENCY_FIELDS) {
      const range = (entry as any)?.[field]?.['adm-zip'];
      if (typeof range === 'string') declarers.push([where, range]);
    }
  }
  declarers.sort((a, b) => a[0].localeCompare(b[0]));
  return {
    'declarer count': String(declarers.length),
    'declaring path': declarers.length === 0 ? '(none)' : declarers.map((d) => d[0]).join(', '),
    'declared range': declarers.length === 0 ? '(none)' : declarers.map((d) => d[1]).join(', '),
    'resolved version': String(lock.packages?.['node_modules/adm-zip']?.version ?? '(absent)'),
  };
}

/** One line per field that moved, naming the field and what the lockfile says. */
function drift(stated: Readings, actual: Readings): string[] {
  return FIELDS.filter((field) => stated[field] !== actual[field]).map(
    (field) =>
      `${field}: ${RECORD_PATH} states "${stated[field]}", package-lock.json now carries ` +
      `"${actual[field]}"`,
  );
}

describe('the record cannot go stale unwitnessed', () => {
  const lockText = fs.readFileSync(path.join(REPO_ROOT, 'package-lock.json'), 'utf8');
  const stated = statedReadings(record);
  const fresh = (): any => JSON.parse(lockText);

  it('QGF-254.AC4 the four readings the record states still match the lockfile', () => {
    const found = drift(stated, lockfileReadings(fresh()));
    expect(found, `the advisory record no longer matches the tree:\n${found.join('\n')}`).toEqual([]);
  });

  it('QGF-254.AC4 the readings are the ones this contract measured at its base', () => {
    // Pinned as literals as well as compared, so a delivery that edits BOTH the
    // record and the lockfile still has to move a number a reader can see.
    expect(stated['declarer count']).toBe('1');
    expect(stated['declaring path']).toBe('node_modules/onnxruntime-node');
    expect(stated['declared range']).toBe('^0.5.16');
    expect(stated['resolved version']).toBe('0.6.1');
  });

  it('QGF-254.AC4 it reds when a second package declares adm-zip, naming the count', () => {
    const lock = fresh();
    lock.packages['node_modules/some-other-thing'] = { dependencies: { 'adm-zip': '^0.5.0' } };
    const found = drift(stated, lockfileReadings(lock));
    expect(found.join('\n')).toContain('declarer count');
    expect(found.join('\n')).toContain('now carries "2"');
  });

  it('QGF-254.AC4 it reds when the declaring path moves, naming the path', () => {
    const lock = fresh();
    lock.packages['node_modules/elsewhere'] = lock.packages['node_modules/onnxruntime-node'];
    delete lock.packages['node_modules/onnxruntime-node'];
    const found = drift(stated, lockfileReadings(lock));
    expect(found.join('\n')).toContain('declaring path');
    expect(found.join('\n')).toContain('now carries "node_modules/elsewhere"');
  });

  it('QGF-254.AC4 it reds when the declared range moves, naming the range', () => {
    const lock = fresh();
    lock.packages['node_modules/onnxruntime-node'].dependencies['adm-zip'] = '^0.7.0';
    const found = drift(stated, lockfileReadings(lock));
    expect(found.join('\n')).toContain('declared range');
    expect(found.join('\n')).toContain('now carries "^0.7.0"');
  });

  it('QGF-254.AC4 it reds when the resolved version moves, naming the version', () => {
    const lock = fresh();
    lock.packages['node_modules/adm-zip'].version = '0.6.2';
    const found = drift(stated, lockfileReadings(lock));
    expect(found.join('\n')).toContain('resolved version');
    expect(found.join('\n')).toContain('now carries "0.6.2"');
  });
});
