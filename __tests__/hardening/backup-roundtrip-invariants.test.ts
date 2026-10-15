/**
 * The round trip every `secure --fix` backup has to survive, checked on
 * generated trees instead of one hand-built case at a time.
 *
 * Each tree is built from a seed: credential configs a fix rewrites (some
 * nested, some holding a byte that is not UTF-8, one sometimes reached through
 * an in-tree symlink), a `.env` whose mode alone can draw a fix, files the fix
 * creates (`.gitignore`, `.env.example`, `SOUL.md`) or already finds, files no
 * fix touches (text and non-UTF-8, modes 600, 644 and 755, nested), a symlink,
 * and a `.hmaignore` rule that excludes a path a fix would otherwise write.
 *
 * `secure --fix` runs the way the CLI runs it: the scan, then the governance
 * step through the same instance's guard (with the CLI's `.hmaignore` check in
 * front of it), then the created-file record. `rollback` follows. Five
 * properties are asserted on every tree:
 *
 *   (a) after rollback every entry has its original bytes and mode, and every
 *       file the fix created is gone;
 *   (b) the run's backup holds a copy of exactly the files the fix changed,
 *       and a mode-only record of exactly the files whose mode alone changed;
 *   (c) no backup path is inside the scanned tree, and a store root inside it
 *       is refused;
 *   (d) no write lands on a path a `.hmaignore` rule excludes;
 *   (e) a relative store root, a store another account created, and a store
 *       root other accounts can write without the sticky bit are refused, and
 *       the tree is left exactly as it was.
 *
 * Every assertion message starts with the tree's seed. A tree is replayed by
 * its test name: `npx vitest run <this file> -t "seed 42$"`.
 *
 * Another account cannot be created here, so the store that "another account
 * created" is a real directory whose `lstat` and `stat` report another uid.
 * Only the ownership is simulated; every file and mode is real.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, readlinkSync, realpathSync, symlinkSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';
import type { ScanResult } from '../../src/hardening/security-check';
import { SoulScanner } from '../../src/soul/scanner';
import { countsAgainstScore } from '../../src/ui/verdict-band';
import { tempDir } from '../helpers/temp-dir';
import { latestStoreRun, storeDirOf, storeRuns } from '../helpers/backup-store';

/** The paths that report another account's uid while a tree runs. */
const owners = vi.hoisted(() => ({ foreign: new Set<string>() }));

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>();
  type StatFn = (p: unknown, opts?: { bigint?: boolean }) => Promise<{ uid: number | bigint }>;
  const otherOwner = (real: StatFn) => vi.fn(async (p: unknown, opts?: { bigint?: boolean }) => {
    const st = await real(p, opts);
    if (!owners.foreign.has(String(p))) return st;
    const uid = typeof st.uid === 'bigint' ? st.uid + 1n : st.uid + 1;
    return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid });
  });
  return {
    ...actual,
    lstat: otherOwner(actual.lstat as unknown as StatFn),
    stat: otherOwner(actual.stat as unknown as StatFn),
  };
});

// ---------------------------------------------------------------------------
// The generator
// ---------------------------------------------------------------------------

/** A small seeded generator (mulberry32), so a tree is a pure function of its seed. */
function seeded(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MODES = [0o600, 0o644, 0o755] as const;
const CREDENTIAL_PATHS = ['config.json', 'settings.json', 'src/config.json', 'services/api/config.json'] as const;
const BYSTANDER_DIRS = ['', 'docs', 'assets', 'lib/a', 'lib/a/b/c'] as const;
const BYSTANDER_NAMES = ['notes.txt', 'data.bin', 'run.sh', 'table.csv', 'blob.raw'] as const;
const WORDS = ['alpha', 'river', 'stone', 'quiet', 'ledger', 'harbor', 'violet', 'orbit', 'maple', 'signal'] as const;
const TOKEN_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** The `.hmaignore` rule shapes a tree can carry, each excluding a path some fix would write. */
const RULES = ['dir', 'path', 'path-check', 'env', 'governance', 'gitignore'] as const;
type Rule = (typeof RULES)[number];

/** The store conditions `--fix` must refuse. Every fifth seed takes one of them. */
const REFUSALS = ['relative', 'foreign', 'shared-root', 'inside-tree'] as const;
type Refusal = (typeof REFUSALS)[number];

interface FileSpec { rel: string; bytes: Buffer; mode: number }
interface LinkSpec { rel: string; target: string }

interface TreeSpec {
  seed: number;
  store: 'private' | Refusal;
  files: FileSpec[];
  links: LinkSpec[];
  rule?: Rule;
  /** Tree-relative paths a `.hmaignore` rule excludes. A trailing `/` names everything below it. */
  excluded: string[];
}

function treeSpec(seed: number): TreeSpec {
  const rnd = seeded(seed);
  const int = (n: number): number => Math.floor(rnd() * n);
  const pick = <T,>(xs: readonly T[]): T => xs[int(xs.length)];
  const chance = (p: number): boolean => rnd() < p;
  const shuffled = <T,>(xs: readonly T[]): T[] => {
    const out = [...xs];
    for (let i = out.length - 1; i > 0; i--) {
      const j = int(i + 1);
      [out[i], out[j]] = [out[j], out[i]];
    }
    return out;
  };

  const files = new Map<string, FileSpec>();
  const put = (rel: string, bytes: Buffer, mode: number = pick(MODES)): void => {
    files.set(rel, { rel, bytes, mode });
  };
  const links: LinkSpec[] = [];
  const excluded: string[] = [];
  const ignoreLines: string[] = [];

  /** A token assembled at run time, never a literal in the source tree. */
  const token = (): string => `ghp_${Array.from({ length: 36 }, () => TOKEN_ALPHABET[int(TOKEN_ALPHABET.length)]).join('')}`;
  const credentialConfig = (): Buffer => {
    const head = `{\n  "githubToken": "${token()}",\n  "port": ${1024 + int(60000)}`;
    // 0xE9 alone is not UTF-8: a fix that reads the file as text and writes it
    // back changes these bytes, and only a byte-exact copy can put them back.
    const tail = chance(0.35)
      ? Buffer.concat([Buffer.from(',\n  "owner": "caf'), Buffer.from([0xe9]), Buffer.from('"\n}\n')])
      : Buffer.from('\n}\n');
    return Buffer.concat([Buffer.from(head), tail]);
  };
  const text = (): Buffer => Buffer.from(
    `${Array.from({ length: 3 + int(12) }, () => pick(WORDS)).join(' ')}\n`,
  );
  /** Bytes that are never valid UTF-8: 0xFF cannot appear in it at all. */
  const nonUtf8 = (): Buffer => Buffer.from([0xff, ...Array.from({ length: 8 + int(120) }, () => int(256)), 0xfe]);
  const governanceText = (): Buffer => Buffer.from(`# Agent\n\nBe helpful. ${pick(WORDS)}.\n`);

  // Credentials a fix rewrites: one to three configs, some of them nested.
  const credentials = shuffled(CREDENTIAL_PATHS).slice(0, 1 + int(3));
  for (const rel of credentials) put(rel, credentialConfig());
  // A credential config reached through an in-tree link: the fix writes the
  // file the link names, and the link itself must still be a link afterwards.
  if (!credentials.includes('config.json') && chance(0.3)) {
    put('real/config.json', credentialConfig());
    links.push({ rel: 'config.json', target: path.join('real', 'config.json') });
  }

  // Only its mode can draw a fix.
  if (chance(0.8)) put('.env', Buffer.from(`PORT=${1024 + int(60000)}\nLOG_LEVEL=info\n`));

  // Absent (a fix creates it), present without the entries a fix adds, or complete.
  const gitignore = int(3);
  if (gitignore === 1) put('.gitignore', Buffer.from('node_modules/\n'));
  if (gitignore === 2) put('.gitignore', Buffer.from('node_modules/\n.env\n.env.local\n*.pem\n'));

  // Absent (the governance step creates SOUL.md), or present (it appends to it).
  const governance = int(3);
  if (governance === 1) put('SOUL.md', governanceText());
  if (governance === 2) put('CLAUDE.md', governanceText());

  if (chance(0.5)) put('package.json', Buffer.from(`{"name":"tree-${seed}","version":"1.0.0"}\n`));

  // Files no fix touches.
  const bystanders: string[] = [];
  const count = 1 + int(5);
  for (let i = 0; i < count; i++) {
    const rel = path.join(pick(BYSTANDER_DIRS), `${i}-${pick(BYSTANDER_NAMES)}`);
    put(rel, chance(0.5) ? text() : nonUtf8());
    bystanders.push(rel);
  }
  if (chance(0.6)) {
    const to = pick(bystanders);
    links.push({ rel: path.join('docs', 'latest'), target: path.relative('docs', to) });
  }

  let rule: Rule | undefined;
  if (chance(0.6)) {
    rule = pick(RULES);
    switch (rule) {
      case 'dir':
        put('fixtures/config.json', credentialConfig());
        ignoreLines.push('fixtures/');
        excluded.push('fixtures/');
        break;
      case 'path':
        put('fixtures/config.json', credentialConfig());
        ignoreLines.push('fixtures/config.json');
        excluded.push('fixtures/config.json');
        break;
      case 'path-check':
        // 0600, so no check other than the one the rule names has a fix to apply to it.
        put('fixtures/config.json', credentialConfig(), 0o600);
        // A rule that names a check is applied only with a reason after it.
        ignoreLines.push('fixtures/config.json:CRED-001 # sample credentials');
        excluded.push('fixtures/config.json');
        break;
      case 'env':
        put('.env', Buffer.from('PORT=8080\nLOG_LEVEL=debug\n'), pick([0o644, 0o755]));
        ignoreLines.push('.env');
        excluded.push('.env');
        break;
      case 'governance':
        // No governance file, so the governance step would create SOUL.md.
        files.delete('SOUL.md');
        files.delete('CLAUDE.md');
        ignoreLines.push('SOUL.md');
        excluded.push('SOUL.md');
        break;
      case 'gitignore':
        files.delete('.gitignore');
        ignoreLines.push('.gitignore');
        excluded.push('.gitignore');
        break;
    }
    put('.hmaignore', Buffer.from(`# generated for seed ${seed}\n${ignoreLines.join('\n')}\n`), 0o644);
  }

  const store = seed % 5 === 0 ? REFUSALS[Math.floor(seed / 5) % REFUSALS.length] : 'private';
  return { seed, store, files: [...files.values()], links, rule, excluded };
}

function materialize(spec: TreeSpec): string {
  const dir = tempDir(`hma-roundtrip-${spec.seed}-`);
  for (const f of spec.files) {
    const p = path.join(dir, f.rel);
    mkdirSync(path.dirname(p), { recursive: true });
    writeFileSync(p, f.bytes);
    chmodSync(p, f.mode);
  }
  for (const l of spec.links) {
    const p = path.join(dir, l.rel);
    mkdirSync(path.dirname(p), { recursive: true });
    symlinkSync(l.target, p);
  }
  return dir;
}

// ---------------------------------------------------------------------------
// Observing a tree
// ---------------------------------------------------------------------------

type Entry =
  | { kind: 'file'; sha: string; mode: number; utf8: boolean }
  | { kind: 'link'; target: string }
  | { kind: 'dir'; mode: number };

const sha = (bytes: Buffer): string => createHash('sha256').update(bytes).digest('hex');
const isUtf8 = (bytes: Buffer): boolean => Buffer.from(bytes.toString('utf-8'), 'utf-8').equals(bytes);
const octal = (m: number): string => m.toString(8).padStart(4, '0');

/** Every entry under `root` by `lstat`: links are recorded as links and never followed. */
function snapshot(root: string): Map<string, Entry> {
  const out = new Map<string, Entry>();
  const walk = (rel: string): void => {
    for (const name of readdirSync(path.join(root, rel)).sort()) {
      const r = rel ? path.join(rel, name) : name;
      const p = path.join(root, r);
      const st = lstatSync(p);
      if (st.isSymbolicLink()) out.set(r, { kind: 'link', target: readlinkSync(p) });
      else if (st.isDirectory()) {
        out.set(r, { kind: 'dir', mode: st.mode & 0o7777 });
        walk(r);
      } else {
        const bytes = readFileSync(p);
        out.set(r, { kind: 'file', sha: sha(bytes), mode: st.mode & 0o7777, utf8: isUtf8(bytes) });
      }
    }
  };
  walk('');
  return out;
}

const describeEntry = (e: Entry | undefined): string => {
  if (!e) return 'absent';
  if (e.kind === 'link') return `link -> ${e.target}`;
  if (e.kind === 'dir') return `dir ${octal(e.mode)}`;
  return `file ${octal(e.mode)} ${e.sha.slice(0, 12)}`;
};

const sameEntry = (a: Entry | undefined, b: Entry | undefined): boolean => describeEntry(a) === describeEntry(b);

/** Every path whose entry differs between two snapshots, described both ways. */
function differences(before: Map<string, Entry>, after: Map<string, Entry>): string[] {
  const out: string[] = [];
  for (const rel of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const a = before.get(rel);
    const b = after.get(rel);
    if (!sameEntry(a, b)) out.push(`${rel}: ${describeEntry(a)} -> ${describeEntry(b)}`);
  }
  return out;
}

const isWithin = (child: string, parent: string): boolean => {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
};

const coveredBy = (rel: string, excluded: readonly string[]): boolean =>
  excluded.some((x) => (x.endsWith('/') ? rel === x.slice(0, -1) || rel.startsWith(x) : rel === x));

interface Manifest {
  existingFiles: string[];
  existingFileModes?: Record<string, number>;
  modeOnlyFiles?: Record<string, number>;
  absentAtBackup: string[];
  absentAtFixWrite?: string[];
  createdFiles: Array<{ path: string; sha256: string }>;
}

const readManifest = (run: string): Manifest =>
  JSON.parse(readFileSync(path.join(run, '.manifest.json'), 'utf-8')) as Manifest;

/** Every file a run directory holds besides its manifest, run-relative. */
function filesIn(run: string, rel = ''): string[] {
  const out: string[] = [];
  for (const e of readdirSync(path.join(run, rel), { withFileTypes: true })) {
    const r = rel ? path.join(rel, e.name) : e.name;
    if (e.isDirectory()) out.push(...filesIn(run, r));
    else if (r !== '.manifest.json') out.push(r);
  }
  return out.sort();
}

// ---------------------------------------------------------------------------
// The two commands, as the CLI runs them
// ---------------------------------------------------------------------------

/**
 * `secure --fix <dir>` in its text format: the scan, then the governance step
 * through the same instance's guard with the `.hmaignore` check the CLI puts in
 * front of it, then the created-file record for what that step wrote.
 *
 * The CLI runs the governance step when the scan reports a governance finding,
 * and those come from the semantic pass this in-process scan does not run. So
 * the step runs on every tree here, as the run-time census in
 * backup-holds-only-changed-files.test.ts runs it: every tree the CLI would
 * harden is hardened, and so are the rest.
 */
async function secureFix(dir: string): Promise<ScanResult> {
  const scanner = new HardeningScanner();
  const result = await scanner.scan({ targetDir: dir, autoFix: true });
  const govFindings = result.findings.filter((f) => countsAgainstScore(f)).filter((f) =>
    f.category === 'governance' || f.category === 'Governance'
    || f.checkId?.startsWith('AST-GOV') || f.checkId?.startsWith('SOUL-'));
  const hardened = await new SoulScanner().hardenSoul(dir, {
    dryRun: false,
    writeGuard: async (rel: string) => {
      const excluded = await scanner.excludeGovernanceWrite(dir, rel, govFindings.map((f) => f.checkId));
      if (excluded) {
        const listed = (result.fixWritesExcluded ??= []);
        if (!listed.some((e) => e.file === excluded.file && e.line === excluded.line)) listed.push(excluded);
        return { refused: `excluded by .hmaignore:${excluded.line} \`${excluded.rule}\`` };
      }
      return scanner.ensureGovernanceBackup(dir, rel);
    },
  });
  if (hardened.sectionsAdded && hardened.sectionsAdded.length > 0) {
    await scanner.recordCreatedFiles(dir, result.backupPath, [hardened.file ?? 'SOUL.md']);
  }
  return result;
}

// ---------------------------------------------------------------------------
// What the trees exercised, so a generator that stops producing a case fails
// the last cell instead of passing every other one with nothing measured.
// ---------------------------------------------------------------------------

const exercised = {
  roundTrips: 0,
  copiesRestored: 0,
  copiesRestoredByMode: { '0600': 0, '0644': 0, '0755': 0 } as Record<string, number>,
  nonUtf8CopiesRestored: 0,
  nestedCopiesRestored: 0,
  modesRestored: { '0644': 0, '0755': 0 } as Record<string, number>,
  createdRemoved: 0,
  writesThroughLink: 0,
  linksKept: 0,
  untouchedKept: 0,
  excludedWritesRefused: Object.fromEntries(RULES.map((r) => [r, 0])) as Record<Rule, number>,
  refusals: Object.fromEntries(REFUSALS.map((r) => [r, 0])) as Record<Refusal, number>,
};

// ---------------------------------------------------------------------------
// The cells
// ---------------------------------------------------------------------------

async function roundTrip(spec: TreeSpec): Promise<void> {
  const tag = `seed ${spec.seed}`;
  const dir = materialize(spec);
  const dirReal = realpathSync(dir);
  const before = snapshot(dir);

  const result = await secureFix(dir);
  const fixed = snapshot(dir);
  const changes = differences(before, fixed);
  expect(changes.length, `${tag}: the fix changed nothing in the tree; this tree measures nothing`).toBeGreaterThan(0);

  // (c) The path the scan reports for the run, and the run directory in the
  // store, are outside the tree, and the tree gained no backup directory.
  expect(result.backupPath, `${tag}: the scan reported no backup`).toBeDefined();
  expect(isWithin(realpathSync(result.backupPath as string), dirReal), `${tag}: the reported backup is inside the scanned tree`)
    .toBe(false);
  expect([...fixed.keys()].filter((rel) => rel.split(path.sep).includes('.hackmyagent-backup')), `${tag}: a backup directory appeared in the tree`)
    .toEqual([]);
  const run = await latestStoreRun(dir);
  expect(realpathSync(run), `${tag}: the run in the store is not the backup the scan reported`).toBe(realpathSync(result.backupPath as string));
  expect(isWithin(realpathSync(run), dirReal), `${tag}: the run directory ${run} is inside the scanned tree`).toBe(false);

  // What the fix did, read from the tree itself.
  const contentChanged: string[] = [];
  const modeChanged: string[] = [];
  const created: string[] = [];
  const removed: string[] = [];
  const otherChanges: string[] = [];
  for (const rel of [...new Set([...before.keys(), ...fixed.keys()])].sort()) {
    const a = before.get(rel);
    const b = fixed.get(rel);
    if (sameEntry(a, b)) continue;
    if (a?.kind === 'file' && b?.kind === 'file') {
      if (a.sha !== b.sha) contentChanged.push(rel);
      else modeChanged.push(rel);
    } else if (!a && b?.kind === 'file') created.push(rel);
    else if (a && !b) removed.push(rel);
    else otherChanges.push(`${rel}: ${describeEntry(a)} -> ${describeEntry(b)}`);
  }
  expect(removed, `${tag}: the fix removed entries from the tree`).toEqual([]);
  expect(otherChanges, `${tag}: the fix changed an entry's kind, or a link or directory`).toEqual([]);

  // (b) The run holds a copy of exactly the files whose bytes changed, with the
  // bytes and mode they had before the fix, and a mode-only record of exactly
  // the files whose mode alone changed.
  const manifest = readManifest(run);
  expect(filesIn(run), `${tag}: the run's copies are not the files the fix changed`).toEqual(contentChanged);
  expect([...manifest.existingFiles].sort(), `${tag}: existingFiles is not the files the fix changed`).toEqual(contentChanged);
  for (const rel of contentChanged) {
    const was = before.get(rel) as Extract<Entry, { kind: 'file' }>;
    expect(sha(readFileSync(path.join(run, rel))), `${tag}: ${rel}: the copy is not the pre-fix bytes`).toBe(was.sha);
    expect(manifest.existingFileModes?.[rel], `${tag}: ${rel}: the copy did not record the pre-fix mode`).toBe(was.mode & 0o777);
  }
  expect(Object.keys(manifest.modeOnlyFiles ?? {}).sort(), `${tag}: the mode-only records are not the files whose mode alone changed`)
    .toEqual(modeChanged);
  for (const rel of modeChanged) {
    const was = before.get(rel) as Extract<Entry, { kind: 'file' }>;
    expect(manifest.modeOnlyFiles?.[rel], `${tag}: ${rel}: the mode-only record is not the pre-fix mode`).toBe(was.mode & 0o777);
  }
  const provenAbsent = new Set([...manifest.absentAtBackup, ...(manifest.absentAtFixWrite ?? [])]);
  for (const rel of created) {
    expect(provenAbsent.has(rel), `${tag}: ${rel} was created and never proven absent`).toBe(true);
  }
  expect(manifest.createdFiles.map((c) => c.path).sort(), `${tag}: the created-file record is not the files the fix created`)
    .toEqual(created);

  // (d) Nothing a `.hmaignore` rule excludes was written, created, chmodded or recorded.
  for (const rel of new Set([...before.keys(), ...fixed.keys()])) {
    if (!coveredBy(rel, spec.excluded)) continue;
    expect(describeEntry(fixed.get(rel)), `${tag}: ${rel} is excluded by .hmaignore and the fix changed it`)
      .toBe(describeEntry(before.get(rel)));
  }
  const recorded = [
    ...manifest.existingFiles, ...Object.keys(manifest.modeOnlyFiles ?? {}), ...manifest.createdFiles.map((c) => c.path),
  ];
  expect(recorded.filter((rel) => coveredBy(rel, spec.excluded)), `${tag}: the run recorded a change to an excluded path`).toEqual([]);
  if (spec.rule && (result.fixWritesExcluded ?? []).some((e) => coveredBy(e.file, spec.excluded))) {
    exercised.excludedWritesRefused[spec.rule]++;
  }

  // (a) Rollback puts back every byte and mode, removes what the fix created,
  // reports nothing it could not do, and consumes the run.
  const report = await new HardeningScanner().rollback(dir);
  const after = snapshot(dir);
  expect(differences(before, after), `${tag}: after rollback the tree differs from the tree before the fix`).toEqual([]);
  expect(report.backupSource, `${tag}: rollback did not use the store`).toBe('store');
  expect(report.unrestored, `${tag}: rollback left entries unrestored`).toEqual([]);
  expect(report.unremoved, `${tag}: rollback left generated files it could not remove`).toEqual([]);
  expect(report.keptModified, `${tag}: rollback kept generated files as modified`).toEqual([]);
  expect(report.keptUnverifiable, `${tag}: rollback kept files it could not verify`).toEqual([]);
  expect([...report.restored].sort(), `${tag}: rollback restored other files than the run held`).toEqual(contentChanged);
  expect([...report.removed].sort(), `${tag}: rollback removed other files than the fix created`).toEqual(created);
  expect(await storeRuns(dir), `${tag}: rollback did not consume the run`).toEqual([]);

  exercised.roundTrips++;
  for (const rel of contentChanged) {
    const was = before.get(rel) as Extract<Entry, { kind: 'file' }>;
    exercised.copiesRestored++;
    exercised.copiesRestoredByMode[octal(was.mode)] = (exercised.copiesRestoredByMode[octal(was.mode)] ?? 0) + 1;
    if (!was.utf8) exercised.nonUtf8CopiesRestored++;
    if (rel.includes(path.sep)) exercised.nestedCopiesRestored++;
    if (spec.links.some((l) => path.normalize(path.join(path.dirname(l.rel), l.target)) === rel)) exercised.writesThroughLink++;
  }
  for (const rel of modeChanged) {
    const was = before.get(rel) as Extract<Entry, { kind: 'file' }>;
    exercised.modesRestored[octal(was.mode)] = (exercised.modesRestored[octal(was.mode)] ?? 0) + 1;
  }
  exercised.createdRemoved += created.length;
  exercised.linksKept += spec.links.length;
  exercised.untouchedKept += [...before.keys()].filter((rel) => before.get(rel)?.kind === 'file' && sameEntry(before.get(rel), fixed.get(rel))).length;
}

/** A run another account could have written: a manifest naming `config.json`, and a copy that says it was planted. */
function plantForeignRun(store: string): void {
  const run = path.join(store, '2026-01-01-000000000-000-abcdef12');
  mkdirSync(run, { recursive: true });
  writeFileSync(path.join(run, '.manifest.json'), JSON.stringify({
    version: 2, existingFiles: ['config.json'], existingFileModes: { 'config.json': 0o644 }, absentAtBackup: [], createdFiles: [],
  }));
  writeFileSync(path.join(run, 'config.json'), '{"planted": true}\n');
}

async function refusedStore(spec: TreeSpec, refusal: Refusal): Promise<void> {
  const tag = `seed ${spec.seed} (${refusal} store)`;
  const dir = materialize(spec);
  const before = snapshot(dir);
  const savedHome = process.env.HMA_BACKUP_HOME;
  let check: () => void = () => {};
  try {
    switch (refusal) {
      case 'relative': {
        // Relative, but naming a scratch directory, so a root wrongly taken
        // from it would land somewhere this cell can see and clean up.
        const scratch = path.join(tempDir('hma-roundtrip-relative-'), 'store');
        process.env.HMA_BACKUP_HOME = path.relative(process.cwd(), scratch);
        expect(path.isAbsolute(process.env.HMA_BACKUP_HOME), `${tag}: the root is not relative; this cell measures nothing`).toBe(false);
        check = () => expect(existsSync(scratch), `${tag}: a store was created under a relative root`).toBe(false);
        break;
      }
      case 'foreign': {
        const store = await storeDirOf(dir);
        mkdirSync(store, { recursive: true, mode: 0o700 });
        plantForeignRun(store);
        const planted = snapshot(store);
        owners.foreign.add(store);
        check = () => expect(differences(planted, snapshot(store)), `${tag}: the other account's store was written to`).toEqual([]);
        break;
      }
      case 'shared-root': {
        const root = tempDir('hma-roundtrip-shared-');
        chmodSync(root, 0o777);
        process.env.HMA_BACKUP_HOME = root;
        check = () => expect(readdirSync(root), `${tag}: a store was created under a root other accounts can write`).toEqual([]);
        break;
      }
      case 'inside-tree':
        process.env.HMA_BACKUP_HOME = path.join(dir, '.hma-store');
        break;
    }

    const result = await secureFix(dir);
    expect(
      result.findings.filter((f) => f.checkId === 'FIX-BACKUP-FAILED').length,
      `${tag}: --fix did not report that it could not take a backup`,
    ).toBe(1);
    expect(result.backupPath, `${tag}: --fix reported a backup`).toBeUndefined();
    expect(differences(before, snapshot(dir)), `${tag}: --fix wrote to the tree with no backup this account owns`).toEqual([]);

    await expect(new HardeningScanner().rollback(dir), `${tag}: rollback did not refuse`).rejects.toThrow();
    expect(differences(before, snapshot(dir)), `${tag}: rollback wrote to the tree`).toEqual([]);
    check();
  } finally {
    owners.foreign.clear();
    if (savedHome === undefined) delete process.env.HMA_BACKUP_HOME;
    else process.env.HMA_BACKUP_HOME = savedHome;
  }
  exercised.refusals[refusal]++;
}

const TREES = 250;
const SEEDS = Array.from({ length: TREES }, (_, i) => i + 1);

describe.skipIf(process.platform === 'win32')('secure --fix then rollback, on generated trees', () => {
  afterEach(() => {
    owners.foreign.clear();
  });

  it.each(SEEDS)('seed %i', async (seed) => {
    const spec = treeSpec(seed);
    if (spec.store === 'private') await roundTrip(spec);
    else await refusedStore(spec, spec.store);
  }, 60_000);

  it('the generated trees exercised every cell', () => {
    expect(exercised.roundTrips, 'fewer than 200 trees made the full round trip').toBeGreaterThanOrEqual(200);
    for (const [mode, n] of Object.entries(exercised.copiesRestoredByMode)) {
      expect(n, `no copy of a ${mode} file was restored`).toBeGreaterThan(0);
    }
    expect(exercised.nonUtf8CopiesRestored, 'no non-UTF-8 file a fix changed was restored').toBeGreaterThan(0);
    expect(exercised.nestedCopiesRestored, 'no nested file a fix changed was restored').toBeGreaterThan(0);
    for (const [mode, n] of Object.entries(exercised.modesRestored)) {
      expect(n, `no mode-only change from ${mode} was restored`).toBeGreaterThan(0);
    }
    expect(exercised.createdRemoved, 'no file the fix created was removed').toBeGreaterThan(0);
    expect(exercised.writesThroughLink, 'no fix wrote through an in-tree link').toBeGreaterThan(0);
    expect(exercised.linksKept, 'no tree held a symlink').toBeGreaterThan(0);
    expect(exercised.untouchedKept, 'no tree held a file the fix left alone').toBeGreaterThan(0);
    for (const [rule, n] of Object.entries(exercised.excludedWritesRefused)) {
      expect(n, `no write a ${rule} .hmaignore rule excludes was refused`).toBeGreaterThan(0);
    }
    for (const [refusal, n] of Object.entries(exercised.refusals)) {
      expect(n, `no ${refusal} store was refused`).toBeGreaterThanOrEqual(5);
    }
  });
});
