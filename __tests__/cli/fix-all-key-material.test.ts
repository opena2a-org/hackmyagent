/**
 * #534 / #431 — `fix-all` leaves no private key inside the tree it fixes.
 *
 * Measured before the fix (2026-08-24, 0.32.0): `fix-all --with-aim` on a
 * fresh `git init` tree wrote the Ed25519 identity (secret key included) to
 * `.opena2a/aim/identity.json` and an AES key to `.opena2a/credvault/store.key`,
 * both staged by `git add -A`, no `.gitignore` written, and the only message
 * called them "plugin data". `--dry-run --with-aim` still wrote
 * `.opena2a/aim/audit.jsonl` into the tree.
 *
 * Every spawn here isolates HOME and OPENA2A_HOME: without that, a run writes a
 * real identity into the developer's own ~/.opena2a.
 *
 * The credential is synthesized at run time from a fixed seed and never
 * committed: the detector skips FAKE/PLACEHOLDER markers, and a real-shaped
 * key in a public repo is worse. The allowlist of in-tree writes below is
 * hand-written on purpose — copied from the implementation it would be a
 * tautology.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';

const PUBLIC_IN_TREE = new Set(['.opena2a/signcrypt/signatures.json', '.opena2a/skillguard/pins.json', '.env.example', 'SKILL.md']);
const B64_88 = /[A-Za-z0-9+/]{86}==/;
const HEX_64_LINE = /^[0-9a-f]{64}\s*$/;

function syntheticKey(): string {
  const alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let seed = 7;
  let body = '';
  for (let i = 0; i < 52; i++) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    body += alpha[seed % alpha.length];
  }
  return `sk-${body}`;
}

function walk(dir: string, base = dir): string[] {
  return readdirSync(dir).flatMap((name) => {
    if (name === '.git') return [];
    const p = path.join(dir, name);
    return statSync(p).isDirectory() ? walk(p, base) : [path.relative(base, p).split(path.sep).join('/')];
  });
}

let root: string;
let home: string;
let opena2aHome: string;

function makeTree(name: string, opts: { git: boolean }): string {
  const dir = path.join(root, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  writeFileSync(path.join(dir, 'SKILL.md'), '---\nname: p\ndescription: root skill\n---\n# P\nhello\n');
  writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ apiKey: syntheticKey() }, null, 2) + '\n');
  // #348 — a fixture repository is created with git isolated from this one
  if (opts.git) initThrowawayRepo(dir);
  return dir;
}

function run(dir: string, args: string[]) {
  const r = spawnSync(process.execPath, [BUILT_CLI, 'fix-all', dir, ...args], {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, OPENA2A_HOME: opena2aHome },
  });
  return { status: r.status, out: String(r.stdout ?? '') + String(r.stderr ?? ''), stdout: String(r.stdout ?? '') };
}

function assertNoPrivateMaterialUnder(dir: string): string[] {
  const files = walk(dir);
  for (const rel of files) {
    const base = path.basename(rel);
    expect(base, `private-material filename under target: ${rel}`).not.toBe('identity.json');
    expect(base, `private-material filename under target: ${rel}`).not.toBe('store.key');
    const text = readFileSync(path.join(dir, rel), 'utf8');
    expect(text, `88-char base64 run (Ed25519 secret shape) in ${rel}`).not.toMatch(B64_88);
    expect(text, `64-hex single line (AES key shape) in ${rel}`).not.toMatch(HEX_64_LINE);
    if (rel.endsWith('.json')) {
      expect(text, `secretKey field in ${rel}`).not.toMatch(/"secretKey"/);
    }
  }
  return files;
}

beforeAll(() => {
  assertDistFresh();
  // real-path form throughout: the CLI reports real paths, and tmpdir is a symlink on macOS
  root = realpathSync.native(mkdtempSync(path.join(tmpdir(), 'hma-534-')));
  home = path.join(root, 'home');
  opena2aHome = path.join(root, 'opena2a-home');
  mkdirSync(home);
  mkdirSync(opena2aHome);
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('fix-all --with-aim leaves no private key in the tree (#534, #431)', () => {
  it('git tree: nothing key-bearing is written under the target; only public files appear, and the identity lands in the user store', () => {
    const dir = makeTree('git-tree', { git: true });
    const before = new Set(walk(dir));
    const { status, out } = run(dir, ['--with-aim']);
    expect(status).toBe(0);

    const after = assertNoPrivateMaterialUnder(dir);
    const written = after.filter((f) => !before.has(f));
    for (const rel of written) {
      expect(PUBLIC_IN_TREE.has(rel), `unexpected in-tree write: ${rel}`).toBe(true);
    }
    const staged = spawnSync('git', ['add', '-A'], { cwd: dir, env: gitFreeEnv() });
    expect(staged.status).toBe(0);
    const porcelain = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: dir, encoding: 'utf8', env: gitFreeEnv() }).stdout;
    expect(porcelain).not.toMatch(/identity\.json|store\.key/);

    // the identity exists in the user store, named in the output, at the path printed
    const stores = readdirSync(path.join(opena2aHome, 'projects'));
    expect(stores).toHaveLength(1);
    const identityPath = path.join(opena2aHome, 'projects', stores[0], 'aim', 'identity.json');
    expect(statSync(identityPath).isFile()).toBe(true);
    expect(out).toContain('Signing identity:');
    expect(out).toContain('(Ed25519, created)');
    expect(out).toContain('outside the project; do not copy it into the tree');
    expect(out).toContain(identityPath);
    expect(out).not.toContain('Plugin data stored');
    expect(out).not.toContain('rm -rf');
    if (process.platform !== 'win32') {
      expect(statSync(path.join(opena2aHome, 'projects', stores[0])).mode & 0o777).toBe(0o700);
      expect(statSync(identityPath).mode & 0o777).toBe(0o600);
    }
    // a second run reuses it and says so
    const again = run(dir, ['--with-aim']);
    expect(again.out).toContain('(Ed25519, reused)');
  });

  it('non-git tree: the same invariant holds without a repository', () => {
    const dir = makeTree('plain-tree', { git: false });
    const before = new Set(walk(dir));
    expect(run(dir, ['--with-aim']).status).toBe(0);
    const written = assertNoPrivateMaterialUnder(dir).filter((f) => !before.has(f));
    for (const rel of written) expect(PUBLIC_IN_TREE.has(rel), `unexpected in-tree write: ${rel}`).toBe(true);
  });

  it('--json names the key path outside the target, the store, and no legacy material', () => {
    const dir = makeTree('json-tree', { git: true });
    const { status, stdout } = run(dir, ['--with-aim', '--json']);
    expect(status).toBe(0);
    const body = JSON.parse(stdout.slice(stdout.indexOf('{')));
    expect(body.privateKeyPaths.identity).toBeTypeOf('string');
    expect(path.isAbsolute(body.privateKeyPaths.identity)).toBe(true);
    expect(path.relative(dir, body.privateKeyPaths.identity).startsWith('..')).toBe(true);
    expect(body.privateKeyPaths.vault).toBeNull();
    expect(body.store.root.startsWith(opena2aHome)).toBe(true);
    expect(body.store.credvaultDir).toBeNull();
    expect(body.store.legacyInTree).toEqual({ identity: { found: false, path: null }, vault: { found: false, path: null } });
    expect(body.legacyKeyMaterial).toEqual([]);
  });

  it('--dry-run and --scan-only write nothing under the target and create no identity', () => {
    for (const flag of ['--dry-run', '--scan-only']) {
      const dir = makeTree(`nowrite${flag}`, { git: true });
      const before = walk(dir).sort();
      const storesBefore = readdirSync(path.join(opena2aHome, 'projects')).length;
      const { status, stdout } = run(dir, ['--with-aim', flag, '--json']);
      // the exit code keeps its meaning (1 while a critical finding would remain — the
      // fixture's credential is not fixed in these modes); what must not change is the disk
      expect([0, 1], flag).toContain(status);
      expect(walk(dir).sort(), `${flag} wrote into the target`).toEqual(before);
      expect(readdirSync(path.join(opena2aHome, 'projects')).length, `${flag} created a store`).toBe(storesBefore);
      const body = JSON.parse(stdout.slice(stdout.indexOf('{')));
      expect(body.privateKeyPaths).toEqual({ identity: null, vault: null });
      // no identity is constructed, so the field that reports one says so
      expect(body.aimEnabled).toBe(false);
    }
  });

  it('read-only modes still scan a target the store would sit inside; only a writing --with-aim refuses', () => {
    const dir = makeTree('self-home-scan', { git: false });
    const env = { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, OPENA2A_HOME: path.join(dir, 'home') };
    const scan = spawnSync(process.execPath, [BUILT_CLI, 'fix-all', dir, '--scan-only', '--json'], { encoding: 'utf8', timeout: 60_000, env });
    const body = JSON.parse(String(scan.stdout).slice(String(scan.stdout).indexOf('{')));
    expect(body.mode).toBe('scan-only');
    expect(body.store).toBeNull();
    expect(body.privateKeyPaths).toEqual({ identity: null, vault: null });
    expect(walk(dir).some((f) => f.startsWith('home/'))).toBe(false);
  });

  it('lists as "safe to commit" only what this run wrote, never a file that merely exists', () => {
    const dir = makeTree('preexisting-example', { git: false });
    // a pre-existing example file with a live-looking value, and no credential finding to rewrite it
    writeFileSync(path.join(dir, '.env.example'), 'DB_PASSWORD=hunter2-realvalue\n');
    writeFileSync(path.join(dir, 'config.json'), '{}\n');
    const { out } = run(dir, []);
    const block = out.slice(out.indexOf('Written to the project'));
    expect(block).not.toContain('.env.example'.slice(1, -1));
  });

  it('SIGN-TIP resolves through the store: absent identity tips creation, present identity names it', () => {
    const dir = makeTree('tip-tree', { git: true });
    const first = run(dir, ['--json']);
    const tips = (body: any) => body.plugins.flatMap((p: any) => p.remediations).filter((r: any) => r.findingId === 'SIGN-TIP');
    const t1 = tips(JSON.parse(first.stdout.slice(first.stdout.indexOf('{'))));
    expect(t1).toHaveLength(1);
    expect(t1[0].description).toContain('stored outside the project');

    // create the identity out of tree, then re-run plain on a tree that still needs signing
    const dir2 = makeTree('tip-tree-2', { git: true });
    expect(run(dir2, ['--with-aim']).status).toBe(0);
    writeFileSync(path.join(dir2, 'HEARTBEAT.md'), '# beat\n');
    const second = run(dir2, ['--json']);
    const t2 = tips(JSON.parse(second.stdout.slice(second.stdout.indexOf('{'))));
    expect(t2).toHaveLength(1);
    expect(t2[0].description).toContain('An identity for this project exists at');
    expect(t2[0].description).toContain(opena2aHome);
  });

  it('a key an earlier version left in the tree is named with its git state, on every channel, and never touched', () => {
    const dir = makeTree('legacy-tree', { git: true });
    const legacy = path.join(dir, '.opena2a', 'aim', 'identity.json');
    mkdirSync(path.dirname(legacy), { recursive: true });
    writeFileSync(legacy, '{"agentName":"FAKE","secretKey":"FAKE-PLACEHOLDER"}\n');
    spawnSync('git', ['add', '.opena2a/aim/identity.json'], { cwd: dir, env: gitFreeEnv() });
    const stat = statSync(legacy);

    const text = run(dir, ['--with-aim']);
    expect(text.status).toBe(0);
    expect(text.out).toContain('Private key inside the project');
    expect(text.out).toContain('(tracked)');
    expect(text.out).toContain('git -C ');
    expect(text.out).toContain('ls-files --error-unmatch');
    expect(text.out).toContain('regenerate');
    expect(text.out).not.toMatch(/remove the key/i);
    expect(statSync(legacy).mtimeMs).toBe(stat.mtimeMs);
    expect(readFileSync(legacy, 'utf8')).toContain('FAKE-PLACEHOLDER');

    const json = run(dir, ['--dry-run', '--json']);
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{')));
    expect(body.legacyKeyMaterial).toEqual([
      { kind: 'identity', path: legacy, relativePath: path.join('.opena2a', 'aim', 'identity.json'), gitState: 'tracked' },
    ]);
    expect(body.store.legacyInTree.identity).toEqual({ found: true, path: legacy });
  });

  it('a vault key an earlier version left in the tree gets its own remedy: nothing to regenerate', () => {
    const dir = makeTree('legacy-vault-tree', { git: true });
    const legacy = path.join(dir, '.opena2a', 'credvault', 'store.key');
    mkdirSync(path.dirname(legacy), { recursive: true });
    writeFileSync(legacy, 'FAKE-PLACEHOLDER\n');
    const stat = statSync(legacy);

    const text = run(dir, []);
    expect(text.out).toContain('Private key inside the project');
    expect(text.out).toContain('(vault key)');
    expect(text.out).toContain('(untracked)');
    expect(text.out).toContain('nothing to regenerate');
    expect(text.out).toContain('git -C ');
    expect(text.out).not.toMatch(/re-signed/);
    expect(statSync(legacy).mtimeMs).toBe(stat.mtimeMs);

    const json = run(dir, ['--scan-only', '--json']);
    const body = JSON.parse(json.stdout.slice(json.stdout.indexOf('{')));
    expect(body.legacyKeyMaterial.map((l: any) => l.kind)).toEqual(['vault']);
    expect(body.store.legacyInTree.vault).toEqual({ found: true, path: legacy });
  });

  it('refuses to run when the store would sit inside the target', () => {
    const dir = makeTree('self-home', { git: false });
    const r = spawnSync(process.execPath, [BUILT_CLI, 'fix-all', dir, '--with-aim'], {
      encoding: 'utf8',
      timeout: 60_000,
      env: { ...process.env, NO_COLOR: '1', OPENA2A_TELEMETRY: 'off', HOME: home, OPENA2A_HOME: path.join(dir, 'home') },
    });
    expect(r.status).not.toBe(0);
    expect(String(r.stderr)).toContain('inside the target');
    expect(walk(dir).some((f) => f.startsWith('home/'))).toBe(false);
  });
});
