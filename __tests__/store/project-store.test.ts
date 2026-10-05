/**
 * The user store resolver (#534, #431): keyed on the project's real path,
 * rooted at $OPENA2A_HOME, never inside the target.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { gitFreeEnv, initThrowawayRepo } from '../helpers/throwaway-repo';
import {
  findLegacyKeyMaterial,
  identityState,
  IdentityUnreadableError,
  projectKey,
  resolveProjectStore,
  userStoreRoot,
} from '../../src/store/project-store';

let tmp: string;
let home: string;
let target: string;
const savedHome = process.env.OPENA2A_HOME;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-store-'));
  home = path.join(tmp, 'home');
  target = path.join(tmp, 'proj');
  fs.mkdirSync(home);
  fs.mkdirSync(target);
  process.env.OPENA2A_HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.OPENA2A_HOME;
  else process.env.OPENA2A_HOME = savedHome;
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('projectKey', () => {
  it('pins the conformance vector every implementation must reproduce', () => {
    // Computed independently with node's crypto before being written here.
    expect(projectKey('/srv/example-project')).toBe('2550ea6e13e5f88a');
  });

  it('is sixteen lowercase hex characters', () => {
    expect(projectKey(target)).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('resolveProjectStore', () => {
  it('roots the store at $OPENA2A_HOME/projects/<key> and keys on the real path', () => {
    const store = resolveProjectStore(target);
    const real = fs.realpathSync.native(target);
    expect(store.projectPath).toBe(real);
    expect(store.key).toBe(projectKey(real));
    // the root is compared and reported in real-path form (tmpdir is a symlink on macOS)
    expect(store.root).toBe(path.join(fs.realpathSync.native(home), 'projects', store.key));
    expect(store.aimDir).toBe(path.join(store.root, 'aim'));
    expect(path.dirname(store.identityPath)).toBe(store.aimDir);
    expect(store.dirFor('anything')).toBe(path.join(store.root, 'anything'));
  });

  it('falls back to ~/.opena2a when OPENA2A_HOME is unset', () => {
    delete process.env.OPENA2A_HOME;
    expect(userStoreRoot()).toBe(path.join(os.homedir(), '.opena2a'));
  });

  it('gives one key to one directory however it is reached', () => {
    const link = path.join(tmp, 'link-to-proj');
    fs.symlinkSync(target, link);
    expect(resolveProjectStore(link).key).toBe(resolveProjectStore(target).key);
    expect(resolveProjectStore(target + path.sep).key).toBe(resolveProjectStore(target).key);
  });

  it('gives different projects different stores', () => {
    const other = path.join(tmp, 'other');
    fs.mkdirSync(other);
    expect(resolveProjectStore(other).root).not.toBe(resolveProjectStore(target).root);
  });

  it('refuses a store that would sit inside the target', () => {
    process.env.OPENA2A_HOME = path.join(target, '.home');
    expect(() => resolveProjectStore(target)).toThrow(/inside the target/);
    // and the inverse framing: the target IS the store root's ancestor
    process.env.OPENA2A_HOME = target;
    expect(() => resolveProjectStore(target)).toThrow(/inside the target/);
    // a component that merely BEGINS with `..` is still inside
    process.env.OPENA2A_HOME = path.join(target, '..hidden');
    expect(() => resolveProjectStore(target)).toThrow(/inside the target/);
    // and the parent directory itself is outside
    process.env.OPENA2A_HOME = path.dirname(target);
    expect(() => resolveProjectStore(target)).not.toThrow();
  });

  it('does not create anything until ensure() is called, then creates the root and manifest', () => {
    const store = resolveProjectStore(target, { createdBy: 'hackmyagent@test' });
    expect(fs.existsSync(store.root)).toBe(false);
    store.ensure();
    expect(fs.existsSync(store.root)).toBe(true);
    const manifest = JSON.parse(fs.readFileSync(path.join(store.root, 'project.json'), 'utf8'));
    expect(manifest).toMatchObject({ schemaVersion: 1, path: store.projectPath, createdBy: 'hackmyagent@test' });
    if (process.platform !== 'win32') {
      expect(fs.statSync(store.root).mode & 0o777).toBe(0o700);
      expect(fs.statSync(path.join(store.root, 'project.json')).mode & 0o777).toBe(0o600);
    }
    // idempotent: a second ensure() keeps the first manifest
    const before = fs.readFileSync(path.join(store.root, 'project.json'), 'utf8');
    store.ensure();
    expect(fs.readFileSync(path.join(store.root, 'project.json'), 'utf8')).toBe(before);
  });
});

describe('identityState', () => {
  // aim-core creates over any file it cannot read or parse; this is the check
  // that keeps an existing identity, in whatever state, from being replaced.
  const FAKE_IDENTITY = JSON.stringify({
    agentId: 'aim_FAKE',
    publicKey: 'FAKE-PLACEHOLDER-PUBLIC',
    secretKey: 'FAKE-PLACEHOLDER-SECRET',
    agentName: 'proj',
    createdAt: '2026-01-01T00:00:00.000Z',
  });

  function identityFile(): string {
    const store = resolveProjectStore(target).ensure();
    fs.mkdirSync(store.aimDir, { recursive: true });
    return store.identityPath;
  }

  function refusal(p: string): IdentityUnreadableError {
    try {
      identityState(p);
    } catch (e) {
      expect(e).toBeInstanceOf(IdentityUnreadableError);
      return e as IdentityUnreadableError;
    }
    throw new Error(`identityState(${p}) did not refuse`);
  }

  it('is absent only when nothing is at the path', () => {
    expect(identityState(identityFile())).toBe('absent');
  });

  it('is present for a readable identity', () => {
    const p = identityFile();
    fs.writeFileSync(p, FAKE_IDENTITY);
    expect(identityState(p)).toBe('present');
  });

  it('refuses a truncated file and leaves it as it was', () => {
    const p = identityFile();
    fs.writeFileSync(p, FAKE_IDENTITY.slice(0, 20));
    const e = refusal(p);
    expect(e.code).toBe('INVALID_JSON');
    expect(e.path).toBe(p);
    expect(fs.readFileSync(p, 'utf8')).toBe(FAKE_IDENTITY.slice(0, 20));
  });

  it('refuses JSON that aim-core would read as no identity, or that holds no key', () => {
    const p = identityFile();
    for (const body of ['null', '0', 'false', '""', '[]', '{}', '{"publicKey":"FAKE"}']) {
      fs.writeFileSync(p, body);
      expect(refusal(p).code, body).toBe('NOT_AN_IDENTITY');
    }
  });

  it('refuses a directory and a dangling link at the path', () => {
    const p = identityFile();
    fs.mkdirSync(p);
    expect(refusal(p).code).toBe('EISDIR');
    fs.rmdirSync(p);
    if (process.platform === 'win32') return;
    fs.symlinkSync(path.join(tmp, 'missing.json'), p);
    expect(refusal(p).code).toBe('ENOENT');
    expect(fs.lstatSync(p).isSymbolicLink()).toBe(true);
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('refuses a file it has no permission to read', () => {
    const p = identityFile();
    fs.writeFileSync(p, FAKE_IDENTITY);
    fs.chmodSync(p, 0o000);
    try {
      expect(refusal(p).code).toBe('EACCES');
    } finally {
      fs.chmodSync(p, 0o600);
    }
    expect(fs.readFileSync(p, 'utf8')).toBe(FAKE_IDENTITY);
  });
});

describe('findLegacyKeyMaterial', () => {
  it('reports nothing on a clean tree', () => {
    expect(findLegacyKeyMaterial(target)).toEqual([]);
  });

  it('names an in-tree identity and vault key with their git state, and touches neither', () => {
    const legacyIdentity = path.join(target, '.opena2a', 'aim', 'identity.json');
    const legacyVault = path.join(target, '.opena2a', 'credvault', 'store.key');
    fs.mkdirSync(path.dirname(legacyIdentity), { recursive: true });
    fs.mkdirSync(path.dirname(legacyVault), { recursive: true });
    fs.writeFileSync(legacyIdentity, '{"agentName":"FAKE","secretKey":"FAKE-PLACEHOLDER"}\n');
    fs.writeFileSync(legacyVault, 'FAKE-PLACEHOLDER\n');
    // #348 — fixture repositories are created and driven with git isolated
    // from this one (a git hook exports GIT_DIR at the real repository).
    initThrowawayRepo(target);
    spawnSync('git', ['add', '.opena2a/aim/identity.json'], { cwd: target, env: gitFreeEnv() });
    const beforeId = fs.statSync(legacyIdentity);
    const beforeVault = fs.statSync(legacyVault);

    const found = findLegacyKeyMaterial(target);
    expect(found.map((f) => [f.kind, f.gitState])).toEqual([
      ['identity', 'tracked'],
      ['vault', 'untracked'],
    ]);
    expect(found[0].path).toBe(legacyIdentity);
    expect(found[0].relativePath).toBe(path.join('.opena2a', 'aim', 'identity.json'));
    expect(fs.statSync(legacyIdentity).mtimeMs).toBe(beforeId.mtimeMs);
    expect(fs.statSync(legacyVault).mtimeMs).toBe(beforeVault.mtimeMs);
  });

  it('ignores a symlinked .opena2a that points outside the tree', () => {
    const elsewhere = path.join(tmp, 'elsewhere');
    fs.mkdirSync(path.join(elsewhere, 'aim'), { recursive: true });
    fs.writeFileSync(path.join(elsewhere, 'aim', 'identity.json'), '{"secretKey":"FAKE-PLACEHOLDER"}\n');
    fs.symlinkSync(elsewhere, path.join(target, '.opena2a'));
    expect(findLegacyKeyMaterial(target)).toEqual([]);
  });

  it('says not-a-repo outside git', () => {
    const legacyVault = path.join(target, '.opena2a', 'credvault', 'store.key');
    fs.mkdirSync(path.dirname(legacyVault), { recursive: true });
    fs.writeFileSync(legacyVault, 'FAKE-PLACEHOLDER\n');
    expect(findLegacyKeyMaterial(target)[0].gitState).toBe('not-a-repo');
  });
});
