/**
 * The user store: where hackmyagent keeps material it writes on a project's
 * behalf that must never live inside the project itself (#534, #431).
 *
 * `fix-all --with-aim` used to write the Ed25519 signing identity — secret key
 * included — to `<target>/.opena2a/aim/`, and `fix-all` wrote a vault key
 * beside it. Both sat ungitignored in the tree the command had just been asked
 * to make safer, one `git add -A` from a commit. Everything private now
 * resolves under the user store; everything that stays in the tree is public
 * material that is correct to commit.
 *
 * Layout: `$OPENA2A_HOME/projects/<key>/` (default root `~/.opena2a`, the
 * same expression the config and pending-scan stores already use), where
 * `key` is the first sixteen hex characters of sha256 over the project's
 * real path. The real path is the one keying input the audited tree cannot
 * influence: any in-tree signal (a git remote, a package name, a marker file)
 * would let a hostile repository key itself onto another project's store and
 * get its files signed with that project's key. `realpathSync.native` is
 * required — on a case-insensitive filesystem the non-native variant returns
 * two spellings, and two keys, for one directory.
 *
 * Conformance vector every implementation pins:
 *   key("/srv/example-project") === "2550ea6e13e5f88a"
 *
 * This module is the ONLY place the private-material filenames and the
 * `aim` / `credvault` directory names are spelled. Plugins receive a
 * `ProjectStore` through `PluginInitOptions` and read paths from it; a path
 * computed from `agentDir` anywhere else fails the repo tripwire test. A
 * rename or move of the project yields a new key and a fresh store; there is
 * no rename detection, by design.
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash } from 'crypto';
import { spawnSync, type SpawnSyncOptionsWithStringEncoding } from 'child_process';

/** aim-core's file contract: `identity.json` at the root of its dataDir. */
const IDENTITY_FILE = 'identity.json';
/** The vault key the credvault plugin wrote next to its store, in-tree, before #431. */
const LEGACY_VAULT_KEY_FILE = 'store.key';
const LEGACY_IN_TREE_DIR = '.opena2a';

export interface ProjectStore {
  /** `$OPENA2A_HOME/projects/<key>` */
  root: string;
  /** sha256(realpath)[:16] */
  key: string;
  /** The project's real path — what `key` was derived from. */
  projectPath: string;
  /** aim-core `dataDir`: identity, audit log, policy. */
  aimDir: string;
  /** The identity file inside `aimDir` (aim-core's contract). */
  identityPath: string;
  /**
   * Reserved for a credential store with a writer and a reader. No shipped
   * version has either — every vault ever written encrypted the literal `{}`
   * — so nothing is created here until one exists (CISO, 2026-08-24).
   */
  credvaultDir: string;
  /** A directory for any other component, under the store root. */
  dirFor(name: string): string;
  /** Create the store root (0700) and its manifest if absent. Idempotent. */
  ensure(): ProjectStore;
}

export interface LegacyKeyMaterial {
  kind: 'identity' | 'vault';
  /** Absolute path inside the target. */
  path: string;
  /** Target-relative, for citations. */
  relativePath: string;
  gitState: 'tracked' | 'untracked' | 'not-a-repo';
}

/** `$OPENA2A_HOME`, else `~/.opena2a` — the expression the rest of the CLI uses. */
export function userStoreRoot(): string {
  return process.env.OPENA2A_HOME || path.join(os.homedir(), '.opena2a');
}

export function projectKey(realPath: string): string {
  return createHash('sha256').update(realPath, 'utf8').digest('hex').slice(0, 16);
}

/**
 * The real path of `p`'s deepest existing ancestor, with the rest appended:
 * the store root usually does not exist yet, and a symlinked prefix (macOS's
 * `/var` -> `/private/var`) would otherwise make the inside-target comparison
 * below compare two spellings of one directory.
 */
function realpathOfExistingPrefix(p: string): string {
  let cur = path.resolve(p);
  const tail: string[] = [];
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break;
    tail.unshift(path.basename(cur));
    cur = parent;
  }
  let real = cur;
  try { real = fs.realpathSync.native(cur); } catch { /* unreadable prefix: compare as spelled */ }
  return path.join(real, ...tail);
}

/**
 * Resolve (without creating) the store for `target`. Throws when the store
 * would sit inside the target — `fix-all ~`, or a target that contains
 * `$OPENA2A_HOME` — because a store inside the audited tree is the defect this
 * module exists to remove, and no flag may recreate it.
 */
export function resolveProjectStore(target: string, opts: { createdBy?: string } = {}): ProjectStore {
  const projectPath = fs.realpathSync.native(target);
  const root = realpathOfExistingPrefix(userStoreRoot());
  const key = projectKey(projectPath);
  const storeRoot = path.join(root, 'projects', key);

  const rel = path.relative(projectPath, storeRoot);
  // A component that merely BEGINS with `..` (`..hidden`) is inside; only the
  // parent segment itself, alone or followed by a separator, is outside.
  const outside = rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel);
  const inside = rel === '' || !outside;
  if (inside) {
    throw new Error(
      `The user store ${storeRoot} would sit inside the target ${projectPath}. ` +
      'Set OPENA2A_HOME to a directory outside the tree being fixed.',
    );
  }

  const dirFor = (name: string): string => path.join(storeRoot, name);
  const aimDir = dirFor('aim');
  const store: ProjectStore = {
    root: storeRoot,
    key,
    projectPath,
    aimDir,
    identityPath: path.join(aimDir, IDENTITY_FILE),
    credvaultDir: dirFor('credvault'),
    dirFor,
    ensure(): ProjectStore {
      // Ancestors (`$OPENA2A_HOME`, `projects/`) keep the default mode; only
      // the project's own store root is private.
      fs.mkdirSync(path.dirname(storeRoot), { recursive: true });
      if (!fs.existsSync(storeRoot)) fs.mkdirSync(storeRoot, { mode: 0o700 });
      try { fs.chmodSync(storeRoot, 0o700); } catch { /* Windows: no mode bits */ }
      const manifest = path.join(storeRoot, 'project.json');
      if (!fs.existsSync(manifest)) {
        const body = JSON.stringify(
          { schemaVersion: 1, path: projectPath, createdAt: new Date().toISOString(), createdBy: opts.createdBy ?? 'hackmyagent' },
          null,
          2,
        );
        try {
          fs.writeFileSync(manifest, body + '\n', { encoding: 'utf-8', flag: 'wx', mode: 0o600 });
        } catch (e: any) {
          if (e.code !== 'EEXIST') throw e;
        }
      }
      return store;
    },
  };
  return store;
}

/**
 * Private key material an earlier hackmyagent wrote INTO the target. Reported,
 * never read, moved or deleted: a key of unknown exposure gets regenerated in
 * the user store, and what happens to the old file is the user's decision
 * with the git state in front of them.
 */
export function findLegacyKeyMaterial(target: string): LegacyKeyMaterial[] {
  const candidates: Array<{ kind: LegacyKeyMaterial['kind']; relativePath: string }> = [
    { kind: 'identity', relativePath: path.join(LEGACY_IN_TREE_DIR, 'aim', IDENTITY_FILE) },
    { kind: 'vault', relativePath: path.join(LEGACY_IN_TREE_DIR, 'credvault', LEGACY_VAULT_KEY_FILE) },
  ];
  const found: LegacyKeyMaterial[] = [];
  let targetReal: string;
  try { targetReal = fs.realpathSync.native(target); } catch { return found; }
  for (const c of candidates) {
    const abs = path.join(target, c.relativePath);
    // Only a file that really lives under the target is "inside the project":
    // a symlinked `.opena2a/` would otherwise name a file elsewhere and the
    // advice "take it out of the tree" would act on the wrong file.
    let real: string;
    try { real = fs.realpathSync.native(abs); } catch { continue; }
    const within = path.relative(targetReal, real);
    if (within === '' || within.startsWith('..' + path.sep) || within === '..' || path.isAbsolute(within)) continue;
    found.push({ kind: c.kind, path: abs, relativePath: c.relativePath, gitState: gitStateOf(target, c.relativePath) });
  }
  return found;
}

function gitStateOf(target: string, relativePath: string): LegacyKeyMaterial['gitState'] {
  // Inside a git hook, git exports GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE
  // pointing at the hook's own repository; inherited, they make `cwd: target`
  // answer for the wrong repository (the git-context.ts precedent, #348).
  const env = { ...process.env };
  delete env.GIT_DIR;
  delete env.GIT_WORK_TREE;
  delete env.GIT_INDEX_FILE;
  const opts: SpawnSyncOptionsWithStringEncoding = {
    cwd: target,
    env,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 5000,
  };
  // The target may be a clone that ships a hostile .git/config; the two
  // read-only queries run with the one config that would execute a command
  // on their behalf switched off.
  const quiet = ['-c', 'core.fsmonitor=false'];
  const inRepo = spawnSync('git', [...quiet, 'rev-parse', '--is-inside-work-tree'], opts);
  if (inRepo.error || inRepo.status !== 0 || inRepo.stdout.trim() !== 'true') return 'not-a-repo';
  const tracked = spawnSync('git', [...quiet, 'ls-files', '--error-unmatch', '--', relativePath], opts);
  return tracked.status === 0 ? 'tracked' : 'untracked';
}
