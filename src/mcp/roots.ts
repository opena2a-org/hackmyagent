/**
 * #463 — the one place the MCP server decides whether it may touch a path.
 *
 * Every MCP tool took a caller-supplied path and acted on it: `analyze_file`
 * read any file on the machine, and `scan` / `deep_scan` / `benchmark` scanned —
 * and with `fix:true`, WROTE — any directory. Measured on `c982b58` against a
 * real stdio session whose cwd was a small project: an absolute path, a `..`
 * traversal and a symlink inside the cwd all returned an out-of-root file's
 * contents, `deep_scan` returned them for a whole out-of-root directory, and
 * `scan {fix:true}` created a backup directory and rewrote `.gitignore` in a
 * tree the server was never pointed at.
 *
 * Containment itself is NOT reimplemented here. `src/hardening/contain.ts`
 * already resolves "is this path inside that tree" for the fix and rollback
 * paths, and #270 is the record of what two implementations of that question
 * cost: they disagreed, and the disagreement was the vulnerability. This module
 * is the root POLICY on top of that one primitive.
 *
 * The root is MANDATORY and there is no unconfined mode. CISO ruled out
 * defaulting to `process.cwd()` for a specific reason: `src/init-mcp.ts` writes
 * `npx -y hackmyagent mcp-serve` into the client config with no `cwd` key, so the
 * working directory is whatever the HOST chose — commonly the user's home
 * directory. "Confine to the cwd" would therefore have meant "confine to
 * nothing" for the exact installation path we ship, while printing a
 * security-sounding flag. A filesystem root or a home directory is refused even
 * when passed explicitly, because the way a mandatory root fails is that people
 * route around it with `--root /`, which is `MCP-001`'s own failure mode
 * reintroduced by us.
 */

import * as path from 'path';
import * as os from 'os';
import { promises as fs } from 'fs';
import { resolveInsideTree, describeResolveRefusal, type ResolveRefusal } from '../hardening/contain';
import { citationTarget, citationPaths } from '../ui/shell-quote';
import { escapePathForDisplay } from '../ui/display-safe';

/** Why a request was refused. Each one has a sentence in `describeRootRefusal`. */
export type RootRefusal =
  | { kind: 'no-root-configured'; cwd: string }
  | { kind: 'root-too-broad'; root: string; why: 'filesystem-root' | 'home-directory' }
  | { kind: 'outside-roots'; requested: string; resolved: string; roots: string[] }
  | { kind: 'not-a-directory'; requested: string; resolved: string; why: 'missing' | 'file' }
  | { kind: 'unresolvable'; requested: string; cause: ResolveRefusal };

/**
 * A refusal this tool AUTHORED, as opposed to one the operating system reported.
 *
 * The distinction is a display one and it is load-bearing. Our refusal text is
 * multi-line by design and every path inside it is display-escaped where it was
 * interpolated, so it can be printed as lines. Node's `fs` errors embed a raw
 * path, so a directory named `proj\n  Roots it may read: /` forged a line that
 * read like ours when the CLI escaped per line instead of per message.
 */
export class RootRefusalError extends Error {}

export type RootsOutcome = { ok: true; roots: string[] } | { ok: false; refusal: RootRefusal };
export type PathOutcome = { ok: true; path: string } | { ok: false; refusal: RootRefusal };

/**
 * The root policy, in ONE place and synchronous.
 *
 * `mcp-serve` refused `/` and `$HOME` while `init-mcp` accepted them, so the
 * command the refusal text sends people to wrote a config that could never
 * work: exit 0, "Added HackMyAgent MCP server", and then every tool call in
 * that client refused for the life of the install. README.md said the two were
 * not accepted, directly beneath the `init-mcp --root` example that accepted
 * them.
 *
 * It is synchronous because `initMcp` writes the config on a sync path, and a
 * policy that existed only on the async side is exactly how the two came apart.
 */
export function rootTooBroad(
  realRoot: string,
  home: string,
): 'filesystem-root' | 'home-directory' | null {
  if (realRoot === path.parse(realRoot).root) return 'filesystem-root';
  if (realRoot === path.resolve(home)) return 'home-directory';
  return null;
}

/**
 * The roots this server session may act in, or the reason it has none.
 *
 * Pure with respect to the environment except for `realpath` and `homedir`, both
 * injectable, so the refusals are reachable from a test without a home directory
 * to spare.
 */
export async function resolveRoots(
  cliRoots: string[],
  env: { cwd?: string; homedir?: string } = {},
): Promise<RootsOutcome> {
  const cwd = env.cwd ?? process.cwd();
  const home = path.resolve(env.homedir ?? os.homedir());

  if (cliRoots.length === 0) {
    return { ok: false, refusal: { kind: 'no-root-configured', cwd: await realpathOrResolve(cwd) } };
  }

  const roots: string[] = [];
  const realHome = await realpathOrResolve(home);
  for (const candidate of cliRoots) {
    const real = await realpathOrResolve(path.resolve(cwd, candidate));
    const why = rootTooBroad(real, realHome);
    if (why) {
      return { ok: false, refusal: { kind: 'root-too-broad', root: real, why } };
    }
    roots.push(real);
  }
  return { ok: true, roots };
}

/**
 * Containment says WHERE a path is. It does not say the path is there.
 *
 * `resolveInsideTree` resolves a destination's PARENT, so a name that does not
 * exist inside the root passes containment — correctly, it is inside — and the
 * scanner then reported on it. Measured: `scan {directory: "nope-not-a-real-dir"}`
 * returned `Score: 98/100 | 1 issue found` and `benchmark` returned
 * `83% compliance`, both `isError: undefined`, for a directory that was never
 * there. A host model that mistypes a path was told the project passed.
 *
 * The CLI has always refused this (`Directory '...' does not exist.`); only the
 * MCP surface answered. Every tool behind this helper takes a DIRECTORY, so the
 * requirement lives here rather than three times in the handlers.
 */
async function confirmDirectory(resolved: string, requested: string): Promise<PathOutcome> {
  try {
    const st = await fs.stat(resolved);
    if (!st.isDirectory()) {
      return { ok: false, refusal: { kind: 'not-a-directory', requested, resolved, why: 'file' } };
    }
    return { ok: true, path: resolved };
  } catch {
    return { ok: false, refusal: { kind: 'not-a-directory', requested, resolved, why: 'missing' } };
  }
}

/**
 * The path to ACT on, or the refusal to report.
 *
 * `..` and symlinks are resolved BEFORE the decision, by `resolveInsideTree`, so
 * a path that leaves the root is refused however it is spelled. A relative path
 * is resolved against each root in turn — the first root that contains it wins.
 */
export async function resolveWithinRoots(roots: string[], requested: string): Promise<PathOutcome> {
  if (roots.length === 0) {
    return { ok: false, refusal: { kind: 'no-root-configured', cwd: process.cwd() } };
  }

  let lastCause: ResolveRefusal = 'escapes-tree';
  let lastMissing: RootRefusal | null = null;
  // Canonicalized ONCE, not per root: the answer does not depend on which root
  // is being tried, and `realpath` is a syscall.
  const absolute = path.isAbsolute(requested) ? await canonicalizeRequest(requested) : null;
  for (const root of roots) {
    const rel = absolute !== null ? path.relative(root, absolute) : requested;

    // The root ITSELF is the common case — `deep_scan {directory: "."}` and
    // `scan {directory: "<the root>"}` are what a host actually sends — and
    // `resolveInsideTree` cannot answer for it: it resolves the destination's
    // PARENT and requires that to be inside the tree, so asked about the tree it
    // refuses its own root with `parent-outside-tree`. Measured: `{"directory":
    // "."}` came back "Path outside the allowed root" naming that same path as
    // the allowed root. Over-correcting a containment fix until it refuses the
    // legitimate case is #270's recorded failure mode, not a new one.
    const normalized = path.normalize(rel);
    if (normalized === '' || normalized === '.') {
      const here = await confirmDirectory(root, requested);
      if (here.ok) return here;
      lastMissing = here.refusal;
      continue;
    }
    // `followLeafLink: true` — a link inside the root that points inside the
    // root is an ordinary file to read; one that points out is refused. That
    // closes the third escape shape measured on `c982b58` FOR THE PATH THE
    // CALLER NAMES, which is all this function sees.
    //
    // It is not confinement over what a scan then DISCOVERS. This comment used
    // to claim the escape shape outright, and the claim was false: the walk
    // reads discovery basenames by joining them onto the target, so a link at
    // `CLAUDE.md` or `.env` was read even though nobody ever passed its path
    // here. That half lives in `DiscoveryOptions.confineTo`, which the MCP
    // handlers pass and the CLI deliberately does not. Both halves are needed
    // and neither implies the other.
    const outcome = await resolveInsideTree(root, rel, { followLeafLink: true });
    if (outcome.ok) {
      // `--root` is repeatable, so a name that is absent from THIS root may be
      // present in the next one. Returning the refusal here made a directory
      // that exists only in a later root unreachable.
      const here = await confirmDirectory(outcome.path, requested);
      if (here.ok) return here;
      lastMissing = here.refusal;
      continue;
    }
    lastCause = outcome.cause;
  }

  // A path that is simply somewhere else gets the boundary message, which names
  // the roots and how to grant one. Anything else — a dangling link, an EACCES,
  // a missing parent — proved nothing about containment and says so instead.
  // #347.4's lesson: one sentence covering seven causes is true of one of them.
  // A path that was INSIDE a root and simply absent is a different answer from
  // one that left every root, and it is the more useful one.
  if (lastMissing) return { ok: false, refusal: lastMissing };
  if (
    lastCause === 'escapes-tree' ||
    lastCause === 'parent-outside-tree' ||
    lastCause === 'leaf-link-outside-tree'
  ) {
    return {
      ok: false,
      refusal: {
        kind: 'outside-roots',
        requested,
        resolved: await bestEffortResolve(roots, requested),
        roots,
      },
    };
  }
  return { ok: false, refusal: { kind: 'unresolvable', requested, cause: lastCause } };
}

/**
 * What the host model — and through it the user — is told.
 *
 * This text has a second audience no ordinary error has. A human who reads
 * "outside the root" stops; a model reads it as an obstacle and tries the next
 * spelling, or a symlink, or asks the user to copy the file in. So it has to say
 * that the boundary is operator-set and not negotiable from inside the session,
 * which is what redirects the model to TELLING the user instead of routing
 * around. That sentence is load-bearing (CPO).
 */
export function describeRootRefusal(refusal: RootRefusal, cliName = 'hackmyagent'): string {
  switch (refusal.kind) {
    case 'no-root-configured':
      return `No project root is configured for this MCP server.

  Server working directory: ${escapePathForDisplay(refusal.cwd)}
  Allowed roots:            none

hackmyagent will not scan until it is told which directory it may read. The
working directory above was inherited from the client that launched this server
rather than chosen, so it is not treated as a grant.

Set the root explicitly. From a terminal:

  ${cliName} init-mcp --root /absolute/path/to/your/project

Then restart your MCP client. Scanning also works with no MCP configuration:

  ${cliName} secure /absolute/path/to/your/project`;

    case 'root-too-broad':
      return `Root not accepted: ${escapePathForDisplay(refusal.root)}

hackmyagent does not accept ${
        refusal.why === 'filesystem-root' ? 'the filesystem root' : 'a home directory'
      } as an MCP root. That
would grant every project and every credential file on this machine to any model
driving this session, which is the same finding hackmyagent reports as MCP-001
when it sees it in someone else's configuration.

Name the project instead. From a terminal:

  ${cliName} init-mcp --root /absolute/path/to/your/project

--root is repeatable, so several projects can be granted individually.`;

    case 'not-a-directory':
      return `${
        refusal.why === 'missing' ? 'No such directory.' : 'That path is a file, not a directory.'
      }

  Requested:   ${escapePathForDisplay(refusal.requested)}
  Resolved to: ${escapePathForDisplay(refusal.resolved)}

The path is inside an allowed root, so this is not a boundary refusal — there is
simply nothing there to scan. hackmyagent will not report a score for a directory
it did not read: a passing result for a path that does not exist would be a clean
bill of health for nothing.

Check the spelling, or list the directory first, then scan a real path.`;

    case 'outside-roots':
      return `Path outside the allowed root.

  Requested:     ${escapePathForDisplay(refusal.requested)}
  Resolved to:   ${escapePathForDisplay(refusal.resolved)}
  Allowed roots: ${refusal.roots.map(escapePathForDisplay).join(', ')}

The hackmyagent MCP server reads only inside the roots it was started with.
Symlinks and ".." are resolved before this check, so a path that points outside a
root is outside it regardless of how it is written.

This boundary is set by the person who configured this MCP server. It cannot be
changed from inside this session, and retrying the same path spelled differently
will return this error again.

To scan this path, either:

  1. Grant it. From a terminal:
       ${cliName} init-mcp ${citedRootGrants(refusal.roots, refusal.resolved, cliName)}
     Then restart your MCP client.

  2. Scan it from a terminal, which is not bound by this root:
       ${cliName} secure ${citationTarget(refusal.resolved)}`;

    case 'unresolvable':
      return `Path could not be used: ${describeResolveRefusal(refusal.cause)}.

  Requested: ${escapePathForDisplay(refusal.requested)}

This is not a report about the path's contents — hackmyagent did not read it.
Check the path and try again, or scan from a terminal:

  ${cliName} secure <directory>`;
  }
}

/**
 * The `--root` operand list for the grant citation, or a fillable placeholder.
 *
 * #273 — all-or-nothing, like `citationPaths` itself: a command that silently
 * dropped one root would offer a remedy it did not give, and the reader could
 * not tell from looking at it.
 */
function citedRootGrants(roots: string[], resolved: string, cliName: string): string {
  const cited = citationPaths([...roots, resolved]);
  if (cited === null) return `--root <dir> --root <dir>   # run \`${cliName} init-mcp --help\``;
  return cited
    .split(' ')
    .map((r) => `--root ${r}`)
    .join(' ');
}

/**
 * The caller's absolute path, canonicalized the way a root already is.
 *
 * `resolveRoots` stores every root through `realpath`, so a root granted as
 * `/tmp/proj` is held as `/private/tmp/proj` on macOS. Comparing the caller's
 * raw spelling against that stored form made the server refuse THE ROOT IT WAS
 * GRANTED: `path.relative('/private/tmp/proj', '/tmp/proj')` climbs out, so the
 * root-itself case never fired and the walk saw a path leaving the tree. The
 * refusal then printed `Resolved to` and `Allowed roots` as the SAME string
 * while saying the path was outside, and told the user to grant a root they had
 * already granted. `init-mcp` writes the spelling the user typed, so the
 * documented setup produced exactly this. Only the non-canonical spelling
 * failed, which is why `.` and `./sub` kept working and hid it.
 *
 * Both sides are canonicalized so there is ONE spelling to compare, rather than
 * a second rule that recognises the other one. This does not widen containment:
 * the tree walk still runs, and a link resolving outside a root still resolves
 * outside it.
 *
 * `realpath` fails on a path that does not exist, so the deepest existing
 * ancestor is resolved and the remainder re-appended — a missing path stays
 * missing and is reported as missing, rather than being reported as outside.
 */
async function canonicalizeRequest(requested: string): Promise<string> {
  const absolute = path.resolve(requested);
  let prefix = absolute;
  const tail: string[] = [];
  for (;;) {
    try {
      const real = await fs.realpath(prefix);
      return tail.length === 0 ? real : path.join(real, ...[...tail].reverse());
    } catch {
      const parent = path.dirname(prefix);
      if (parent === prefix) return absolute; // reached the filesystem root
      tail.push(path.basename(prefix));
      prefix = parent;
    }
  }
}

/** `realpath` when the path exists, the lexical resolution when it does not. */
async function realpathOrResolve(p: string): Promise<string> {
  try {
    return await fs.realpath(p);
  } catch {
    return path.resolve(p);
  }
}

/**
 * The location to NAME in the refusal.
 *
 * A user told only "outside the root" cannot tell a typo from a symlink they
 * forgot about. This resolves as far as the filesystem allows so the message can
 * say where the path actually went. It discloses a LOCATION and never contents,
 * and only for a path the caller already supplied.
 */
async function bestEffortResolve(roots: string[], requested: string): Promise<string> {
  const base = path.isAbsolute(requested) ? requested : path.resolve(roots[0], requested);
  return realpathOrResolve(base);
}
