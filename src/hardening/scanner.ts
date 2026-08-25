/**
 * Hardening Scanner
 * Scans for security issues and optionally auto-fixes them
 */

// `fs/promises` with read attribution for the coverage ledger. Wrapping the
// namespace once is what lets all 153 read sites report what they examined
// without a per-call-site sweep — a sweep would be fail-OPEN, and a site
// missed in it would claim coverage it never had. See `tracked-fs.ts`.
import { fs } from './tracked-fs';
// `realpath.native` exists only on the callback and sync APIs, and the backup
// root needs it: the JS implementation does not canonicalize case (#334).
import * as fsSync from 'fs';
import * as crypto from 'crypto';
import * as path from 'path';
import { execFile } from 'child_process';
import type { ScanResult, SecurityFinding, SecurityFindingDraft, Severity, ProjectType } from './security-check';
import { emitFinding } from './finding-emit';
import { StructuralAnalyzer, toSecurityFindings, LLMAnalyzer } from '../semantic';
import { enrichWithTaxonomy } from './taxonomy';
import { lineFromOffset } from '../types/text-position';
import { classifySkillSection, isLikelyFalsePositive } from './skill-context';
import { isCorpusPath, isTestPath, isExamplePath } from './path-context';
import { scanAssembly } from '../lifecycle/assembly-scanner';
import {
  parseDeclaredCapabilities as parseSkillDeclaredCaps,
  inferActualCapabilities,
  validateCapabilities,
} from './skill-capability-validator';
import { clampScoreToVerdictBand, countsAgainstScore, expandSuppressed, retainForVerdict, summarizeSuppressed } from '../ui/verdict-band';
import { shellQuote, citationTarget, citationPath, citationPaths, commandNaming } from '../ui/shell-quote';
import {
  isPathWithinDirectory as containIsPathWithinDirectory,
  resolveInsideTree as containResolveInsideTree,
  describeResolveRefusal,
  type ResolveOutcome,
  type ResolveRefusal,
} from './contain';
import { GOVERNANCE_FILES } from '../soul/governance-files';
// One vocabulary with `detect`'s permission-grant rule (#363, #364), so the two
// commands cannot disagree in direction on the same `.claude/settings.json`.
import { walkConfigForGrants } from '../scanner/permission-vocabulary';
import { parseAiConfig, proseAllowEntry, forReport, MAX_TEXT } from '../scanner/permission-grant';

/** Redact, escape and cap a value out of a scanned config before quoting it. */
const forFinding = (s: string): string => forReport(s, MAX_TEXT);
import { escapeForDisplay } from '../ui/display-safe';
import {
  CoverageLedger,
  withActiveLedger,
  type CategoryCoverage,
  type CheckExecution,
  type CoverageTruncation,
  noteListFailure,
} from './coverage-ledger';

/**
 * Backup manifest format version. v1 (pre-0.25.1) wrote `createdFiles` as a
 * plain string array holding every backup candidate that happened to be
 * absent when the backup was taken, and rollback unlinked all of them — so a
 * file the user wrote between `--fix` and `rollback` was deleted as though
 * HMA had generated it, while SOUL.md (not a candidate at all) survived a
 * rollback that claimed everything had been reverted (#262).
 */
const BACKUP_MANIFEST_VERSION = 2;

/** A file a fix stage actually created, with the hash of what it wrote. */
/**
 * Every extension the JavaScript/TypeScript family uses, as ONE list.
 *
 * #414. `walkDirectory` was called with a hand-written extension array at each
 * of twelve JS-family sites, in four different spellings: `['.ts', '.js']`,
 * `['.ts', '.js', '.mjs']`, `['.ts', '.js', '.py', '.mjs']` and
 * `['.ts', '.js', '.md', '.txt']`. Whether a check read your file depended on
 * which check it was.
 *
 * The sharpest case sat three lines apart inside `checkNemoClawPatterns`, whose
 * own docstring says it detects "unsafe installs, missing digest verification,
 * injection vectors, secret leaks":
 *
 *   const shFiles   = walkDirectory(targetDir, ['.sh'], 0, 5);
 *   const tsJsFiles = walkDirectory(targetDir, ['.ts', '.js'], 0, 5);
 *
 * Measured on 0.31.0 against a consumer repo, as a control: identical hazards
 * (an `sk-ant-api03` shaped key, `child_process.exec`, and a curl-pipe-to-sh)
 * produced 2 CRITICALs from the `.sh` and NOTHING from the `.mjs`, in the same
 * run, from the same check group, scoring 98/100. #413 fixed the semantic
 * compile set, so those files reach NanoMind; this is the static half.
 *
 * `.mjs` matters more than the count suggests: it is the standard extension for
 * build, release and deploy tooling, which is where the credentials and the
 * shell-outs live.
 *
 * NOT a general "source file" list. Walks that are deliberately single-language
 * keep their own arrays and MUST NOT be widened to this: `['.sh']` for shell
 * checks, `['.py']` for Python, `['.yaml', '.yml']` for workflow parsing. A
 * check that only understands shell learns nothing from being handed a `.tsx`,
 * and widening it would cost scan time and invite false positives.
 */
export const JS_FAMILY_EXTENSIONS = ['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx'] as const;

/**
 * Sync twin of `HardeningScanner.unsearchableAncestor`, at module scope so
 * `buildUnreadInputFinding` can classify an obstruction its caller did not
 * (the `check` arm passes the ledger record through unmodified). Same bounds,
 * kept textually in step with the async method — change the two together: the
 * shallowest ancestor inside the target that this process cannot enter, the
 * target root included and named `.` (#588). `accessSync` here is an
 * inspection of a path already known to exist, not a discovery read.
 */
export function unsearchableAncestorSync(absPath: string, targetDir: string): string | undefined {
  const root = path.resolve(targetDir);
  let dir = path.dirname(absPath);
  let shallowest: string | undefined;
  while (dir.startsWith(root + path.sep)) {
    try {
      fsSync.accessSync(dir, fsSync.constants.X_OK);
    } catch {
      shallowest = dir;
    }
    dir = path.dirname(dir);
  }
  // The root last (#588): a root that lists but cannot be entered loses every
  // path beneath it, and naming a child instead sends the user to the wrong
  // directory. `.` is the root's own relative name, so the remedy stays a
  // relative command like every other.
  if (dir === root || path.resolve(absPath) === root) {
    try {
      fsSync.accessSync(root, fsSync.constants.X_OK);
    } catch {
      shallowest = root;
    }
  }
  return shallowest ? (path.relative(targetDir, shallowest) || '.') : undefined;
}

/**
 * Build the per-path `SCAN-UNREAD-001` finding for one discovered-but-unread
 * input. Module-level, shared by both arms, so a second command (`check` on a local path,
 * #508) can emit the identical finding through the same errno->remedy logic
 * instead of carrying a second copy of it — the per-channel-copy class #494
 * was the receipt for.
 *
 * ONE finding per path, not one naming the first of N: `file` is a single
 * field and SARIF/ASFF consumers key on it, so a summary finding leaves every
 * path after the first in no structured field at all. The remedy is derived
 * from the ERRNO, not from the finding — `chmod` answers a permission denial
 * and is a dead end for `EIO`/`ELOOP`, which the predicate deliberately admits.
 *
 * `command` names the CLI verb the remedy re-runs; it defaults to `secure`, so
 * the `HardeningScanner.secure` caller's re-run verb is unchanged.
 *
 * Not pure: when the caller did not classify the obstruction and the record
 * carries its absolute path, this builder probes the tree itself
 * (`unsearchableAncestorSync`, plus one read-bit probe on the obstruction) so
 * both arms print the same remedy for the same obstruction. The probes are
 * inspections of paths already known to exist and report to no channel.
 */
export function buildUnreadInputFinding(
  u: { rel: string; code: string; kind?: 'file' | 'directory'; obstructedBy?: string; path?: string },
  opts: { cliName: string; targetDir: string; command?: string },
): SecurityFinding {
  const { code, obstructedBy } = u;
  const { cliName, targetDir, command = 'secure' } = opts;
  const kind: 'file' | 'directory' = u.kind ?? 'file';
  const isDir = kind === 'directory';
  const permission = code === 'EACCES' || code === 'EPERM';
  // The scan root is its own relative name. Both callers derive `rel` with a
  // basename fallback for a path that IS the target; that name is not a path
  // inside the target and must not render as one (#588).
  const rel = u.path && path.resolve(u.path) === path.resolve(targetDir) ? '.' : u.rel;
  // A directory is shown with a trailing separator on every channel — `file`,
  // `message` and SARIF's uri all derive from it — so a reader never mistakes
  // it for a file. The ruled shape for this kind.
  const shown = isDir ? (rel === '.' ? './' : `${rel.replace(/[\\/]+$/, '')}/`) : rel;
  const cited = citationPath(rel);
  const target = citationTarget(targetDir);
  // The directory this user cannot enter, when that — not the record's own
  // mode — is why it was lost (#515). `chmod u+r <file>` inside it fails with
  // the same EACCES the scan did, so the remedy names the directory instead.
  //
  // Classified HERE when the caller did not: the `check` arm hands the ledger
  // record straight to this builder and computes no ancestor of its own, and
  // without this fallback it printed exactly the dead-end remedy this branch
  // exists to remove — on the same input, in the same run (#515 adversarial
  // round). Probe only for a permission denial, only when the record carries
  // its absolute path.
  const obstruction = obstructedBy
    ?? (permission && u.path ? unsearchableAncestorSync(u.path, targetDir) : undefined);
  // A directory record whose only obstruction is itself (its listing failed and
  // every ancestor is searchable) is its own remedy target; an ancestor that
  // cannot be entered is the #515 shape and wins over it.
  const ancestor = isDir && (obstruction === undefined || obstruction === rel) ? undefined : obstruction;
  const citedAncestor = ancestor ? citationPath(ancestor) : null;
  // `chmod u+x` answers a directory that can be LISTED but not entered. One
  // that denies read as well needs `u+rx`, and the guidance must not claim it
  // "can be listed" (mode 000: nothing lists it). When the probe cannot tell
  // — the directory vanished between the record and this render, or the
  // caller pinned a path that never existed — the enterable-not-listable
  // wording stands, which is what every earlier pin in the unit suite relies
  // on.
  let ancestorDeniesRead = false;
  if (ancestor && permission) {
    try {
      fsSync.accessSync(path.resolve(targetDir, ancestor), fsSync.constants.R_OK);
    } catch (e) {
      const c = (e as NodeJS.ErrnoException).code;
      ancestorDeniesRead = c === 'EACCES' || c === 'EPERM';
    }
  }
  // Every runnable remedy is a string LITERAL per verb, never a raw
  // `${command}` interpolation: a bare identifier in a runnable command string
  // is what the render-source gate (#273) forbids, and `command` is a fixed
  // internal verb, not a path operand. `${cited}`/`${citedAncestor}`/`${target}`
  // are citation-bound (`citationPath` quotes shell-significant names and
  // returns null for a display hazard, which falls through to the generic
  // remedy) and `${cliName}` is a known non-path operand. The gate itself does
  // not inspect `chmod` sites — its operand class has no `+` (#618) — so the
  // binding, not the gate, is what protects these strings.
  const chmodUx = (dir: string): string => (command === 'check'
    ? `chmod u+x ${dir} && ${cliName} check ${target}`
    : `chmod u+x ${dir} && ${cliName} secure ${target}`);
  const chmodUrx = (dir: string): string => (command === 'check'
    ? `chmod u+rx ${dir} && ${cliName} check ${target}`
    : `chmod u+rx ${dir} && ${cliName} secure ${target}`);
  const chmodUr = (file: string): string => (command === 'check'
    ? `chmod u+r ${file} && ${cliName} check ${target}`
    : `chmod u+r ${file} && ${cliName} secure ${target}`);
  // The remedy is keyed on the ERRNO first; the failed-call rule (a listing
  // that failed => `u+rx`, a read under a directory this user cannot enter =>
  // `u+x` on that directory) lives inside the permission branch only. Any
  // other errno names a cause it can actually produce — `chmod` answers a
  // permission denial and is a dead end for the rest, and a cause that the
  // errno cannot have sends the user the wrong way (#617). A dangling symlink
  // is ENOENT and never reaches this finding, so it is not among the causes.
  const cause = ((): string => {
    switch (code) {
      case 'ENAMETOOLONG':
        return 'the absolute path is longer than this system allows — scan the tree from a shallower checkout';
      case 'ELOOP':
        return 'a symbolic-link loop sits on this path';
      case 'EIO':
        return 'an I/O error was reported on this path';
      case 'ENXIO':
      case 'ENODEV':
      case 'ESTALE':
        return 'the device or mount behind this path is not available';
      default:
        return 'an I/O error or an unreadable mount are the usual causes';
    }
  })();
  const fix = !permission
    ? `Resolve the ${code} on this path: ${cause}, then re-run this scan.`
    : citedAncestor
      ? (ancestorDeniesRead ? chmodUrx(citedAncestor) : chmodUx(citedAncestor))
      : isDir
        ? (cited ? chmodUrx(cited) : 'Make the directory named above listable, then re-run this scan.')
        : (cited ? chmodUr(cited) : 'Make the file named above readable, then re-run this scan.');
  // The errno is named in the body, not only in `message`: the rendered
  // finding prints `guidance`, so an errno that lives only on `message`
  // reaches no reader — and the errno is the input that decides which
  // remedy applies.
  const ancestorSentence = ancestor
    ? (ancestorDeniesRead
      ? `\`${ancestor}\` cannot be listed or entered by this user (no read or execute bit `
        + `on the directory), which is why ${shown} could not be ${isDir ? 'listed' : 'read'}: `
        + `the remedy is on \`${ancestor}\`, not on ${isDir ? shown : 'the file'}. `
      : `\`${ancestor}\` can be listed but not entered by this user (no execute bit on the `
        + `directory), which is why ${shown} could not be ${isDir ? 'listed' : 'opened'}: `
        + `the remedy is on \`${ancestor}\`, not on ${isDir ? shown : 'the file'}. `)
    : '';
  const pathLength = code === 'ENAMETOOLONG' && u.path
    ? `The absolute path is ${u.path.length} characters. `
    : '';
  const guidance = isDir
    ? ancestorSentence
      + (ancestor
        ? ''
        : (permission
          ? `${shown} could not be listed by this user (${code}): the directory denies read or `
            + 'search to this process, so nothing beneath it was discovered. '
          : `${shown} could not be listed (${code}): ${cause}. ${pathLength}`))
      + 'The score above is an upper bound, not a measurement of this tree: nothing was ruled '
      + 'out about anything beneath it, and a credential or an injected instruction there would '
      + 'be invisible to this scan — leaving the score HIGHER than if it had been listable, '
      + 'because the evidence simply left the assessment. Re-run once it can be listed. If it is '
      + 'meant to stay closed, scan a narrower target that does not contain it — an `.hmaignore` '
      + 'path rule will not clear this, because it scopes what is reported and cannot make an '
      + 'unlisted directory listed.'
    : ancestorSentence
      + `This file was discovered inside the target and the read failed with ${code}`
      + (permission ? '' : ` (${cause})`)
      + `, so its contents never reached a check. ${pathLength}`
      + 'The score above is an upper bound, not a measurement of this tree: nothing was ruled out '
      + 'about this file, and a credential or an injected instruction in it would be invisible to '
      + 'this scan — leaving the score HIGHER than if the file had been readable, because the '
      + 'evidence simply left the assessment. Re-run once it can be read. If it is meant to be '
      + 'unreadable, scan a narrower target that does not contain it — an `.hmaignore` path rule '
      + 'will not clear this, because it scopes what is reported about a file and cannot make an '
      + 'unread file read.';
  return {
    checkId: 'SCAN-UNREAD-001',
    name: 'Input Discovered But Not Read',
    description: isDir
      ? 'A directory inside the target was discovered and could not be listed, so nothing inside it reached any check'
      : 'A file inside the target was discovered and its contents could not be read, so no check examined it',
    category: 'hardening',
    severity: 'medium',
    // `passed: false` so it is SHOWN. A `passed: true` finding is filtered
    // out of the report, which is how an earlier disclosure managed to
    // exist in the code and appear nowhere on screen.
    passed: false,
    message: isDir
      ? `${shown} could not be listed (${code}) — its contents were not discovered, so nothing inside it reached any check.`
      : `${rel} could not be read (${code})`,
    file: shown,
    kind,
    fixable: false,
    fix,
    guidance,
  } as any;
}

export interface CreatedFileRecord {
  /** Path relative to the scan target. */
  path: string;
  /** sha256 of the generated content, at the moment it was recorded. */
  sha256: string;
}

/** v2 backup manifest. v1 manifests are read defensively — see readManifest. */
export interface BackupManifest {
  version?: number;
  /** Files that existed before the fix and were copied into the backup. */
  existingFiles: string[];
  /**
   * Backup candidates observed missing WHEN THE BACKUP WAS TAKEN. Candidates
   * only, not claims: nothing here is known to have been written.
   */
  absentAtBackup: string[];
  /**
   * Paths proven missing immediately BEFORE a fix wrote them (#300/#304).
   *
   * Kept apart from `absentAtBackup` because the two are different evidence
   * and `recordCreatedFiles` turns both into a rollback-time `unlink`. Folding
   * write-time absences into the backup-time list silently falsified the
   * safety argument stated at that call site — that every entry was observed
   * missing at backup time — which is the one property making the delete safe.
   */
  absentAtFixWrite?: string[];
  /** Files a fix stage created, hashed so rollback can verify before deleting. */
  createdFiles: CreatedFileRecord[];
  /** v1 `createdFiles` entries, preserved verbatim so rollback can report them. */
  legacyCreatedFiles?: string[];
}

/** What a rollback actually did, so the CLI never overstates it. */
export interface RollbackReport {
  /** Files restored from the backup copy. */
  restored: string[];
  /** Generated files removed (content hash still matched). */
  removed: string[];
  /** Generated files left in place because the user edited them since. */
  keptModified: string[];
  /** Files a pre-0.25.1 manifest listed with no hash to verify against. */
  keptUnverifiable: string[];
  /**
   * Files the manifest listed that could NOT be put back, with the reason
   * (#327). A rollback with any of these has not completed, so the caller must
   * report this rather than claim a clean revert.
   *
   * #338/#346 — `backupHoldsCopy` says whether the backup actually still holds a
   * copy of THIS entry. It is the fact the retention decision is made on, and
   * the fact the header states; both used to be asserted unconditionally of
   * every entry, and for a manifest naming a file the backup never held, both
   * were false.
   */
  unrestored: Array<{ path: string; reason: string; backupHoldsCopy: boolean }>;
  /**
   * Files the manifest listed as GENERATED that this run could not act on
   * (#342).
   *
   * #327's stated property is that a rollback either puts every listed file back
   * or says which ones it could not, and only `existingFiles` got that channel.
   * A `createdFiles` entry whose destination would not resolve was dropped with a
   * bare `continue`, and the legacy loop did the same: measured on a `SOUL.md`
   * that is a symlink, `[+] Rollback complete / removed 0 generated files`, exit
   * 0, the file still on disk and the backup consumed.
   *
   * Reported, never retained on: the backup holds no copy of a generated file, so
   * keeping the directory buys nothing and would feed the #338 wedge.
   */
  unremoved: Array<{ path: string; reason: string }>;
  /**
   * Backups this run passed over because they could not be used at all — a
   * symlink, a non-directory, an unreadable or implausible manifest (#338).
   *
   * Selection is a GUESS at a name the scanned tree can write, so it must be
   * able to try the next candidate. These are reported, never deleted: HMA
   * could not read them, so it cannot know they hold nothing.
   */
  skippedBackups: Array<{ name: string; reason: string }>;
  /**
   * Candidates that listed files and put none of them back.
   *
   * A backup that promised entries and delivered nothing is not this run's
   * backup, whatever the reason — and the reason is always something the scanned
   * tree arranged, at one end or the other. It is KEPT (it may hold bytes nobody
   * can read yet), reported, and passed over, so one forged directory cannot
   * stand in front of the real backup for ever.
   */
  barrenBackups: Array<{ name: string; listed: number }>;
  /**
   * How many further backup directories sit behind the one this run used
   * (#338). Reported when a rollback does not complete, so a user staring at a
   * retained directory is told that dealing with it uncovers another.
   */
  backupsBehind: number;
  /**
   * Where the backup was left when it still holds a copy of something that
   * could not be restored. Absent when the backup held nothing worth keeping,
   * which is the case that consumes it.
   */
  backupRetainedAt?: string;
  /** Which backup directory under the base this run actually used. */
  backupUsed?: string;
  /**
   * The backup this run finished with and could not delete.
   *
   * Its own channel, not `backupRetainedAt`: that one means "kept on purpose,
   * because it still holds a copy", it is rendered only inside the
   * `unrestored` block, and a run with nothing unrestored would have set it and
   * printed nothing — a backup left on disk with no line saying so.
   */
  backupRemovalFailed?: { path: string; reason: string };
}

// `ResolveRefusal` / `ResolveOutcome` / `resolveInsideTree` moved to
// `./contain` (#270). The write side needs the identical containment property
// and had none, and two implementations of "is this path inside the tree" is
// exactly how that asymmetry arose.

/** Why one manifest entry could not be put back. */
type RestoreRefusal =
  | ResolveRefusal
  | 'source-outside-backup'
  | 'source-unreadable'
  | 'source-resolves-outside-backup'
  | 'source-not-regular-file'
  | 'source-unexaminable'
  | 'write-failed';

/**
 * One sentence per cause, each true of that cause and of nothing else.
 *
 * Written as a total record rather than a `switch` with a default, so adding a
 * refusal without giving it a sentence is a compile error rather than a silent
 * fallback to whichever sentence was nearest.
 */
const RESTORE_REFUSAL_REASONS: Record<RestoreRefusal, string> = {
  'escapes-tree': 'the manifest entry points outside the scanned directory',
  'parent-unresolvable': 'the directory it belongs in could not be resolved',
  'parent-outside-tree': 'a directory on the way to it leads outside the scanned directory',
  'leaf-is-link': 'a symbolic link stands where the file should be',
  'leaf-link-dangling': 'it is a symbolic link that points at nothing',
  'leaf-link-outside-tree': 'it is a symbolic link that points outside the scanned directory',
  'leaf-unexaminable': 'the filesystem would not say what is currently at that path',
  'source-outside-backup': 'the manifest entry points outside the backup',
  'source-unreadable': 'the backup holds no readable copy of it',
  'source-resolves-outside-backup': 'the copy in the backup resolves outside the backup',
  'source-not-regular-file': 'the copy in the backup is not a regular file',
  'source-unexaminable': 'the copy in the backup could not be examined',
  'write-failed': 'writing it back failed',
};

/**
 * Defines which checks apply to which project types
 * Key: check ID prefix or full ID
 * Value: array of project types this check applies to
 *
 * If a check ID is not in this map, it applies to 'all' project types
 */
const CHECK_PROJECT_TYPES: Record<string, ProjectType[]> = {
  // Core security checks - apply to all projects
  'CRED-': ['all'], // Credential exposure - always critical
  'GIT-': ['all'], // Git security - always important
  'PERM-': ['all'], // File permissions - always important
  'DEP-': ['all'], // Dependencies - always important

  // Environment checks - API/webapp mostly
  'ENV-': ['webapp', 'api', 'mcp'],

  // AI-specific checks - apply to MCP servers and AI-integrated projects
  'CLAUDE-': ['all'], // Claude-specific (if files exist)
  'MCP-': ['mcp'], // MCP configuration - only MCP servers
  'PROMPT-': ['mcp', 'api'], // Prompt injection - MCP and APIs
  'TOOL-': ['mcp'], // MCP tool boundaries

  // Web-specific checks - only for web apps and APIs
  'AUTH-': ['webapp', 'api'], // Authentication/authorization
  'SESSION-': ['webapp', 'api'], // Session management
  'NET-': ['webapp', 'api'], // Network security (HTTPS, etc.)
  'IO-': ['webapp', 'api'], // Input/output (XSS, etc.)

  // Skill/config checks - apply to all because if these files exist, they matter
  'SKILL-': ['all'], // Skill file security (fires only when skill files exist)
  'HEARTBEAT-': ['all'], // Heartbeat/periodic task security (fires only when HEARTBEAT.md exists)
  'GATEWAY-': ['openclaw'], // Gateway configuration security
  'CONFIG-': ['all'], // Configuration file security (fires only when config files exist)
  'SUPPLY-': ['all'], // Supply chain security (fires only when skill files exist)
  'CVE-': ['openclaw'], // CVE-specific detection
  'API-': ['api'], // API security headers
  'RATE-': ['webapp', 'api'], // Rate limiting
  'PROC-': ['webapp', 'api'], // Process security (headers, etc.)

  // Database/encryption - only for apps with data storage
  'INJ-': ['webapp', 'api'], // SQL injection, input validation
  'ENCRYPT-': ['webapp', 'api'], // Encryption, password hashing

  // Logging/audit - servers and MCP.
  //
  // ORDER IS LOAD-BEARING. `findingAppliesTo` takes the FIRST key that matches,
  // so `LOG-002` must stay ABOVE `LOG-` or it silently falls back to the group
  // and stops applying outside webapp/api/mcp. Held by
  // `check-project-types-order.test.ts`.
  //
  // The LOG- group is advice ("consider structured logging"), which is why it
  // is scoped to server-shaped projects. LOG-002 is NOT advice: it matches
  // sensitive data in a log call in code that was read. Code that logs a
  // password is wrong in a library exactly as much as in an API (#421).
  'LOG-002': ['all'],
  'LOG-': ['webapp', 'api', 'mcp'],
  'AUDIT-': ['webapp', 'api'],

  // Sandboxing - containerized apps
  'SANDBOX-': ['webapp', 'api', 'mcp'],

  // Secret management - primarily for apps with secrets
  'SEC-': ['webapp', 'api', 'mcp'],

  // Semantic analysis - applies to all project types
  'SEM-': ['all'],

  // Unicode steganography - applies to all projects
  'UNICODE-STEGO-': ['all'],

  // Agent memory/context checks
  'MEM-': ['all'],
  // RAG poisoning checks
  'RAG-': ['all'],
  // Agent identity checks
  'AIM-': ['all'],
  // Agent DNA integrity checks
  'DNA-': ['all'],
  // Skill memory manipulation checks
  'SKILL-MEM-': ['openclaw', 'mcp'], // dead entry: the SKILL- group is declared first and wins
  // NemoClaw/sandbox static analysis checks
  'NEMO-': ['all'],

  // AI infrastructure exposure checks (research gap coverage)
  'LLM-': ['all'], // LLM inference endpoint exposure
  'AITOOL-': ['all'], // AI tooling exposure (Jupyter, Gradio, etc.)
  'A2A-': ['all'], // A2A protocol exposure
  'WEBCRED-': ['all'], // Credentials in web-served files

  // Code injection and supply chain checks
  'CODEINJ-': ['all'], // Code injection via exec with interpolation
  'INSTALL-': ['all'], // Unsafe install scripts (curl|sh)
  'CLIPASS-': ['all'], // Credentials passed as CLI arguments
  'INTEGRITY-': ['all'], // Integrity check bypass
  'TOCTOU-': ['all'], // Time-of-check-time-of-use race conditions
  'TMPPATH-': ['all'], // Hardcoded /tmp path attacks
  'DOCKERINJ-': ['all'], // Docker exec with variable injection
  'ENVLEAK-': ['all'], // Environment variable leakage to child processes
  'SANDBOX-005': ['openclaw', 'mcp'], // Messaging API pre-allowed in sandbox (dead entry: the SANDBOX- group is declared first and wins)
  'WEBEXPOSE-': ['all'], // Sensitive files in web-served directories
  'AGENT-CRED-': ['all'], // Missing credential protection in system prompts
  'SOUL-OVERRIDE-': ['all'], // Skill content overriding SOUL.md
  'SOUL-': ['all'],          // SOUL governance gap checks

  // Context lifecycle checks (assembly-stage analysis)
  'LIFECYCLE-': ['all'],
};

/** Scan depth for CAAT tiered scanning */
export type ScanDepth = 'quick' | 'standard' | 'deep';

export interface ScanOptions {
  targetDir: string;
  autoFix?: boolean;
  /** Preview fixes without applying them */
  dryRun?: boolean;
  /** Check IDs to ignore (e.g., ['CRED-001', 'GIT-002']) */
  ignore?: string[];
  /** File/folder paths to ignore (e.g., ['.env', 'secrets/', 'test/']) */
  ignorePaths?: string[];
  /** Enable Layer 3 LLM analysis (requires ANTHROPIC_API_KEY in CLI mode) */
  deep?: boolean;
  /**
   * CAAT scan depth tier:
   *   quick    — config checks, credential detection, basic file analysis only (Tier 4)
   *   standard — all hardening checks + dependency audit (default, Tier 2-3)
   *   deep     — everything + LLM semantic analysis + attack simulation (Tier 1)
   */
  scanDepth?: ScanDepth;
  /** Progress callback for long-running operations */
  onProgress?: (message: string) => void;
  /** CLI command prefix for fix messages (default: 'hackmyagent') */
  cliName?: string;
  /**
   * Set to true when scanning a downloaded npm/registry package (not a local project).
   * Suppresses checks that only make sense for source repos (GIT-001, GIT-002, GIT-003).
   */
  isNpmPackage?: boolean;
  /**
   * The NanoMind semantic pass, run INSIDE the coverage ledger's window (#499).
   *
   * The caller supplies it as a hook rather than calling it after `scan()`
   * returns, and that placement is the whole fix. `scan()` installs the ambient
   * ledger around `scanInner` only, so a semantic pass invoked afterwards ran
   * with `activeLedger` null: its reads reported nothing, its read FAILURES
   * reported nothing, and at `--scan-depth quick` — where 55 of the 61 static
   * checks are skipped and the semantic layer is the only reader of the tree —
   * an unreadable credential file left the assessment entirely. `secure` scored
   * that tree 98/100 at exit 0 while the same tree readable scored 69/100 at
   * exit 1.
   *
   * Running here also puts the pass ahead of the three things that consume the
   * ledger and used to happen first: the `unreadablePaths()` collection and its
   * per-path `SCAN-UNREAD-001` findings, the `.hmaignore` scope filter applied
   * to them, and the coverage snapshot on the result. So the semantic layer's
   * lost inputs travel the exact channels a static check's do, through one
   * settlement point, with no second source of truth and no per-channel copy
   * (#494 is the receipt for why that matters).
   *
   * It is invoked OUTSIDE any `coverage.run()` frame, which is what keeps the
   * scope narrow: with an empty method stack `noteRead` drops the read as
   * unattributable, so semantic SUCCESSES stay out of `filesExamined`, while
   * `noteReadFailure` records the failure as `(unattributed)`. That asymmetry is
   * the ledger's documented safety direction — dropping a success understates
   * coverage, dropping a failure would assert nothing was lost — and it is why
   * this fix moves the gate without re-baking a single coverage number.
   *
   * Findings it returns are appended before the score is computed. A throw is
   * contained: the semantic layer is an enhancement and must never take the
   * static scan down with it.
   */
  // Drafts on both sides: the semantic pass runs INSIDE the scan, upstream of
  // route point 4, so it neither receives nor returns emitted findings. Typing
  // it on `SecurityFinding` would oblige a merge pass to invent the two
  // redaction fields it is in no position to know.
  semanticPass?: (ctx: {
    targetDir: string;
    findings: SecurityFindingDraft[];
    projectType: ProjectType;
  }) => Promise<{ findings?: SecurityFindingDraft[] } | void>;
}

// Patterns for detecting exposed credentials
// Each pattern is carefully tuned to minimize false positives
const CREDENTIAL_PATTERNS = [
  // Anthropic: sk-ant-api followed by version and 20+ char key
  { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/ },
  // OpenAI project keys: sk-proj- prefix with 20+ chars
  { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/ },
  // OpenAI legacy keys: sk- followed by 48+ chars (avoid short matches)
  { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/ },
  // AWS Access Key: AKIA prefix, exactly 20 chars total
  { name: 'AWS_ACCESS_KEY', pattern: /AKIA[0-9A-Z]{16}/ },
  // Note: AWS Secret Key pattern removed - generic base64 causes false positives
  // GitHub fine-grained PAT
  { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/ },
  // GitHub PAT (new format)
  { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/ },
  // Slack tokens: very specific format
  { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/ },
  // Google API keys: AIza prefix
  { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/ },
  // Stripe live/test keys
  { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/ },
  // SendGrid
  { name: 'SENDGRID_KEY', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/ },
];

/**
 * #292 — config-shaped filenames CRED-001 inspects for hardcoded credentials.
 *
 * These used to be probed only as `path.join(targetDir, name)`, so the same
 * token scored 69/100 at `config.json` and 96/100 with no finding at all at
 * `src/config.json`, `sub/config.json` or `config/production.json`. A
 * conventional layout therefore passed clean. Code files were never affected —
 * the AST layer covers those at any depth (AST-CRED-001/003) — so the gap was
 * specific to config-shaped files below the scan root.
 *
 * Matching is on BASENAME at any depth, via the bounded, symlink-safe walk in
 * `collectSensitiveArtifacts`. Order of the root probe is preserved separately
 * by the caller so existing golden output does not churn.
 */
const CONFIG_CANDIDATE_NAMES = new Set([
  'config.json',
  'config.yaml',
  'config.yml',
  'mcp.json',
  'settings.json',
  'secrets.json',
  'credentials.json',
  '.env',
  '.env.local',
  'CLAUDE.md',
]);

/**
 * Spans in `text` that are well-formed environment-variable references.
 *
 * Deliberately strict: matched braces and a shell-identifier name. `${FOO`
 * is malformed and `${sk-ant-api03-…}` is not an identifier, so neither earns
 * an exemption. Mirrors the anchored `isEnvRef` predicate GATEWAY-003 already
 * uses, adapted from whole-value to span matching because CRED-001 scans raw
 * lines rather than parsed JSON values.
 */
function envRefSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  const re = /\$\{[A-Za-z_][A-Za-z0-9_]*\}/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) spans.push([m.index, m.index + m[0].length]);
  return spans;
}

/**
 * #301 — a reference wraps a NAME. A span whose name is itself
 * credential-shaped is a VALUE wearing reference syntax, and earns nothing.
 *
 * #281 replaced a substring test with a span test, which was the right
 * shape, but the span pattern is a shell identifier — `[A-Za-z_][A-Za-z0-9_]*`
 * — and five of the ten credential patterns are built entirely from
 * identifier-legal characters. So the credential FITS INSIDE the exemption:
 *
 *   {"token":"ghp_aaa…"}      score 69   CRED-001 fires
 *   {"token":"${ghp_aaa…}"}   score 96   CRED-001 silent
 *
 * Two braces, and a CRITICAL is gone — the same one-token suppression #281
 * set out to remove, relocated from "append a reference" to "become one".
 * Affects `ghp_`, `github_pat_`, `sk_live_`, `AKIA`, and dash-free `AIza`.
 * Anthropic/OpenAI/Slack/SendGrid keys contain `-` or `.`, which no
 * identifier admits, which is why the suite never saw this.
 *
 * The legitimate exemption survives untouched, because the names it exists
 * for are not credential-shaped: `${ANTHROPIC_API_KEY}`, `${GITHUB_TOKEN}` —
 * including the ones CRED-001's own fix writes — match no pattern here.
 *
 * What this DOES give up is a braced AWS-key-shaped NAME, a variable genuinely
 * named after the credential it holds, which now reports. That trade is
 * deliberate and one-directional: a name indistinguishable from a live key is
 * indistinguishable to a reader too, the finding names the file and line, and
 * the cost of the other reading is a silently unreported secret.
 */
function isCredentialShapedName(inner: string, pattern: RegExp): boolean {
  // Non-global: `test` on a /g regex advances lastIndex between calls.
  return new RegExp(pattern.source, pattern.flags.replace(/g/g, '')).test(inner);
}

/**
 * #281 — true when `text` carries a live credential that is NOT merely part of
 * an environment-variable reference.
 *
 * CRED-001 tested `line.includes('${' + envVar + '}')` and MCP-003 tested
 * `!value.includes('${')`. Both are SUBSTRING tests over the whole line/value,
 * so appending ` ${ANTHROPIC_API_KEY}` to a live key silenced the check and
 * moved the score — a one-token suppression of a CRITICAL finding, available
 * to anyone who can edit the file being scanned. GATEWAY-003 was given an
 * anchored whole-value predicate in 0.25.1; this is the same discipline.
 *
 * The exemption is kept, but narrowed to what it was actually for: a match
 * that lies ENTIRELY inside a well-formed reference. That still matters —
 * `AKIA[0-9A-Z]{16}` matches inside a braced name of that shape, and
 * `AIza[0-9A-Za-z_-]{35}` inside a long `${AIza…}`, so a blanket removal
 * would invent false positives on legitimately-referenced variables.
 */
export function hasCredentialOutsideEnvRef(text: string, pattern: RegExp): boolean {
  if (typeof text !== 'string' || text.length === 0) return false;
  // Fresh global regex: callers pass both /g and non-/g patterns, and a
  // shared /g regex carries `lastIndex` between calls.
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
  // #301 — a span only exempts if it references a NAME. `${ghp_aaa…}` is the
  // key itself in braces, so it is not an exemption, it is the finding.
  const spans = envRefSpans(text).filter(
    ([s, e]) => !isCredentialShapedName(text.slice(s + 2, e - 1), pattern),
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const start = m.index;
    const end = m.index + m[0].length;
    const insideRef = spans.some(([s, e]) => start >= s && end <= e);
    if (!insideRef) return true;
    if (m[0].length === 0) re.lastIndex++; // guard against zero-width loops
  }
  return false;
}

/**
 * The only characters a `${...}` reference may pad a credential with. Shell
 * identifier bytes, and deliberately nothing else: this class cannot cross a
 * quote, comma, colon or brace, which is the entire safety property below.
 */
const REF_PADDING_CHAR = /[A-Za-z0-9_]/;

/**
 * Replace every occurrence of `pattern` in one line with `${envVar}`, absorbing
 * an enclosing `${...}` wrapper when — and only when — the wrapper really is
 * one.
 *
 * #310 — this replaced a regex, `/\$\{[^{}]*\}/g`, whose character class
 * admits quotes, commas and colons. On a minified one-line config it paired the
 * `${` of an unrelated value with the NEXT `}` anywhere on the line and deleted
 * everything between:
 *
 *   {"template":"${","token":"ghp_…","keep":"KEEP","port":8080}
 *     ->  {"template":"${GITHUB_TOKEN}          <- two keys gone, invalid JSON
 *
 * and reported `fixed: true` at 98/100 over the wreckage. A regex cannot
 * express "the brace that opens THIS span", so the span is walked out from the
 * match instead: over identifier padding only, and only into a `${` that is
 * still adjacent after that walk. Everything a reference may legally contain is
 * absorbed; nothing else can be, because the padding class cannot reach past a
 * structural character.
 *
 * The three shapes #308 exists for are still absorbed whole — `${MY_ghp_…}`,
 * `${ghp_…_PROD}`, `${A_ghp_…_B}` — so the fix no longer emits the
 * `${MY_${GITHUB_TOKEN}}` nesting that no shell expands. An unterminated
 * `"${ghp_…<EOL>` absorbs its opener too, since there is no brace to pair with
 * and leaving it would emit exactly that nesting.
 *
 * A `${` that is NOT followed by a well-formed span — `${MY_ghp_…"}` — is left
 * alone and only the credential is replaced. That is literal text that happens
 * to precede a credential, not a reference, and preserving it is lossless.
 */
export function replaceCredentialWithEnvRef(
  line: string,
  pattern: RegExp,
  envVar: string,
): string {
  const ref = '${' + envVar + '}';
  const re = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g',
  );
  let out = '';
  let cursor = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++; // zero-width match: never advances on its own
      continue;
    }
    if (m.index < cursor) continue; // already inside an absorbed wrapper
    let start = m.index;
    let end = start + m[0].length;

    // Walk left over padding, stopping at `cursor` so the walk can never
    // re-enter text an earlier replacement already emitted.
    let left = start;
    while (left > cursor && REF_PADDING_CHAR.test(line[left - 1])) left--;
    if (left - 2 >= cursor && line[left - 1] === '{' && line[left - 2] === '$') {
      let right = end;
      while (right < line.length && REF_PADDING_CHAR.test(line[right])) right++;
      if (line[right] === '}') {
        start = left - 2;
        end = right + 1;
      } else if (line.indexOf('}', end) === -1) {
        start = left - 2; // unterminated span: absorb the opener, keep `end`
      }
    }

    out += line.slice(cursor, start) + ref;
    cursor = end;
    if (re.lastIndex < cursor) re.lastIndex = cursor;
  }
  return out + line.slice(cursor);
}

/**
 * #292, second half — directories whose contents are config BY LOCATION rather
 * than by filename. `config/production.json` is the case the issue calls out
 * explicitly, and basename matching alone does not reach it: nothing about
 * `production.json` is config-shaped, the enclosing `config/` is.
 *
 * Scoped to structured-data extensions so a `config/README.md` or a
 * `config/build.ts` (already covered by the AST layer) is not re-read here.
 */
const CONFIG_DIR_NAMES = new Set(['config', 'conf', 'configs', 'settings']);
const CONFIG_DIR_EXTENSIONS = new Set(['.json', '.yaml', '.yml', '.toml', '.ini']);

/**
 * The directory `--fix` writes its backups into. Named once because two
 * different walks have to agree about it, and they did not: the gateway walk
 * tested the entry NAME at every level while the sensitive-artifact walk
 * tested a root-anchored PREFIX (#302).
 */
const BACKUP_DIR_NAME = '.hackmyagent-backup';

/**
 * A directory named by its filesystem IDENTITY rather than by any spelling of
 * its path.
 *
 * Four rounds of this subsystem's guards were strings that DESCRIBE the backup
 * directory — a `\`-folded path (#304), a directory name (#305), a manifest
 * shape (#309), a case-sensitive `path.resolve` prefix compare (#317) — and
 * every round the attacker changed the string without changing the directory.
 * `dev`+`ino` is the directory itself: it cannot be respelled by case folding
 * on a case-insensitive filesystem, by a symlink, by Unicode normalization, or
 * by a `..` that cancels out.
 */
interface FsIdentity {
  dev: number;
  ino: number;
}

/**
 * The identity of what a path reaches, or why it could not be taken.
 *
 * #333 — `identityOf` used to return `null` for every failure, and `null` means
 * "not our backup" to both callers. For the DETECTION walk that is fail-closed:
 * the directory gets scanned, so nothing is hidden. For the WRITE gate it is
 * fail-OPEN — `isInsideOwnBackup` returning false there means ALLOW THE WRITE —
 * so any `EACCES`, `ELOOP`, `EIO` or `EMFILE` on an ancestor `stat` during a
 * `--fix` run left HackMyAgent free to rewrite its own backup, with only the
 * name check standing in the way: the string this whole change argues cannot be
 * trusted.
 *
 * Only ENOENT proves absence. Everything else proves nothing, and "I could not
 * check" must not become "it is not ours" — the same inference as #313, and as
 * the `resolveInsideTree` fail-open fixed earlier in this stack.
 */
type IdentityProbe =
  | { kind: 'identity'; id: FsIdentity }
  /** Proven absent: nothing is there. */
  | { kind: 'absent' }
  /** The filesystem refused to answer. Establishes nothing in either direction. */
  | { kind: 'unknown' };

/** `stat`, not `lstat`: the identity wanted is the directory a path REACHES. */
async function identityOf(p: string): Promise<IdentityProbe> {
  try {
    const st = await fs.stat(p);
    return { kind: 'identity', id: { dev: st.dev, ino: st.ino } };
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'absent' }
      : { kind: 'unknown' };
  }
}

/** Fails closed: a missing identity on either side is never a match. */
function sameIdentity(a: FsIdentity | null | undefined, b: FsIdentity | null | undefined): boolean {
  return !!a && !!b && a.dev === b.dev && a.ino === b.ino;
}

/** The identity if one could be taken, else undefined — for the callers that only need a match. */
function identityOrUndefined(probe: IdentityProbe): FsIdentity | undefined {
  return probe.kind === 'identity' ? probe.id : undefined;
}

/**
 * A backup-setup failure that carries WHY, machine-readably.
 *
 * `FIX-BACKUP-FAILED` used to report `code` from `err.name`, which is `Error` for
 * anything that is not an errno — so a refusal HMA decided on its own arrived at
 * the user as a bare "Backup failed (Error)" under guidance that listed only
 * permission causes and a fix line saying "make the target writable". For a
 * symlinked backup base that advice is wrong: making it writable changes nothing.
 * The code lets the finding name the real cause and the matching remedy.
 */
type BackupSetupCode = 'HMA-BACKUP-SYMLINK' | 'HMA-BACKUP-NOT-DIR'
  | 'HMA-BACKUP-OUTSIDE-TREE' | 'HMA-BACKUP-NO-NEW-DIR' | 'HMA-BACKUP-VANISHED'
  | 'HMA-BACKUP-UNIDENTIFIED';

function backupSetupError(code: BackupSetupCode, message: string): NodeJS.ErrnoException {
  const err = new Error(message) as NodeJS.ErrnoException;
  err.code = code;
  return err;
}

/*
 * `backupArchiveDirFor` used to live here: it walked the path's SEGMENTS looking
 * for one spelled `.hackmyagent-backup`, exactly or case-folded.
 *
 * It is gone with #341, and so is everything built on it. Recognising an archive
 * by a name in the scanned tree is the sixth instance of the class this stack
 * exists to close — a `\`-folded path (#304), a directory name (#305), a
 * manifest shape (#309), a case-sensitive compare (#317), a manifest array
 * element (#326), a manifest's existence (#331) — and the exact-name half was
 * never gated on anything at all, so a `vendor/.hackmyagent-backup/lib/…`
 * credential was left in plaintext with no forgery required.
 *
 * See `resolveArchiveBase` for what replaced it: not a better description of the
 * directory, but the directory.
 */

/**
 * The backup directory HackMyAgent uses for a given tree, as the filesystem
 * resolves it — or null when there is none.
 *
 * This is the whole answer to "is this file inside a backup archive". It is not
 * a name, not a shape, and not a file: it is `<realpath(target)>/`
 * `.hackmyagent-backup` as `realpath.native` canonicalizes it, plus that
 * directory's `dev`+`ino`. The scanned tree can CREATE that directory — that is
 * the ordinary pre-existing-backup case, and adopting it is correct — but it
 * cannot make some other directory be it, under any spelling.
 *
 * `realpath.native` is what makes one rule cover every spelling: on a
 * case-insensitive filesystem a tree shipping `.HACKMYAGENT-BACKUP` IS this
 * directory and resolves to it, and on a case-sensitive one it is a different
 * directory that HackMyAgent would never write to. Neither case needs a
 * per-spelling rule, and no Unicode fold, symlink or `..` changes the answer.
 *
 * Three-valued, and only a PROVEN absence is `none`. Returning "no base here"
 * on any failure would be fail-OPEN at the one caller that matters: the write
 * gate reads "not an archive" as permission to rewrite the file, so a transient
 * EACCES on the tree root would have authorised HackMyAgent to redact a previous
 * run's backup. That is #313's inference and #333's, arrived at through a
 * different door.
 *
 * A base that is a symlink or not a directory IS a proven `none`:
 * `prepareBackupRoot` refuses to write backups through either, so there is
 * nothing of HackMyAgent's in that tree to protect.
 */
type ArchiveBase =
  | { kind: 'base'; real: string; ident: FsIdentity }
  /** Proven: nothing HackMyAgent would use as a backup base is there. */
  | { kind: 'none' }
  /** The filesystem refused to answer. Establishes nothing in either direction. */
  | { kind: 'unknown' };

async function resolveArchiveBase(targetDir: string): Promise<ArchiveBase> {
  let treeReal: string;
  try {
    treeReal = await fs.realpath(targetDir);
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'none' }
      : { kind: 'unknown' };
  }

  const base = path.join(treeReal, BACKUP_DIR_NAME);
  try {
    const st = await fs.lstat(base);
    // A base that is a symlink or not a directory is PROVEN not to be an archive
    // of ours: `prepareBackupRoot` refuses to write backups through either, so
    // there is nothing of HackMyAgent's in that tree to protect.
    if (st.isSymbolicLink() || !st.isDirectory()) return { kind: 'none' };
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'none' }
      : { kind: 'unknown' };
  }

  let real: string;
  try {
    real = fsSync.realpathSync.native(base);
  } catch (err) {
    return (err as NodeJS.ErrnoException)?.code === 'ENOENT'
      ? { kind: 'none' }
      : { kind: 'unknown' };
  }

  return archiveBaseFromProbe(await identityOf(real), real);
}

/**
 * The base a probe of the resolved directory establishes.
 *
 * Split out because the window between "lstat said directory" and "stat for the
 * identity" is not something a test can hold open, and mutating this clause to
 * `{ kind: 'none' }` left the whole suite green — which by this project's own
 * rule (#347.1) means the fail-open direction was untested.
 */
export function archiveBaseFromProbe(probe: IdentityProbe, real: string): ArchiveBase {
  if (probe.kind === 'identity') return { kind: 'base', real, ident: probe.id };
  return probe.kind === 'absent' ? { kind: 'none' } : { kind: 'unknown' };
}

/** True when a file is config-shaped by filename, or by sitting directly in a config directory. */
function isConfigShapedFile(basename: string, parentDirName: string): boolean {
  if (CONFIG_CANDIDATE_NAMES.has(basename)) return true;
  if (!CONFIG_DIR_NAMES.has(parentDirName.toLowerCase())) return false;
  return CONFIG_DIR_EXTENSIONS.has(path.extname(basename).toLowerCase());
}

// MEM-006 receiver gate: persistence-semantic identifier parts. A `.push(...)`
// only counts as a memory/persistence sink when its receiver chain contains one
// of these word-parts (matched after splitting on dots, brackets, snake_case,
// and camelCase humps) — so `userMemory`/`vectorStore`/`chatHistory` fire while
// local render arrays (`lines`/`out`/`parts`) do not. See checkMemoryStoreSanitization.
const PERSISTENT_RECEIVER_PARTS = new Set([
  'mem', 'memo', 'memos', 'memory', 'memories',
  'history', 'histories',
  'conversation', 'conversations', 'convo', 'convos',
  'context', 'contexts',
  'session', 'sessions',
  'message', 'messages',
  'chat', 'chats',
  'transcript', 'transcripts',
  'store', 'stores',
  'cache', 'caches',
  'persist', 'persistence',
  'db', 'database', 'databases',
]);

// OpenClaw skill security patterns
const SKILL_REMOTE_FETCH_PATTERNS: RegExp[] = [
  /curl\s+(-[a-zA-Z]+\s+)*https?:\/\//gi,
  /wget\s+(-[a-zA-Z]+\s+)*https?:\/\//gi,
  /fetch\s*\(\s*['"`]https?:\/\//gi,
  /\|\s*(ba)?sh/gi,  // pipe to shell
  /\|\s*sudo/gi,     // pipe to sudo
];

const SKILL_CREDENTIAL_ACCESS_PATTERNS: RegExp[] = [
  /~\/\.ssh/gi,
  /~\/\.aws/gi,
  /~\/\.config\/solana/gi,
  /~\/\.config\/gcloud/gi,
  /~\/\.kube/gi,
  /~\/\.gnupg/gi,
  /keychain/gi,
  /wallet.*\.json/gi,
  /seed.*phrase/gi,
  /private.*key/gi,
  // Match .env as a standalone file reference, not as part of process.env or documentation
  // like ".env.example in sync" or "set in .env.local"
  /(?:^|[\s"'`(])\.env(?:\.local|\.production|\.development)?(?:[\s"'`)]|$)/gi,
  /credentials\.json/gi,
];

const SKILL_EXFILTRATION_PATTERNS: RegExp[] = [
  /webhook\.site/gi,
  /requestbin/gi,
  /ngrok\.io/gi,
  /curl\s+[^\n]*?-d\s/gi,      // Non-greedy with newline boundary
  /curl\s+[^\n]*?--data/gi,
  /curl\s+[^\n]*?-X\s*POST/gi,
  /fetch\s*\([^)]*method:\s*['"]POST/gi,
];

const SKILL_REVERSE_SHELL_PATTERNS: RegExp[] = [
  /nc\s+(-[a-zA-Z]+\s+)*.*-e/gi,
  /bash\s+-i\s+/gi,
  /\/dev\/tcp\//gi,
  /\/dev\/udp\//gi,
  /python.*socket.*connect/gi,
  /perl.*socket.*connect/gi,
];

const SKILL_CLICKFIX_PATTERNS: RegExp[] = [
  /copy\s+(and\s+)?paste\s+(this\s+)?(into|in)\s+(your\s+)?terminal/gi,
  /run\s+this\s+command/gi,
  /execute\s+(the\s+following|this)/gi,
  /curl.*\|\s*(ba)?sh/gi,
  /wget.*\|\s*(ba)?sh/gi,
];

const HEARTBEAT_DANGEROUS_CAPS: string[] = [
  'shell:*',
  'shell:bash',
  'shell:sh',
  'filesystem:*',
  'filesystem:~/*',
  'filesystem:/',
  'network:*',
];

// ClawHavoc campaign IOCs (Koi Security research, Jan 2026)
const CLAWHAVOC_C2_IPS = ['91.92.242.30'];
const CLAWHAVOC_MALICIOUS_FILES = [
  'openclaw-agent.exe', 'openclaw-agent.zip', 'openclawcli.zip',
  'agent-setup.exe', 'openclaw-installer.dmg',
];
const CLAWHAVOC_CLICKFIX_PATTERNS: RegExp[] = [
  /download.*paste.*terminal/i,
  /copy.*(?:command|script).*terminal/i,
  /right[- ]click.*open/i,
  /run.*\.exe/i,
];
const CLAWHAVOC_ARCHIVE_PASSWORD = /password\s*[:=]\s*["']?(openclaw|claw|agent|setup)["']?/i;

const PROMPT_INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?(previous|prior|above)/gi,
  /disregard\s+(all\s+)?(previous|prior)/gi,
  /system:\s/gi,
  /<\|.*\|>/gi,  // special tokens
  /\[INST\]/gi,
  /\[\/INST\]/gi,
  /<<SYS>>/gi,
  /Human:/gi,
  /Assistant:/gi,
];

// Severity weights for score calculation
const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
};

/**
 * Standalone scoring function using exponential decay with governance weight.
 * This is the canonical scoring formula — all score paths must use it.
 *
 * Accepts findings with at minimum: { passed?, fixed?, severity, category, checkId }.
 *
 * Per-check capping: only the first MAX_FINDINGS_PER_CHECK instances of each
 * unique checkId contribute to the weighted sum at full weight. Additional
 * instances contribute at a steeply diminished rate (10%). This prevents a
 * single pattern-match check (e.g. AST-CRED-001) from dominating the score
 * when it fires across dozens of files in a large repository. All findings
 * are still reported — only the score contribution is capped.
 */
export function calculateSecurityScore(findings: Array<{ passed?: boolean; fixed?: boolean; severity: string; category?: string; checkId?: string }>): {
  score: number;
  maxScore: number;
} {
  const GOVERNANCE_CATEGORIES = new Set(['governance', 'Governance', 'injection-hardening', 'trust-hierarchy']);
  const GOVERNANCE_PREFIXES = ['AST-GOV', 'AST-GOVERN', 'AST-PROMPT', 'AST-HEARTBEAT'];
  const GOVERNANCE_WEIGHT = 0.4;
  const DECAY_CONSTANT = 150;
  const MAX_FINDINGS_PER_CHECK = 3;
  const OVERFLOW_WEIGHT = 0.1; // 10% weight for findings beyond the cap

  // Count occurrences per checkId to apply diminishing returns
  const checkIdCounts = new Map<string, number>();

  let weightedSum = 0;
  for (const finding of findings) {
    // Shared with the #259 verdict-band clamp so the number and the cap can
    // never disagree. A fix whose verification pass proved the issue
    // survived (`fixVerified: false`) still counts: checks set `fixed` before
    // knowing the write landed, and a swallowed `fs.chmod` failure must not
    // buy a clean score on a file that is still world-readable.
    if (countsAgainstScore(finding)) {
      const checkId = finding.checkId || '_unknown_';
      const count = (checkIdCounts.get(checkId) || 0) + 1;
      checkIdCounts.set(checkId, count);

      const isGovernance = GOVERNANCE_CATEGORIES.has(finding.category || '') ||
        GOVERNANCE_PREFIXES.some(p => (finding.checkId || '').startsWith(p));
      const governanceMultiplier = isGovernance ? GOVERNANCE_WEIGHT : 1;
      const capMultiplier = count <= MAX_FINDINGS_PER_CHECK ? 1 : OVERFLOW_WEIGHT;
      const sevWeight = SEVERITY_WEIGHTS[finding.severity as Severity] ?? 0;
      weightedSum += sevWeight * governanceMultiplier * capMultiplier;
    }
  }

  const score = weightedSum === 0
    ? 100
    : Math.round(100 * Math.exp(-weightedSum / DECAY_CONSTANT));

  return { score, maxScore: 100 };
}

/**
 * The composite this findings set would produce if the archive the current
 * `--fix` run created were not in the tree — the score of the live tree.
 *
 * #374. `undefined` when no finding is flagged `inOwnArchive`, which is the
 * normal case: a detect-only scan, a `--dry-run`, a `--fix` whose archive
 * turned out to hold nothing scoreable. Returning `undefined` rather than the
 * unchanged score keeps "there is no second number" distinguishable from "the
 * second number happens to be equal", so the report cannot print a delta line
 * claiming a 0-point archive.
 *
 * Takes the SAME array the headline score is computed from and applies the same
 * clamp, so the pair is always two views of one evidence set. Subtracting a
 * finding can only lower `weightedSum`, so this is >= the headline score.
 */
export function scoreExcludingOwnArchive(
  findings: SecurityFindingDraft[],
): number | undefined {
  if (!findings.some(f => f.inOwnArchive)) return undefined;
  const liveTree = findings.filter(f => !f.inOwnArchive);
  const { score: raw } = calculateSecurityScore(liveTree);
  // Clamped through the same #259 band as the headline. Without this a live
  // tree with one surviving HIGH would advertise an unclamped 89 next to a
  // clamped headline, and the delta would read as the archive's cost when 20
  // of it was the clamp coming off.
  return clampScoreToVerdictBand(raw, liveTree).score;
}

/**
 * Check if a finding applies to the given project type based on the
 * CHECK_PROJECT_TYPES map. Exported so CLI can filter findings after
 * NanoMind merge.
 */
export function findingAppliesTo(finding: SecurityFindingDraft, projectType: ProjectType): boolean {
  // FIRST match in declaration order. A full check ID overrides the group it
  // sits in by being DECLARED BEFORE it — `check-project-types-order.test.ts`
  // holds that ordering, because nothing else does.
  //
  // Resolving the LONGEST key instead would remove the order dependency and is
  // what the map's "prefix OR full ID" wording implies. It was tried and
  // reverted: two entries in the map are narrower than the group they sit in
  // and had never taken effect, so making them live SUBTRACTED project types.
  // `SANDBOX-005` — a HIGH file-and-line detection for a messaging API
  // pre-allowed in a sandbox policy — silently stopped applying to `webapp`
  // and `api`. Widening those entries instead put a HIGH false positive on
  // every clean library. Changing this resolution order is a detection change
  // for the whole map and needs its own corpus; it is not a side effect of
  // fixing one check.
  for (const [prefix, types] of Object.entries(CHECK_PROJECT_TYPES)) {
    if (finding.checkId.startsWith(prefix)) {
      if (types.includes('all')) return true;
      return types.includes(projectType);
    }
  }
  return true;
}

/**
 * Whether a finding would be REPORTED to the user at all.
 *
 * The one definition of the reported set, because there being two is what #457
 * was. `scanInner` gates its findings on exactly these three conditions
 * (`!f.fixed && f.passed`, `!f.file`, `!findingAppliesTo`) before it decides
 * what a suppression withheld, and five CLI call sites re-spell the same three
 * conditions after `reapplyIgnoreFilters`. `reapplyIgnoreFilters` itself did
 * not, so it recorded findings the user was never going to see as
 * "suppressed" — and #450 adds a suppressed finding's penalty back at every
 * gate. The result was a suppression that INVENTED a penalty: on a bare `mcp`
 * project, one `.hmaignore` line reading `!SANDBOX-002` moved the score from
 * 98/100 exit 0 to 69/100 exit 1, for a finding that scores nothing when it is
 * not suppressed.
 *
 * A suppression may only ever subtract from the report. Anything that is not
 * reportable cannot be withheld, so it cannot be disclosed as withheld and its
 * penalty cannot be added back.
 *
 * Callers pass `projectType` rather than reading it off the scanner because
 * `reapplyIgnoreFilters` runs on a merged array whose project type belongs to
 * the CLI's `result`, not to the scanner instance.
 */
export function isReportableFinding(
  f: { passed?: boolean; fixed?: boolean; file?: string; checkId: string },
  projectType: ProjectType,
): boolean {
  return retainForVerdict(f) && Boolean(f.file) && findingAppliesTo(f as SecurityFindingDraft, projectType);
}

/**
 * Drop failed findings that are pathless AND do not apply to the current
 * project type (issue #131 / #130). A check that fires `passed: false`
 * without `file` evidence on a project type the check is not meant for
 * is a true noise-floor finding: e.g., `NET-003` HTTPS Configuration
 * firing on an `mcp` project that doesn't expose HTTP at all.
 *
 * Pathless findings whose check DOES apply to this project type are
 * preserved — they represent real project-level detections that lack
 * file attribution due to a separate emission bug, not noise. Passed
 * findings are always retained.
 *
 * Consumers of allFindings (corpus release-smoke, benchmark, OASB-2
 * composite) get a clean signal without dropping legitimate findings.
 */
export function dropPathlessNoiseFloor(
  findings: SecurityFindingDraft[],
  projectType: ProjectType,
): SecurityFindingDraft[] {
  return findings.filter((f) => {
    if (f.passed || f.fixed) return true;
    if (f.file) return true;
    return findingAppliesTo(f, projectType);
  });
}

/**
 * True when `matchIndex` on `line` is inside a string literal or comment.
 * Walks the line character by character tracking single, double, and
 * backtick quote state plus `//` line comments and `/* ... *\/` block
 * comments. Used by NEMO-009 so eval(...) substrings passed as test
 * input to a prompt-injection screener (e.g. `screenInput('eval(atob(
 * "malicious"))')`) do not fire — the eval() token is text, not a real
 * code-execution site.
 *
 * Conservative semantics:
 *  - A backslash escape inside a quote consumes the next character if
 *    one exists. A trailing backslash at end of line consumes only the
 *    backslash itself (no phantom next-char skip).
 *  - An unclosed block comment treats the rest of the line as comment.
 *  - A line comment (`//`) outside quotes makes the rest of the line a
 *    comment.
 *  - Template-literal interpolation (`${...}` inside a backtick) is a
 *    re-entry into code state. When the helper hits `${` inside a
 *    backtick it scans forward with a brace-depth counter to find the
 *    matching `}`. If `matchIndex` lies inside that span the match is
 *    real code and the helper returns false; otherwise the helper
 *    skips past the entire `${...}` region (still inside the backtick)
 *    and keeps walking, so a `//` comment after the closing backtick
 *    is still recognized.
 *  - The helper does NOT attempt to detect regex literals. A real
 *    `/don't/; eval(payload)` line will be mis-suppressed only if the
 *    apostrophe inside the regex toggles open-quote state and the
 *    eval token comes before the regex closes; in practice eval
 *    appearing on the same line as a regex literal containing an
 *    apostrophe is rare enough to leave unhandled rather than ship a
 *    regex-context heuristic that FPs on multi-line strings.
 *  - Returns false when the match is in real code.
 *
 * Complexity: O(line.length) per call. The outer walker advances `i`
 * monotonically (every branch either does `i++` or `i = j` past a
 * matched region); the inner template-interpolation brace loop is
 * bounded by `j < line.length` and is entered at most once per `${...}`
 * region that the outer walker steps into. MAX_WALK_ITERATIONS is a
 * belt-and-suspenders cap that fires only on inputs already pathological
 * enough to be a different problem.
 */
const MAX_WALK_ITERATIONS = 100000;

export function isMatchInsideStringLiteral(line: string, matchIndex: number): boolean {
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let i = 0;
  let outerIters = 0;
  while (i < matchIndex) {
    if (++outerIters > MAX_WALK_ITERATIONS) {
      // Pathological input. Conservative default: treat the match as
      // inside-string so the suppression path fires; over-suppression
      // is a smaller harm than walker hang on a CI pipeline.
      return true;
    }
    const c = line[i];
    if (!inSingle && !inDouble && !inBacktick) {
      if (c === '/' && line[i + 1] === '/') {
        return true;
      }
      if (c === '/' && line[i + 1] === '*') {
        const end = line.indexOf('*/', i + 2);
        if (end === -1) {
          return true;
        }
        if (matchIndex < end + 2) {
          return true;
        }
        i = end + 2;
        continue;
      }
      if (c === "'") inSingle = true;
      else if (c === '"') inDouble = true;
      else if (c === '`') inBacktick = true;
    } else {
      if (inBacktick && c === '$' && line[i + 1] === '{') {
        let depth = 1;
        let j = i + 2;
        let innerIters = 0;
        while (j < line.length && depth > 0) {
          if (++innerIters > MAX_WALK_ITERATIONS) {
            // Same defensive default as the outer cap. Outer walker
            // continues past the `${...}` region by setting i.
            break;
          }
          const cj = line[j];
          if (cj === '{') depth++;
          else if (cj === '}') depth--;
          j++;
        }
        const exprStart = i + 2;
        const exprEnd = depth === 0 ? j - 1 : line.length;
        if (matchIndex >= exprStart && matchIndex < exprEnd) {
          return false;
        }
        i = depth === 0 ? j : line.length;
        continue;
      }
      if (c === '\\') {
        // Backslash escape inside a quote. Skip the next character only
        // if one exists in the line. A trailing backslash at EOL falls
        // through to the unchanged `i++` and the outer loop exits
        // naturally on the next iteration. Bound against `line.length`
        // (not `matchIndex`) so the helper stays correct if a caller
        // ever passes `matchIndex >= line.length`.
        if (i + 1 < line.length) {
          i += 2;
          continue;
        }
      }
      if (inSingle && c === "'") inSingle = false;
      else if (inDouble && c === '"') inDouble = false;
      else if (inBacktick && c === '`') inBacktick = false;
    }
    i++;
  }
  return inSingle || inDouble || inBacktick;
}

/**
 * Parsed .hmaignore rules split into path patterns and check ID patterns.
 * Check ID patterns start with `!` and support trailing `*` wildcards.
 * Example: `!SANDBOX-*` suppresses all SANDBOX checks.
 */
export interface HmaIgnoreRules {
  paths: string[];
  checkIds: string[];
}

/**
 * Load .hmaignore patterns from a target directory. Exported so CLI
 * can re-apply ignore filtering after NanoMind merge.
 */
export async function loadHmaIgnore(targetDir: string): Promise<HmaIgnoreRules> {
  const ignorePath = path.join(targetDir, '.hmaignore');
  try {
    const content = await fs.readFile(ignorePath, 'utf-8');
    const lines = content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    return {
      paths: lines.filter(l => !l.startsWith('!')),
      checkIds: lines.filter(l => l.startsWith('!')).map(l => l.slice(1)),
    };
  } catch {
    return { paths: [], checkIds: [] };
  }
}

/**
 * Check if a file path matches any .hmaignore path pattern. Exported so CLI
 * can filter findings after NanoMind merge.
 */
export function isPathIgnored(filePath: string, ignoredPaths: string[]): boolean {
  if (!filePath || ignoredPaths.length === 0) return false;
  const normalized = filePath.replace(/\\/g, '/');
  return ignoredPaths.some(pattern => {
    const normalizedPattern = pattern.replace(/\\/g, '/').replace(/\/$/, '');
    return normalized.startsWith(normalizedPattern + '/') || normalized === normalizedPattern;
  });
}

/**
 * Check if a checkId matches any .hmaignore check ID pattern.
 * Supports exact match and trailing `*` wildcard (e.g. `SANDBOX-*`).
 */
export function isCheckIgnored(checkId: string, ignoredChecks: string[]): boolean {
  if (!checkId || ignoredChecks.length === 0) return false;
  return ignoredChecks.some(pattern => {
    if (pattern.endsWith('*')) {
      return checkId.startsWith(pattern.slice(0, -1));
    }
    return checkId === pattern;
  });
}

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB max file size to prevent memory exhaustion
const MAX_LINE_LENGTH = 10000; // 10KB max line length for regex safety

/**
 * Shell-escape a string for safe interpolation into advisory fix commands.
 *
 * #328 — an alias for the one implementation in `src/ui/shell-quote.ts`. Two
 * copies of this function lived in this file under two names, which is how the
 * report that most needed it ended up with neither.
 */
const shellEscape = shellQuote;

/**
 * `rm <path>` for a file this scanner wants removed, quoted (#273).
 *
 * These `fix:` strings are DATA — built here, rendered from `src/cli.ts` much
 * later as `f.fix` — so the source gate, which follows taint one level inside a
 * single file, never saw them. Unquoted, a skill at `.claude/skills/my
 * skill$(id)/SKILL.md` produced `rm .claude/skills/my skill$(id)/SKILL.md`:
 * three arguments, one of them a live command substitution, on a command whose
 * whole job is deletion.
 *
 * When the path cannot be shown truthfully there is no command, per the rule in
 * `shell-quote.ts`: the finding already names the file in its `file` field, and
 * a `rm` naming bytes the reader cannot see deletes the wrong thing. The prose
 * says what to do and why no command came with it.
 */
/**
 * `chmod 600 <files…>` with every operand quoted (#273).
 *
 * A list, so it fails as a list: if any one name cannot be shown truthfully the
 * whole command is withheld, because a `chmod` that silently drops one file
 * reports a remedy it did not offer. The names stay on the finding's
 * `details.files`, which is where the reader gets them.
 */
function chmodFix(files: readonly string[]): string {
  const cited = citationPaths(files);
  return cited === null
    ? 'Set these files to mode 600. At least one name cannot be shown truthfully in a shell command, so no runnable citation is offered — the full list is on this finding.'
    : `chmod 600 ${cited}`;
}

function removeFileFix(relativePath: string, why: string): string {
  return commandNaming(relativePath, (p) => `rm ${p}`)
    ?? `${why} Remove the file named in this finding. Its name contains characters that cannot be shown truthfully in a shell command, so no runnable citation is offered — delete it from a file manager, or quote the name yourself.`;
}

/**
 * Detect whether a SKILL.md content has any of the malice signals listed in
 * issue #135. A skill that's just missing hygiene metadata (no version, no
 * publisher, no installed_hash) is a hygiene gap — MEDIUM. The same gap on
 * a skill that ALSO has wildcard tools, a credential-shaped env block, an
 * outbound postRunHook, or persistence patterns is a real attack surface
 * that the missing metadata makes harder to govern — HIGH.
 *
 * Used by SKILL-020 (frontmatter hygiene), SUPPLY-001 (publisher), and
 * SUPPLY-004 (installed_hash) to choose default severity. Reserved HIGH
 * means HIGH actually means something.
 */
export function hasSkillMaliceSignals(content: string): boolean {
  // Wildcard allowedTools: '*' or [-"*"] or ["*"]
  if (/^allowedTools:\s*['"]?\*['"]?\s*$/m.test(content)) return true;
  if (/^allowedTools:\s*\n(?:\s*-\s*['"]?\*['"]?\s*\n)/m.test(content)) return true;
  // Wildcard allowedPaths
  if (/^allowedPaths:\s*\n(?:\s*-\s*['"]?\*\*['"]?\s*\n)/m.test(content)) return true;

  // env: block with credential-shaped keys AND credential-shaped values.
  // Key-substring alone (`CACHE_KEY: foo`, `CSRF_TOKEN_HEADER: x-csrf-token`,
  // `JWT_SIGNING_KEY_NAME: prod`) is too noisy — many benign config keys
  // contain `_KEY` / `_TOKEN` / `_SECRET` substrings without storing actual
  // credentials. Mirroring `evidenceShowsCredentialFormat` from #152: require
  // the value to either match a known vendor prefix OR be a high-entropy
  // 20+ char run of credential-shaped chars. Real vendor secrets are
  // 20+ chars; FAKE-shaped corpus credentials are too (e.g. AKIAFAKE0...).
  const envBlockMatch = /^env:\s*\n((?:[ \t]+[A-Z_][A-Z0-9_]*:\s*\S.*\n?)+)/m.exec(content);
  if (envBlockMatch) {
    const envBody = envBlockMatch[1];
    const lines = envBody.split(/\n/);
    for (const line of lines) {
      const m = /^[ \t]+([A-Z_][A-Z0-9_]*):\s*(\S.*?)\s*$/.exec(line);
      if (!m) continue;
      const key = m[1];
      const value = m[2].replace(/^["']|["']$/g, '');
      const keyMatchesCredentialShape =
        /(?:_KEY|_TOKEN|_SECRET|^AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)$|^GITHUB_TOKEN$|^GH_TOKEN$|^OPENAI_API_KEY$|^ANTHROPIC_API_KEY$|^GOOGLE_API_KEY$|^SLACK_(?:BOT_)?TOKEN$|^STRIPE_(?:LIVE_|TEST_)?KEY$)/i.test(
          key,
        );
      if (!keyMatchesCredentialShape) continue;
      const valueLooksCredential =
        /^(?:sk-|sk_live_|sk_test_|ghp_|gho_|github_pat_|xox[abprs]-|eyJ)/.test(value) ||
        /^AKIA[0-9A-Z]{16}/.test(value) ||
        /^AIza[0-9A-Za-z_-]{35}/.test(value) ||
        /^[A-Za-z0-9+=/_]{20,}$/.test(value);
      if (valueLooksCredential) return true;
    }
  }

  // postRunHook: with outbound network primitive (curl/wget/sh/bash piped or invoked with URL)
  if (/^postRunHook:/m.test(content)) {
    const hookSection = content.slice(content.indexOf('postRunHook:'));
    if (/(?:curl|wget|fetch|http|sh|bash|node|python)\s/i.test(hookSection.slice(0, 500)) &&
        /https?:\/\//i.test(hookSection.slice(0, 500))) {
      return true;
    }
  }

  // Persistence patterns in body
  if (/~\/\.(?:bashrc|zshrc|profile|bash_profile)|crontab\s+-|setInterval\s*\(|while\s+true|every\s+\d+\s*(?:min|sec|hour)/i.test(content)) {
    return true;
  }

  return false;
}


/**
 * Heuristic: does a `.env` file body actually contain secret-like values?
 *
 * GIT-003 severity is calibrated by content, not presence (#242). A real
 * exposed secret floors the downstream opena2a composite (CRITICAL); a
 * secret-less `.env` (e.g. `PORT=3000` / `LOG_LEVEL=info`) is only preventive
 * hygiene (HIGH). This is calibration-by-content, NOT detection narrowing — a
 * single real secret still returns true.
 *
 * Calibrated to err toward CRITICAL: a false downgrade (missing a real secret)
 * is worse than a false upgrade, so the value bar is deliberately low for
 * credential-shaped keys. Only values that are clearly non-secret (booleans,
 * numbers, short config strings, template placeholders) are treated as benign.
 */
export function envBodyContainsSecrets(content: string): boolean {
  // 1. Any known vendor credential pattern anywhere in the body → real secret.
  //    CREDENTIAL_PATTERNS are non-global, so `.test` carries no lastIndex state.
  for (const { pattern } of CREDENTIAL_PATTERNS) {
    if (pattern.test(content)) return true;
  }

  // 2. Per-line KEY=VALUE inspection. Two-tier on purpose (#242 adversarial
  //    review): a "strong" value signal is unambiguous and runs regardless of
  //    the key name (so a secret stashed under an innocuous key — `SESSION=eyJ…`,
  //    `X=sk_test_…`, a `user:pass@host` URL — can't evade CRITICAL). A "weak"
  //    opaque-value signal is gated by a credential-shaped key, because an
  //    opaque 8+ char value alone is ambiguous (build hash, cache-buster, DSN
  //    without creds) and counting it everywhere would re-introduce the very
  //    over-rating this issue fixes.
  const lines = content.split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;

    const key = line.slice(0, eq).trim().replace(/^export\s+/i, '');
    let value = line.slice(eq + 1).trim();
    // Strip an inline trailing comment only when the value is unquoted.
    if (!/^["']/.test(value)) value = value.replace(/\s+#.*$/, '').trim();
    // Strip surrounding quotes.
    value = value.replace(/^(["'])(.*)\1$/, '$2').trim();
    if (!value) continue; // empty value = nothing exposed

    // --- Strong, key-independent signals (high precision) ---
    // Recognized vendor key formats and JWTs are unambiguous secrets. Lengths
    // are kept no looser than CREDENTIAL_PATTERNS so a benign identifier that
    // merely starts with `AIza`/`sk-` can't false-match (#242 review F3).
    if (
      /(?:^|[^a-zA-Z0-9])(?:sk-ant-api\d|sk-proj-[a-zA-Z0-9]{16,}|sk-[a-zA-Z0-9]{40,}|sk_live_[a-zA-Z0-9]{16,}|sk_test_[a-zA-Z0-9]{16,}|ghp_[a-zA-Z0-9]{20,}|gh[osru]_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|xox[abprs]-[0-9a-zA-Z-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|SG\.[a-zA-Z0-9_-]{16,})/.test(
        value,
      ) ||
      /^eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]+$/.test(value) // JWT (header.payload.signature)
    ) {
      return true;
    }

    // URL carrying embedded credentials (`scheme://user:pass@host`) — but only
    // when the password is a real literal, not an interpolated `${VAR}` /
    // doc-grade placeholder. A templated DSN provably holds no secret, and
    // flagging it CRITICAL would re-introduce the #242 over-rating (review F1).
    const urlCred = /:\/\/([^/\s:@]+):([^/\s:@]+)@/.exec(value);
    if (urlCred) {
      const userinfo = urlCred[1] + urlCred[2];
      const passLower = urlCred[2].toLowerCase();
      const interpolated = /[${}<>]/.test(userinfo) || /%[a-zA-Z_]+%/.test(userinfo);
      const passIsPlaceholder =
        /(?:^|[-_])your[-_]/.test(passLower) ||
        /^(?:pass|passwd|password|secret|changeme|change_me|placeholder|example|dummy|todo|tbd)$/.test(passLower);
      if (!interpolated && !passIsPlaceholder) return true;
    }

    // --- Weak opaque-value signal, gated by a credential-shaped key ---
    const keyMatchesCredentialShape =
      /(?:_KEY$|_KEY_|_TOKEN|_SECRET|_PASSWORD|_PASSWD|^PASSWORD$|^PASSWD$|^SECRET$|^TOKEN$|^API_?KEY$|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|AUTH_TOKEN|_CREDENTIALS?$)/i.test(
        key,
      );
    if (!keyMatchesCredentialShape) continue;

    // Reject obvious placeholders / template markers (these are .env.example-grade).
    const lower = value.toLowerCase();
    const isPlaceholder =
      /^\$\{/.test(value) || // ${VAR} interpolation reference
      /^<.*>$/.test(value) || // <your-key>
      /\.\.\./.test(value) ||
      /^x{3,}$/i.test(value) ||
      /(?:^|[-_])your[-_]/.test(lower) ||
      /\b(?:changeme|change_me|placeholder|example|dummy|replace[-_ ]?me|todo|tbd|none|null|undefined)\b/.test(
        lower,
      );
    if (isPlaceholder) continue;

    // Reject clearly non-secret value shapes: booleans, env names, log levels,
    // numbers, and credential-less URLs (a URL *with* creds was already caught).
    if (/^(?:true|false|yes|no|on|off|debug|info|warn|error|trace|development|production|staging|test)$/i.test(value)) {
      continue;
    }
    if (/^-?\d+(?:\.\d+)?$/.test(value)) continue; // pure number
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) continue; // bare scheme://host with no creds

    // A substantial opaque value under a credential-shaped key → real secret.
    if (/^[A-Za-z0-9+/=_.\-$]{8,}$/.test(value)) return true;
  }

  return false;
}


/**
 * Check if a variation selector at position i in rawBuffer is a legitimate
 * emoji presentation selector (U+FE0F following an emoji base character).
 *
 * Emoji base characters that commonly precede FE0F:
 * - Keycap digits/symbols: 0-9, #, * (encoded as single ASCII bytes)
 * - BMP symbols: U+2600-27BF range (encoded as 3-byte UTF-8: E2 XX XX or E2 XX XX)
 * - SMP emoji: U+1F300-1FAFF (encoded as 4-byte UTF-8: F0 9F XX XX)
 */
function isEmojiVariationSelector(buf: Buffer, vsStart: number): boolean {
  // Walk backward to find the preceding character
  // The variation selector is at vsStart (3 bytes: EF B8 8F)
  // We need to check what character precedes it

  if (vsStart === 0) return false;

  // Check for 4-byte SMP emoji before (F0 9F XX XX) — most common case
  if (vsStart >= 4) {
    const b0 = buf[vsStart - 4];
    const b1 = buf[vsStart - 3];
    if (b0 === 0xF0 && b1 === 0x9F) return true; // U+1F000-1FFFF (emoji range)
  }

  // Check for 3-byte BMP symbol before (E2 XX XX) — symbols like warning, gear, etc.
  if (vsStart >= 3) {
    const b0 = buf[vsStart - 3];
    const b1 = buf[vsStart - 2];
    if (b0 === 0xE2) {
      // U+2600-27BF: Misc Symbols, Dingbats (E2 98 80 through E2 9E BF)
      if (b1 >= 0x98 && b1 <= 0x9E) return true;
      // U+2300-23FF: Misc Technical (E2 8C 80 through E2 8F BF) — includes hourglass, etc.
      if (b1 >= 0x8C && b1 <= 0x8F) return true;
    }
    // U+2700-27BF also encoded as E2 9C XX - E2 9E XX
    if (b0 === 0xE2 && b1 >= 0x9C && b1 <= 0x9E) return true;
  }

  // Check for 1-byte ASCII keycap base: #, *, 0-9
  if (vsStart >= 1) {
    const prev = buf[vsStart - 1];
    if (prev === 0x23 || prev === 0x2A) return true; // # or *
    if (prev >= 0x30 && prev <= 0x39) return true;   // 0-9
  }

  return false;
}

/**
 * Check if a Cyrillic character at position ci in chars[] is in a Cyrillic
 * text context (legitimate i18n) rather than mixed into a Latin word (attack).
 *
 * Looks at a window of nearby characters. If the neighborhood contains
 * mostly Cyrillic or other non-Latin chars, it's i18n. If surrounded by
 * Latin chars, it's a homoglyph attack.
 */
function isCyrillicInCyrillicContext(chars: string[], ci: number): boolean {
  // Look at a window of 10 chars in each direction
  const windowSize = 10;
  const start = Math.max(0, ci - windowSize);
  const end = Math.min(chars.length, ci + windowSize + 1);

  let latinCount = 0;
  let cyrillicCount = 0;

  for (let j = start; j < end; j++) {
    if (j === ci) continue;
    const cp = chars[j].codePointAt(0)!;
    // Latin letter
    if ((cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A)) {
      latinCount++;
    }
    // Any Cyrillic (U+0400-052F)
    if (cp >= 0x0400 && cp <= 0x052F) {
      cyrillicCount++;
    }
  }

  // If there are at least 3 other Cyrillic chars nearby, this is i18n text
  // (translations, i18n badges, etc. always have multiple Cyrillic chars together)
  if (cyrillicCount >= 3) return true;

  // If the immediate neighbors are both Latin, this is a homoglyph attack
  const prevLatin = ci > 0 && (() => {
    const cp = chars[ci - 1].codePointAt(0)!;
    return (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A);
  })();
  const nextLatin = ci < chars.length - 1 && (() => {
    const cp = chars[ci + 1].codePointAt(0)!;
    return (cp >= 0x41 && cp <= 0x5A) || (cp >= 0x61 && cp <= 0x7A);
  })();

  if (prevLatin && nextLatin) return false; // Sandwiched in Latin = attack

  // Ambiguous case: not enough context. If there are ANY other Cyrillic
  // chars nearby, give benefit of the doubt (i18n).
  return cyrillicCount > 0;
}

/**
 * The identity of a just-created backup directory, or the right refusal.
 *
 * #347.3 — this used to be `identityOrUndefined(...)` followed by `if (!ident)`,
 * which collapses the three-valued probe back into two and throws away exactly
 * the distinction #333 added it for. An EACCES, ELOOP or EIO on the directory
 * `mkdir` had just returned was reported as `HMA-BACKUP-VANISHED — disappeared
 * immediately after being created`, a claim about the filesystem that only
 * ENOENT supports, sending the user to look for a race that is not there.
 *
 * A named function rather than three lines inline, because the window between
 * `mkdir` and `stat` is not something a test can hold open: the decision is
 * observable here, and observing it is the point.
 */
export function backupIdentityOrThrow(probe: IdentityProbe, backupDir: string): FsIdentity {
  if (probe.kind === 'identity') return probe.id;
  if (probe.kind === 'absent') {
    throw backupSetupError(
      'HMA-BACKUP-VANISHED',
      `Backup directory ${backupDir} disappeared immediately after being created.`,
    );
  }
  throw backupSetupError(
    'HMA-BACKUP-UNIDENTIFIED',
    `Backup directory ${backupDir} was created, but the filesystem would not describe it, `
    + 'so HackMyAgent cannot tell its own backup apart from the files it is about to fix.',
  );
}

/**
 * The ordering field of a backup directory name: exactly three characters,
 * always.
 *
 * #347.6 — `createRunBackupDir` added `attempt` (up to 7) to a sequence already
 * capped at 998 and then padded, so a 999th same-millisecond sibling produced a
 * FOUR-character field, breaking both the sort invariant the name exists for and
 * the three-character parse that reads it back. `nextStampSequence` keeps its own
 * cap; what was missing is a clamp AFTER the addition, which is the only place
 * that holds.
 *
 * Exported so the invariant can be asserted against THIS expression rather than
 * against a copy of it in a test — the whole width range is unreachable through
 * `createRunBackupDir`, which needs 999 directories in one millisecond plus two
 * `EEXIST` collisions on an unpredictable component.
 */
export function stampSequenceField(seq: number, attempt: number): string {
  return String(Math.min(seq + attempt, 999)).padStart(3, '0');
}

/**
 * SHELL-EXFIL-001 helpers — deterministic credential-file exfiltration in
 * shell scripts. Modeled on `checkInstallScripts` (INSTALL-001), scoped by the
 * CSR ruling of 2026-08-24 to the credential-file-upload shape so it does not
 * overlap INSTALL-001's `curl … | sh` download-execute surface.
 *
 * The signal is a remote `curl`/`wget` that READS a known credential file into
 * the request body — not the HTTP verb. A bare `@file` POST of a non-credential
 * payload does not fire; the credential-file allowlist is the discriminator.
 */

/**
 * Path suffixes that identify a home-directory credential file. Matched
 * home-prefix-agnostically: `~/.aws/credentials`, `$HOME/.aws/credentials`,
 * `/root/.aws/credentials` and `/home/u/.aws/credentials` all end in
 * `/.aws/credentials`. SSH public keys (`id_rsa.pub`) do not end in these
 * suffixes and so never match.
 */
const SHELL_EXFIL_HOME_CRED_SUFFIXES = [
  '/.aws/credentials',
  '/.ssh/id_rsa',
  '/.ssh/id_ed25519',
  '/.ssh/id_ecdsa',
  '/.ssh/id_dsa',
  '/.docker/config.json',
  '/.kube/config',
  '/.netrc',
  '/.git-credentials',
  '/.npmrc',
];

/** Any file under the gcloud config dir is credential material. */
const SHELL_EXFIL_GCLOUD_DIR = '/.config/gcloud/';

/** Credential files matched by basename (project-local or home). */
const SHELL_EXFIL_BARE_CRED_NAMES = new Set([
  '.npmrc',
  '.netrc',
  '.git-credentials',
]);

/** `.env.example` and friends are placeholder templates, not secrets. */
const SHELL_EXFIL_ENV_TEMPLATE_TOKENS = new Set(['example', 'sample', 'template', 'dist']);

/**
 * True when `rawPath` names a known credential file. Home-prefix-agnostic:
 * `~`, `$HOME`, `${HOME}` and absolute home paths are all treated as the same
 * suffix. `.env`/`.env.*` match by basename but exclude template placeholders.
 */
export function isCredentialFilePath(rawPath: string): boolean {
  const p = rawPath.trim().replace(/^['"]/, '').replace(/['"]$/, '');
  if (!p) return false;

  // Home-anchored credential files: normalise a leading ~ / $HOME / ${HOME} to
  // a bare `/…` so the suffix comparison is prefix-agnostic, then also test the
  // raw path so an absolute `/root/.aws/credentials` still matches.
  const norm = p
    .replace(/^~(?=\/)/, '')
    .replace(/^\$\{HOME\}(?=\/)/, '')
    .replace(/^\$HOME(?=\/)/, '');
  for (const suf of SHELL_EXFIL_HOME_CRED_SUFFIXES) {
    if (norm.endsWith(suf) || p.endsWith(suf)) return true;
  }
  if (p.includes(SHELL_EXFIL_GCLOUD_DIR)) return true;

  // Basename-matched credential files.
  const base = (p.split('/').pop() || '');
  if (base === '.env') return true;
  if (base.startsWith('.env.')) {
    // A real dotenv file (.env.production) is a secret; a template is not. Scan
    // every dot-segment after `.env.`, not just the final extension, so a
    // template backup like `.env.example.bak` is still recognised as a template.
    const segments = base.slice('.env.'.length).split('.');
    return !segments.some(s => SHELL_EXFIL_ENV_TEMPLATE_TOKENS.has(s));
  }
  return SHELL_EXFIL_BARE_CRED_NAMES.has(base);
}

/**
 * Upload tokens that make curl/wget READ a local file into the request body.
 * Each captures the file path (group 1). Modelled on how curl actually decides
 * to read a file, verified against curl 8.7.1:
 *
 *  - Plain data flags (`-d`/`--data`/`--data-binary`/`--data-ascii`) read a file
 *    ONLY when the value BEGINS with `@`. A `name=` prefix (`-d name=@f`) is sent
 *    literally — no read — so these patterns require a value-initial `@`. Long
 *    flags take a space or `=` separator; short `-d` takes a space or is glued
 *    (`-d@f`), never `-d=` (that `=` is part of the value curl sends literally).
 *  - `--data-urlencode` reads on `@f` or `name@f` (an optional name then `@`), but
 *    NOT `name=@f`; the name segment excludes `=`, so the `=@` form cannot match.
 *  - Form flags (`-F`/`--form`) DO read `name=@f`, so they keep the field prefix.
 *  - `-T`/`--upload-file` take a bare path (no `@`).
 *
 * `--data-raw` is excluded structurally: curl passes its `@` through literally,
 * and because the separator must follow the flag NAME, `--data-raw` never
 * satisfies `--data(?:\s+|=)` — the `-raw` is neither a space nor `=`. Short-flag
 * patterns are anchored with `(?:^|\s)` so `-d` does not match inside a token.
 *
 * Every class is a linear regex: an optional name segment then a mandatory `@`
 * (excluded from that segment's class, so no ambiguous overlap) then `[^\s'"]+`.
 */
const SHELL_EXFIL_UPLOAD_PATTERNS: RegExp[] = [
  // curl plain data flags, value-initial @ (long: space or '='; -d handled below).
  /(?:--data-binary|--data-ascii|--data)(?:\s+|=)['"]?@([^\s'"]+)/g,
  // curl -d: space-separated or glued, value-initial @.
  /(?:^|\s)-d\s*['"]?@([^\s'"]+)/g,
  // curl --data-urlencode: @file or name@file (name excludes '=', so name=@ is out).
  /--data-urlencode(?:\s+|=)['"]?[^\s'"@=]*@([^\s'"]+)/g,
  // curl form upload: --form name=@file (the file IS read here).
  /--form(?:\s+|=)['"]?[^\s'"@]*@([^\s'"]+)/g,
  // curl -F name=@file, name possibly glued (`-Ffile=@f`).
  /(?:^|\s)-F\s*['"]?[^\s'"@]*@([^\s'"]+)/g,
  // curl file upload by path (no @): --upload-file file.
  /--upload-file(?:\s+|=)['"]?@?([^\s'"=]+)/g,
  // curl -T file, path possibly glued (`-T~/.ssh/id_rsa`).
  /(?:^|\s)-T\s*['"]?@?([^\s'"=]+)/g,
  // wget --post-file / --body-file (space or `=`).
  /--(?:post-file|body-file)(?:\s*=|\s+)['"]?([^\s'"]+)/g,
];

/** A literal remote URL in the same command is required (item-7 conjunct 4). */
const SHELL_EXFIL_URL = /\b(?:https?|ftps?):\/\/[^\s'"]+/;

/**
 * Detects a single shell command that exfiltrates a credential file to a remote
 * endpoint. Returns the matched credential path and destination URL, or null.
 * Four conjuncts on one line: (1) curl/wget invocation, (2) a file-reading
 * upload token, (3) the read path is a credential file, (4) a literal remote URL.
 */
export function detectShellCredentialExfil(
  line: string,
): { credPath: string; url: string } | null {
  if (!/\b(?:curl|wget)\b/.test(line)) return null;
  const urlMatch = line.match(SHELL_EXFIL_URL);
  if (!urlMatch) return null;
  for (const pattern of SHELL_EXFIL_UPLOAD_PATTERNS) {
    // Every match on the line, not just the first: a benign `@payload.json`
    // before a real `@~/.aws/credentials` must not mask the credential.
    for (const m of line.matchAll(pattern)) {
      if (isCredentialFilePath(m[1])) {
        return { credPath: m[1], url: urlMatch[0] };
      }
    }
  }
  return null;
}

export class HardeningScanner {
  private cliName = 'hackmyagent';
  /**
   * Coverage ledger for the current `scan()`. Replaced per run.
   *
   * Initialised to a ledger rooted at a path nothing resolves inside, so a
   * check invoked outside `scan()` records against a throwaway rather than
   * crashing or, worse, banking evidence onto the previous run's ledger.
   */
  private coverage: CoverageLedger = new CoverageLedger(path.join(path.sep, 'hackmyagent-no-active-scan'));
  /** Fix writes that did not land this run. Reset per `scan()`. */
  private fixWriteFailures: { file: string; code: string; message: string }[] = [];
  /**
   * Fix writes that landed inside a directory named like a backup archive but
   * belonging to a DIFFERENT tree. Reset per `scan()`.
   *
   * Not a failure — the write is recoverable through this run's own backup. It
   * is a fact the other tree's owner has to be told, because their `rollback`
   * no longer restores what they expect.
   */
  private fixWritesIntoForeignArchive: string[] = [];
  /**
   * Every path a fix write actually landed on this run. Reset per `scan()`.
   *
   * `recordCreatedFiles` used to derive its candidates from the findings —
   * `f.fixed && f.file` — which silently assumes every file a fix writes is
   * named by some finding. `.env.example` is written by the `CRED-001` fix
   * while that finding's `file` names the config it EDITED, so the generated
   * file reached no candidate list, `rollback` never removed it, and the
   * report still claimed completeness. Tracking the writes themselves does
   * not depend on finding attribution, so a fix with no owning finding cannot
   * fall through the same gap again.
   */
  private fixWritePaths: string[] = [];
  /**
   * Backup context for the current `--fix` run, or undefined when no backup
   * was taken (detect-only, dry-run, or a `createBackup` failure that already
   * downgraded the run). `applyFixWrite` refuses to write without it — see
   * `ensureBackupCovers`.
   */
  private backupContext: {
    backupDir: string;
    /**
     * The backup directory's `dev`+`ino`. Carried separately from the path
     * because the path is what four rounds of attackers respelled (#317).
     */
    backupIdent: FsIdentity;
    targetDir: string;
    covered: Set<string>;
  } | undefined;
  /**
   * The backup directory a given tree uses, resolved on first ask (#341).
   *
   * Keyed by the scanned directory and resolved LAZILY rather than seeded by
   * `scan()`. A guard whose state some other method has to remember to
   * initialise is a guard that is off whenever a caller forgets — and this one
   * decides whether a write can destroy a backup. Asking for it is what
   * resolves it.
   *
   * Not derived from the backup CONTEXT either: a detect-only run has no
   * context and still has to answer "is this file inside a backup archive" the
   * same way, or `secure` and `secure --fix` disagree about the same file.
   */
  private archiveBases = new Map<string, ArchiveBase>();
  /** Per-directory memo for `isInsideArchiveBase`. Reset per `scan()`. */
  private archiveDirAnswers = new Map<string, 'yes' | 'no' | 'unknown'>();
  /** Per-directory memo for `resolvesToANestedArchive`. Reset per `scan()`. */
  private nestedArchiveDirs = new Map<string, boolean>();
  /**
   * Target-relative paths the last `createBackup` already accounted for, in
   * either manifest list. Seeds `backupContext.covered` so the static
   * candidates are not re-copied one at a time.
   */
  private lastBackupCovered: string[] = [];
  /** Identity of the directory the last `createBackup` created. See #317. */
  private lastBackupIdent: FsIdentity | undefined;
  // Files that may be created or modified during auto-fix
  private static readonly BACKUP_FILES = [
    'config.json',
    'config.yaml',
    'config.yml',
    'mcp.json',
    'settings.json',
    '.env',
    '.env.local',
    '.gitignore',
    '.env.example',
    '.cursor/mcp.json',
    '.vscode/mcp.json',
    '.claude/settings.json',
    'package.json',
    'openclaw.json',
    'moltbot.json',
    // Governance artifacts. `secure --fix` runs harden-soul, which either
    // creates the governance file or appends sections to an existing one;
    // without them here, an existing one was modified with no backup to restore
    // from and a generated one was never tracked for removal (#262).
    //
    // #271 — DERIVED, not hand-copied. This list carried `SOUL.md` and
    // `CLAUDE.md` while `hardenSoul` targets whatever `findGovernanceFile()`
    // returns from `GOVERNANCE_FILES`, so the other eight were modified with no
    // manifest entry. Measured on merged main: `.cursorrules` 113 -> 19055
    // bytes, absent from the manifest, `rollback` printing `[+] Rollback
    // complete` at exit 0. A second constant that must track the first forever
    // is the defect, so there is one list and both sides read it.
    ...GOVERNANCE_FILES,
    // AI infrastructure files (research gap checks)
    'docker-compose.yml',
    'docker-compose.yaml',
    'compose.yml',
    'compose.yaml',
    'Dockerfile',
    'jupyter_notebook_config.py',
    'jupyter_server_config.py',
    '.well-known/agent.json',
    '.well-known/mcp.json',
  ];

  /**
   * Validate that a file path is within the target directory (no path traversal)
   */
  private isPathWithinDirectory(filePath: string, directory: string): boolean {
    return containIsPathWithinDirectory(filePath, directory);
  }

  /**
   * Load .hmaignore file from target directory.
   * Returns path patterns (plain lines) and check ID suppression patterns (lines starting with !).
   */
  private async loadHmaIgnore(targetDir: string): Promise<{ paths: string[]; checkIds: string[] }> {
    const ignorePath = path.join(targetDir, '.hmaignore');
    try {
      const content = await fs.readFile(ignorePath, 'utf-8');
      const lines = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      const paths: string[] = [];
      const checkIds: string[] = [];
      for (const line of lines) {
        if (line.startsWith('!')) {
          // Check ID suppression pattern: strip the ! prefix, store uppercase
          checkIds.push(line.slice(1).toUpperCase());
        } else {
          paths.push(line);
        }
      }
      return { paths, checkIds };
    } catch {
      return { paths: [], checkIds: [] };
    }
  }

  /**
   * Check if a check ID matches any suppression pattern from .hmaignore.
   * Supports exact match and wildcard (*) at the end (e.g. SANDBOX-* matches SANDBOX-001).
   */
  private isCheckIdSuppressed(checkId: string, patterns: string[]): boolean {
    if (patterns.length === 0) return false;
    const upper = checkId.toUpperCase();
    return patterns.some(pattern => {
      if (pattern.includes('*')) {
        // Convert glob pattern to regex: escape special chars, replace * with .*
        const regexStr = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
        return new RegExp(regexStr).test(upper);
      }
      return upper === pattern;
    });
  }

  /**
   * Re-apply .hmaignore filters to a set of findings.
   * Call this after NanoMind merge overwrites result.findings with unfiltered data.
   *
   * `projectType` is required, not optional, and that is deliberate (#457). It
   * only feeds `isReportableFinding`, so a caller that omitted it would still
   * compile, still run, and still record unreportable findings as suppressed —
   * the defect this parameter exists to close, restored silently. Making it
   * required turns every un-migrated call site into a compile error instead.
   */
  /**
   * GENERIC over the finding type, deliberately. Every return is `findings`
   * itself or a filter of it — this method marks and removes, and never
   * constructs a finding — so whatever the caller passed in comes back out.
   *
   * Typing it on `SecurityFindingDraft` instead would force the CLI to cast at
   * `cli.ts:4703`/`:4720`, where the post-merge report is re-derived into
   * `ScanResult.findings`. That cast would launder the `RedactedFinding` brand
   * at the one point downstream of the boundary that rebuilds both channels —
   * exactly the "a site that satisfies the type by casting" case the runtime
   * `redactionStatus` field exists to catch, except silent. Preserving the type
   * parameter keeps the brand intact through the re-filter and makes the casts
   * unnecessary rather than load-bearing.
   */
  async reapplyIgnoreFilters<T extends SecurityFindingDraft>(
    findings: T[],
    targetDir: string,
    projectType: ProjectType,
    additionalIgnorePaths?: string[],
  ): Promise<T[]> {
    const hmaIgnore = await this.loadHmaIgnore(targetDir);
    const allIgnoredPaths = [...hmaIgnore.paths, ...(additionalIgnorePaths || [])];
    const suppressedCheckPatterns = hmaIgnore.checkIds;

    // Reset FIRST, and on the no-op path too: a reused scanner instance must not
    // let the previous target's scope narrowing be disclosed against this one.
    this.lastOutOfScope = [];
    this.lastSuppressed = [];

    if (allIgnoredPaths.length === 0 && suppressedCheckPatterns.length === 0) {
      return findings;
    }

    // #450 — the same split `scanInner` makes, for the same reasons. A check-ID
    // rule is MARKED and kept, because this runs after the NanoMind merge on the
    // very array the CLI recomputes the score from, so returning a shortened
    // array re-created the laundering the scan path had just stopped doing. A
    // path rule is a scope change and leaves the array, with the summary parked
    // on `lastOutOfScope` for the caller to disclose. Callers render with
    // `isDisplayed()`.
    const pathExcluded: T[] = [];
    const checkSuppressed: T[] = [];
    for (const f of findings) {
      // Already out of scope from the scan pass. It must be re-collected, not
      // skipped: `nmResult.mergedFindings` is rebuilt from `allFindings`, which
      // holds the SAME objects `scanInner` marked, so an early `continue` here
      // let every path-excluded finding ride back into the scored array. That
      // put HMA's own 65 excluded fixture findings on both the `Scope` line and
      // the `Suppressed` line while still scoring them 0/100 — the marking was
      // idempotent, the filtering was not.
      if (f.suppressedBy === 'hmaignore-path') { pathExcluded.push(f); continue; }
      if (f.suppressed) { checkSuppressed.push(f); continue; }
      if (this.isCheckIdSuppressed(f.checkId, suppressedCheckPatterns)) {
        f.suppressed = true;
        f.suppressedBy = 'hmaignore-check';
        checkSuppressed.push(f);
      } else if (!this.retainAfterPathSuppression(f, allIgnoredPaths)) {
        // #280 — keys on every covered path, not just `f.file`.
        f.suppressed = true;
        f.suppressedBy = 'hmaignore-path';
        pathExcluded.push(f);
      }
    }
    // #457 — the DISCLOSURE is gated on what would have been reported; the
    // REMOVAL below is not. Two different questions, and conflating them is what
    // the defect was.
    //
    // A suppression can only ever subtract from the report. `scanInner` settles
    // that by filtering to the reportable set BEFORE it splits suppressed from
    // kept (see the `filteredFindings` filter and the loop under it); this
    // method runs on a post-merge array and never did, so a pathless finding —
    // one the user was never going to see, and which scores nothing when left
    // alone — was recorded as suppressed, and #450 adds a suppressed finding's
    // penalty back at every gate. Measured on a bare `mcp` project: a one-line
    // `.hmaignore` reading `!SANDBOX-002` moved it from 98/100 exit 0 to
    // 69/100 exit 1. Suppression INVENTED the penalty, which is #450's own
    // defect in mirror image and would have taught users that asking for a
    // quieter report costs score.
    //
    // The removal is deliberately left alone. Narrowing it too would push
    // unreportable findings back into the returned array, and the one caller
    // that does not re-filter (`secure-openclaw`, `cli.ts`) would start listing
    // and scoring them — trading this defect for a new one on another path.
    const reportable = (f: SecurityFindingDraft) => isReportableFinding(f, projectType);
    this.lastOutOfScope = summarizeSuppressed(pathExcluded.filter(reportable));
    this.lastSuppressed = summarizeSuppressed(checkSuppressed.filter(reportable));
    if (pathExcluded.length === 0 && checkSuppressed.length === 0) return findings;
    const removed = new Set([...pathExcluded, ...checkSuppressed]);
    return findings.filter((f) => !removed.has(f));
  }

  /**
   * Scope narrowing from the most recent `reapplyIgnoreFilters` call, so the
   * caller can disclose it (#450). Identity only — see `summarizeSuppressed`.
   *
   * Per-call, and reset on every call including the no-op one, so a reused
   * scanner instance cannot let one target's `.hmaignore` describe the next
   * target's scan.
   */
  lastOutOfScope: ReturnType<typeof summarizeSuppressed> = [];

  /**
   * Check IDs an `.hmaignore` `!CHECK-ID` rule suppressed in the most recent
   * `reapplyIgnoreFilters` call (#450). Their penalties must be added back at
   * every score and gate the caller derives afterwards.
   */
  lastSuppressed: ReturnType<typeof summarizeSuppressed> = [];

  /**
   * Every path a finding speaks for.
   *
   * `details.files`: checks like GIT-001 and PERM-001 point `file` at one
   * representative path and carry the rest of the evidence in
   * `details.files`, so reading either side alone loses paths.
   */
  private coveredFilesOf(f: SecurityFindingDraft): string[] {
    const listed = Array.isArray(f.details?.files) ? f.details.files : [];
    return [...new Set(
      [f.file, ...listed].filter(
        (p): p is string => typeof p === 'string' && p.length > 0,
      ),
    )];
  }

  /**
   * #280 — decide whether `.hmaignore` should suppress a finding, keying on
   * ALL the paths it covers rather than on `f.file` alone.
   *
   * The old predicate was `f.file && isPathIgnored(f.file, ignored)`. Because
   * PERM-001's `file` is just `permissionIssues[0]`, ignoring that one path
   * deleted the whole finding — including the still-world-readable `.env`
   * listed in `details.files` — and RAISED the score. Measured on a fixture
   * with `.env` and `secrets.json` both 0644: ignoring `secrets.json` moved
   * 44 -> 49 and PERM-001 vanished while `.env` stayed `-rw-r--r--`. A
   * suppression rule that improves the score while the hazard is untouched
   * is the same class of defect as a failed fix raising it.
   *
   * Now: suppress only when EVERY covered path is ignored. Otherwise keep the
   * finding and re-point it onto a surviving path, so the report never names
   * a file the user asked not to hear about while still reporting the ones
   * they did.
   *
   * Returns true to KEEP. May re-point `f.file` / `f.details.files` in place.
   */
  private retainAfterPathSuppression(f: SecurityFindingDraft, ignoredPaths: string[]): boolean {
    // A coverage statement is not a finding ABOUT a path's contents, so a path
    // rule cannot scope it away (#438).
    //
    // `test-fixtures/` in an `.hmaignore` means "this part of the tree is not my
    // product", which honestly removes findings about what is IN those files.
    // It cannot make the scan's own claim about what it READ true. And the
    // paragraph above is explicit that scoping is legitimate *provided the scope
    // is disclosed* — for this finding that proviso does not hold: `outOfScope`
    // is rendered as a bare count on text and `--json`, and NOT AT ALL on sarif,
    // asff and html. Letting a path rule clear this gate therefore produced
    // exit 0 with nothing said on three of the five channels, on the channels a
    // CI consumer reads. Measured, and it is the exact failure this unit exists
    // to remove.
    //
    // So it stays visible and stays in the exit code. The remedy is to make the
    // file readable or to scan a narrower target — not to declare the unread
    // file out of scope. If `outOfScope` ever renders on every channel, this
    // carve-out is the thing to revisit.
    if (f.checkId === 'SCAN-UNREAD-001') return true;

    const covered = this.coveredFilesOf(f);
    // Nothing path-shaped to judge — a finding about the tree as a whole.
    if (covered.length === 0) return true;

    const survivors = covered.filter((p) => !this.isPathIgnored(p, ignoredPaths));
    if (survivors.length === 0) return false;
    if (survivors.length === covered.length) return true;

    // Partially ignored: keep it, but stop naming suppressed paths.
    if (f.file && this.isPathIgnored(f.file, ignoredPaths)) {
      f.file = survivors[0];
    }
    if (Array.isArray(f.details?.files)) {
      (f.details as { files: string[] }).files = survivors;
    }
    return true;
  }

  /**
   * Check if a file path matches any .hmaignore pattern.
   */
  /** Every unreadable input this run recorded, before scope filtering. */
  private unreadableAll: { path: string; code: string; kind: 'file' | 'directory'; rel: string; obstructedBy?: string }[] = [];

  /**
   * For a permission-denied read, the shallowest ancestor inside the target
   * that this process cannot ENTER. `chmod 600 <dir>` is listable and not
   * traversable, so every `stat`/`open` on its children fails with `EACCES`
   * whatever the children's own modes are (#515) — and the remedy the finding
   * used to print, `chmod u+r <file>`, fails with the same `EACCES` the scan
   * did. The remedy belongs on the directory.
   *
   * Shallowest, because a deeper directory cannot even be inspected until the
   * one above it is searchable; naming it is the one step the user can take
   * now. For a file a walker LISTED, only its parent can be unsearchable (the
   * listing itself needed every directory above the parent); the walk matters
   * for fixed-path probes, which reach several levels down without listing.
   * Returns the path relative to the target, or undefined when every ancestor
   * is searchable (the file itself is the obstruction). The target root is
   * probed last and named `.` (#588): a root that lists but cannot be entered
   * loses every path beneath it, and a walk that stopped strictly inside the
   * target left each child with a per-file remedy that fails.
   *
   * `access(X_OK)` is an inspection of a path already known to exist, not a
   * discovery read: a rejection here is the probe's answer, and the tracked
   * namespace deliberately reports nothing for it.
   *
   * Bounds are mirrored by the module-level `unsearchableAncestorSync` (the
   * finding builder's fallback for a caller that passes the raw ledger
   * record); change the two together.
   */
  private async unsearchableAncestor(absPath: string, targetDir: string): Promise<string | undefined> {
    const root = path.resolve(targetDir);
    let dir = path.dirname(absPath);
    let shallowest: string | undefined;
    while (dir.startsWith(root + path.sep)) {
      try {
        await fs.access(dir, fs.constants.X_OK);
      } catch {
        shallowest = dir;
      }
      dir = path.dirname(dir);
    }
    // The root last (#588) — see `unsearchableAncestorSync`.
    if (dir === root || path.resolve(absPath) === root) {
      try {
        await fs.access(root, fs.constants.X_OK);
      } catch {
        shallowest = root;
      }
    }
    return shallowest ? (path.relative(targetDir, shallowest) || '.') : undefined;
  }

  /**
   * The `{count, codes}` shape `cli.ts` settles the exit code on, counted over
   * EVERY unread input this run recorded — deliberately not narrowed by an
   * `.hmaignore` path rule.
   *
   * A path rule scopes what is REPORTED about a file's contents; it cannot make
   * an unread file read, and `retainAfterPathSuppression` keeps
   * `SCAN-UNREAD-001` out of path suppression for exactly that reason. So the
   * count, the finding and the exit code are three readings of one unscoped
   * fact (#438, #590). An earlier shape narrowed this number to an in-scope
   * list; that inverted the disclosure — a file the scan could not read AND
   * had scoped out went silent, on the channels where `outOfScope` does not
   * render at all — and was removed. A method named for that shape survived
   * it (#590).
   */
  private allUnreadableInputs(): { count: number; codes: Record<string, number>; directories: number } {
    const codes: Record<string, number> = {};
    let directories = 0;
    for (const u of this.unreadableAll) {
      codes[u.code] = (codes[u.code] ?? 0) + 1;
      if (u.kind === 'directory') directories++;
    }
    return { count: this.unreadableAll.length, codes, directories };
  }

  private isPathIgnored(filePath: string, ignoredPaths: string[]): boolean {
    if (!filePath || ignoredPaths.length === 0) return false;
    const normalized = filePath.replace(/\\/g, '/');
    return ignoredPaths.some(pattern => {
      const normalizedPattern = pattern.replace(/\\/g, '/').replace(/\/$/, '');
      return normalized.startsWith(normalizedPattern + '/') || normalized === normalizedPattern;
    });
  }

  /**
   * Install a fresh coverage ledger for this run, then scan.
   *
   * The ledger is per-run and the install is scoped: a nested scan (the verify
   * pass a `--fix` performs through its own scanner instance) collects onto
   * its own ledger and restores this one on the way out, so neither run banks
   * the other's evidence.
   */
  async scan(options: ScanOptions): Promise<ScanResult> {
    const ledger = new CoverageLedger(options.targetDir);
    this.coverage = ledger;
    // Per-run, like the ledger itself: a reused instance must not inherit the
    // previous scan's unread set.
    this.unreadableAll = [];
    return withActiveLedger(ledger, () => this.scanInner(options));
  }

  private async scanInner(options: ScanOptions): Promise<ScanResult> {
    const { targetDir, autoFix = false, dryRun = false, ignore = [], cliName = 'hackmyagent' } = options;
    this.cliName = cliName;
    // Per-run, so a reused scanner instance cannot report a previous run's
    // failed writes.
    this.fixWriteFailures = [];
    this.fixWritesIntoForeignArchive = [];
    this.fixWritePaths = [];
    // Cleared per run, and only ever set below once a backup actually
    // exists. A reused scanner instance must not let one run's backup
    // authorise the next run's writes (#300).
    this.backupContext = undefined;
    this.archiveDirAnswers = new Map();
    this.archiveBases = new Map();
    this.nestedArchiveDirs = new Map();

    // Resolve effective scan depth — --deep flag implies 'deep' depth
    const scanDepth: ScanDepth = options.scanDepth || (options.deep ? 'deep' : 'standard');
    const isQuick = scanDepth === 'quick';
    const isDeepScan = scanDepth === 'deep';

    // Load .hmaignore for path-based exclusions and check ID suppressions
    const hmaIgnore = await this.loadHmaIgnore(targetDir);
    // Merge with any programmatic ignorePaths
    const allIgnoredPaths = [...hmaIgnore.paths, ...(options.ignorePaths || [])];
    // Check ID suppression patterns from .hmaignore (supports wildcards)
    const suppressedCheckPatterns = hmaIgnore.checkIds;

    // Normalize ignore list to uppercase for case-insensitive matching
    // Merge CLI --ignore flags with .hmaignore !-prefixed check IDs
    const ignoredChecks = new Set(ignore.map((id) => id.toUpperCase()));

    // In dry-run mode, we detect what would be fixed but don't modify anything
    let shouldFix = autoFix && !dryRun;

    // Create backup before auto-fix (not in dry-run mode).
    //
    // Guarded, and a failure degrades the run to a detect-only scan rather
    // than aborting it. `createBackup` mkdirs `.hackmyagent-backup/` and
    // writes a manifest; on a read-only tree — a read-only mount, a container
    // volume, a restricted CI checkout — both throw, and because this call
    // sat unguarded the exception escaped `scan()` before a single check had
    // run. `secure --fix` printed a raw `EACCES` and exited 1 with an empty
    // body under `--format json`, indistinguishable from a crash, on a tree
    // that `secure` alone scans perfectly well.
    //
    // Fixing without a backup is not an option either: every fix write would
    // be unrevertable. So the run keeps its detection and drops its fixes,
    // and says so.
    let backupPath: string | undefined;
    let backupFailure: { code: string; message: string } | undefined;
    if (shouldFix) {
      try {
        backupPath = await this.createBackup(targetDir);
        // Every fix write from here on is gated on this (#300). Seeded with
        // what `createBackup` already copied so the static candidates are not
        // re-copied one at a time.
        //
        // `lastBackupIdent` is set by the same call and is non-undefined
        // whenever it resolves, so a missing identity here means the contract
        // broke; refuse the fix rather than fall back to a path compare (#317).
        if (!this.lastBackupIdent) {
          throw new Error(`Backup at ${backupPath} could not be identified on the filesystem.`);
        }
        this.backupContext = {
          backupDir: backupPath,
          backupIdent: this.lastBackupIdent,
          targetDir,
          covered: new Set(this.lastBackupCovered),
        };
      } catch (err) {
        const e = err as NodeJS.ErrnoException;
        backupFailure = {
          code: e?.code || (err instanceof Error ? err.name : 'UnknownError'),
          message: err instanceof Error ? err.message : String(err),
        };
        shouldFix = false;
      }
    }

    // Track if any fix fails for atomic rollback
    let fixFailed = false;

    // Detect platform and project type
    const platform = await this.detectPlatform(targetDir);
    const projectType = await this.detectProjectType(targetDir);

    // Run all checks
    const findings: SecurityFindingDraft[] = [];

    // Credential exposure checks
    const credFindings = await this.coverage.run('checkCredentialExposure', () => this.checkCredentialExposure(targetDir, shouldFix));
    findings.push(...credFindings);

    // CLAUDE.md specific checks
    const claudeFindings = await this.coverage.run('checkClaudeMd', () => this.checkClaudeMd(targetDir, shouldFix));
    findings.push(...claudeFindings);

    // MCP configuration checks
    const mcpFindings = await this.coverage.run('checkMcpConfig', () => this.checkMcpConfig(targetDir, shouldFix));
    findings.push(...mcpFindings);

    // File permission checks
    const permFindings = await this.coverage.run('checkFilePermissions', () => this.checkFilePermissions(targetDir, shouldFix));
    findings.push(...permFindings);

    // Git security checks (skip for downloaded npm packages — not a source repo)
    if (!options.isNpmPackage) {
      const gitFindings = await this.coverage.run('checkGitSecurity', () => this.checkGitSecurity(targetDir, shouldFix));
      findings.push(...gitFindings);
    } else {
      this.coverage.skip('checkGitSecurity', 'target is a downloaded npm package, not a source repo');
    }

    // Network security checks
    const netFindings = await this.coverage.run('checkNetworkSecurity', () => this.checkNetworkSecurity(targetDir, shouldFix));
    findings.push(...netFindings);

    // --- Standard and Deep checks (skipped in quick mode) ---
    if (!isQuick) {
    // Additional MCP checks
    const mcpAdvFindings = await this.coverage.run('checkMcpAdvanced', () => this.checkMcpAdvanced(targetDir, shouldFix));
    findings.push(...mcpAdvFindings);

    // Claude Code advanced checks
    const claudeAdvFindings = await this.coverage.run('checkClaudeAdvanced', () => this.checkClaudeAdvanced(targetDir, shouldFix));
    findings.push(...claudeAdvFindings);

    // Cursor configuration checks
    const cursorFindings = await this.coverage.run('checkCursorConfig', () => this.checkCursorConfig(targetDir, shouldFix));
    findings.push(...cursorFindings);

    // VSCode configuration checks
    const vscodeFindings = await this.coverage.run('checkVscodeConfig', () => this.checkVscodeConfig(targetDir, shouldFix));
    findings.push(...vscodeFindings);

    // Additional credential checks
    const credAdvFindings = await this.coverage.run('checkCredentialsAdvanced', () => this.checkCredentialsAdvanced(targetDir, shouldFix));
    findings.push(...credAdvFindings);

    // Additional permission checks
    const permAdvFindings = await this.coverage.run('checkPermissionsAdvanced', () => this.checkPermissionsAdvanced(targetDir, shouldFix));
    findings.push(...permAdvFindings);

    // Environment and config checks
    const envFindings = await this.coverage.run('checkEnvironmentSecurity', () => this.checkEnvironmentSecurity(targetDir, shouldFix));
    findings.push(...envFindings);

    // Logging and audit checks
    const logFindings = await this.coverage.run('checkLoggingSecurity', () => this.checkLoggingSecurity(targetDir, shouldFix));
    findings.push(...logFindings);

    // Dependency checks
    const depFindings = await this.coverage.run('checkDependencySecurity', () => this.checkDependencySecurity(targetDir, shouldFix));
    findings.push(...depFindings);

    // Session and auth checks
    const authFindings = await this.coverage.run('checkAuthSecurity', () => this.checkAuthSecurity(targetDir, shouldFix));
    findings.push(...authFindings);

    // Process and runtime checks
    const procFindings = await this.coverage.run('checkProcessSecurity', () => this.checkProcessSecurity(targetDir, shouldFix));
    findings.push(...procFindings);

    // Additional Claude checks
    const claude3Findings = await this.coverage.run('checkClaudeExtended', () => this.checkClaudeExtended(targetDir, shouldFix));
    findings.push(...claude3Findings);

    // Additional MCP checks
    const mcp2Findings = await this.coverage.run('checkMcpExtended', () => this.checkMcpExtended(targetDir, shouldFix));
    findings.push(...mcp2Findings);

    // Additional network checks
    const net2Findings = await this.coverage.run('checkNetworkExtended', () => this.checkNetworkExtended(targetDir, shouldFix));
    findings.push(...net2Findings);

    // Input/output security checks
    const ioFindings = await this.coverage.run('checkIOSecurity', () => this.checkIOSecurity(targetDir, shouldFix));
    findings.push(...ioFindings);

    // API security checks
    const apiFindings = await this.coverage.run('checkAPISecurity', () => this.checkAPISecurity(targetDir, shouldFix));
    findings.push(...apiFindings);

    // Secret management checks
    const secretFindings = await this.coverage.run('checkSecretManagement', () => this.checkSecretManagement(targetDir, shouldFix));
    findings.push(...secretFindings);

    // Prompt injection defense checks
    const promptFindings = await this.coverage.run('checkPromptSecurity', () => this.checkPromptSecurity(targetDir, shouldFix));
    findings.push(...promptFindings);

    // Input validation checks
    const injFindings = await this.coverage.run('checkInputValidation', () => this.checkInputValidation(targetDir, shouldFix));
    findings.push(...injFindings);

    // Rate limiting checks
    const rateFindings = await this.coverage.run('checkRateLimiting', () => this.checkRateLimiting(targetDir, shouldFix));
    findings.push(...rateFindings);

    // Session security checks
    const sessionFindings = await this.coverage.run('checkSessionSecurity', () => this.checkSessionSecurity(targetDir, shouldFix));
    findings.push(...sessionFindings);

    // Encryption checks
    const encryptFindings = await this.coverage.run('checkEncryption', () => this.checkEncryption(targetDir, shouldFix));
    findings.push(...encryptFindings);

    // Audit trail checks
    const auditFindings = await this.coverage.run('checkAuditTrail', () => this.checkAuditTrail(targetDir, shouldFix));
    findings.push(...auditFindings);

    // Sandboxing checks
    const sandboxFindings = await this.coverage.run('checkSandboxing', () => this.checkSandboxing(targetDir, shouldFix));
    findings.push(...sandboxFindings);

    // Tool boundary checks
    const toolFindings = await this.coverage.run('checkToolBoundaries', () => this.checkToolBoundaries(targetDir, shouldFix));
    findings.push(...toolFindings);

    // OpenClaw skill checks
    const skillFindings = await this.coverage.run('checkOpenclawSkills', () => this.checkOpenclawSkills(targetDir, shouldFix));
    findings.push(...skillFindings);

    // OpenClaw heartbeat checks
    const heartbeatFindings = await this.coverage.run('checkOpenclawHeartbeat', () => this.checkOpenclawHeartbeat(targetDir, shouldFix));
    findings.push(...heartbeatFindings);

    // OpenClaw gateway checks
    const gatewayFindings = await this.coverage.run('checkOpenclawGateway', () => this.checkOpenclawGateway(targetDir, shouldFix));
    findings.push(...gatewayFindings);

    // OpenClaw config checks
    const configFindings = await this.coverage.run('checkOpenclawConfig', () => this.checkOpenclawConfig(targetDir, shouldFix));
    findings.push(...configFindings);

    // OpenClaw supply chain checks
    const supplyFindings = await this.coverage.run('checkOpenclawSupplyChain', () => this.checkOpenclawSupplyChain(targetDir, shouldFix));
    findings.push(...supplyFindings);

    // OpenClaw CVE-specific checks
    const cveFindings = await this.coverage.run('checkOpenclawCVE', () => this.checkOpenclawCVE(targetDir, shouldFix));
    findings.push(...cveFindings);

    // Unicode steganography checks (GlassWorm detection)
    const unicodeStegoFindings = await this.coverage.run('checkUnicodeSteganography', () => this.checkUnicodeSteganography(targetDir, shouldFix));
    findings.push(...unicodeStegoFindings);

    // Memory/context poisoning checks
    const memFindings = await this.coverage.run('checkMemoryPoisoning', () => this.checkMemoryPoisoning(targetDir, shouldFix));
    findings.push(...memFindings);

    // RAG poisoning checks
    const ragFindings = await this.coverage.run('checkRAGPoisoning', () => this.checkRAGPoisoning(targetDir, shouldFix));
    findings.push(...ragFindings);

    // Agent identity checks
    const aimFindings = await this.coverage.run('checkAgentIdentity', () => this.checkAgentIdentity(targetDir, shouldFix));
    findings.push(...aimFindings);

    // Agent DNA integrity checks
    const dnaFindings = await this.coverage.run('checkAgentDNA', () => this.checkAgentDNA(targetDir, shouldFix));
    findings.push(...dnaFindings);

    // Skill memory manipulation checks
    const skillMemFindings = await this.coverage.run('checkSkillMemory', () => this.checkSkillMemory(targetDir, shouldFix));
    findings.push(...skillMemFindings);

    // NemoClaw codebase pattern checks
    const nemoFindings = await this.coverage.run('checkNemoClawPatterns', () => this.checkNemoClawPatterns(targetDir, shouldFix));
    findings.push(...nemoFindings);

    // AI infrastructure exposure checks (research gap coverage)
    const llmFindings = await this.coverage.run('checkLLMExposure', () => this.checkLLMExposure(targetDir, shouldFix));
    findings.push(...llmFindings);

    const aiToolFindings = await this.coverage.run('checkAIToolExposure', () => this.checkAIToolExposure(targetDir, shouldFix));
    findings.push(...aiToolFindings);

    const a2aFindings = await this.coverage.run('checkA2AExposure', () => this.checkA2AExposure(targetDir, shouldFix));
    findings.push(...a2aFindings);

    const mcpDiscoveryFindings = await this.coverage.run('checkMCPDiscovery', () => this.checkMCPDiscovery(targetDir, shouldFix));
    findings.push(...mcpDiscoveryFindings);

    const webCredFindings = await this.coverage.run('checkWebServedCredentials', () => this.checkWebServedCredentials(targetDir, shouldFix));
    findings.push(...webCredFindings);

    // Code injection, supply chain, and operational security checks
    // NOTE: CODEINJ-001 removed — deduplicated with NEMO-005 (same detection)

    const installFindings = await this.coverage.run('checkInstallScripts', () => this.checkInstallScripts(targetDir, shouldFix));
    findings.push(...installFindings);

    const shellExfilFindings = await this.coverage.run('checkShellCredentialExfil', () => this.checkShellCredentialExfil(targetDir, shouldFix));
    findings.push(...shellExfilFindings);

    const cliPassFindings = await this.coverage.run('checkCLICredentialPassthrough', () => this.checkCLICredentialPassthrough(targetDir, shouldFix));
    findings.push(...cliPassFindings);

    const integrityFindings = await this.coverage.run('checkIntegrityBypass', () => this.checkIntegrityBypass(targetDir, shouldFix));
    findings.push(...integrityFindings);

    const toctouFindings = await this.coverage.run('checkTOCTOU', () => this.checkTOCTOU(targetDir, shouldFix));
    findings.push(...toctouFindings);

    // NOTE: TMPPATH-001 removed — deduplicated with NEMO-006 (same detection)

    const dockerInjFindings = await this.coverage.run('checkDockerInjection', () => this.checkDockerInjection(targetDir, shouldFix));
    findings.push(...dockerInjFindings);

    // NOTE: ENVLEAK-001 removed — deduplicated with NEMO-007 (same detection)

    const sandboxMsgFindings = await this.coverage.run('checkSandboxMessaging', () => this.checkSandboxMessaging(targetDir, shouldFix));
    findings.push(...sandboxMsgFindings);

    const webExposeFindings = await this.coverage.run('checkWebExposedFiles', () => this.checkWebExposedFiles(targetDir, shouldFix));
    findings.push(...webExposeFindings);

    const soulOverrideFindings = await this.coverage.run('checkSoulOverride', () => this.checkSoulOverride(targetDir, shouldFix));
    findings.push(...soulOverrideFindings);

    const soulGovFindings = await this.coverage.run('checkSoulGovernanceGaps', () => this.checkSoulGovernanceGaps(targetDir));
    findings.push(...soulGovFindings);

    const memSanitizeFindings = await this.coverage.run('checkMemoryStoreSanitization', () => this.checkMemoryStoreSanitization(targetDir, shouldFix));
    findings.push(...memSanitizeFindings);

    const agentCredFindings = await this.coverage.run('checkAgentCredentialProtection', () => this.checkAgentCredentialProtection(targetDir, shouldFix));
    findings.push(...agentCredFindings);

    // Context lifecycle assembly checks (Stage 1)
    const lifecycleFindings = await this.coverage.run('checkContextLifecycle', () => this.checkContextLifecycle(targetDir, options));
    findings.push(...lifecycleFindings);
    } // end of standard/deep checks

    // A quick scan runs 6 of the 61 orchestrated checks. Record the other 55
    // as skipped so their categories report `not examined` with the depth as
    // the reason, instead of inheriting the fail-closed default's vaguer
    // "no check in this category ran".
    if (isQuick) {
      this.coverage.skipUnrun('scan depth is `quick` — standard and deep checks did not run');
    }

    // Layer 2: Structural analysis (standard and deep only)
    let layer2Count = 0;
    let layer3Count = 0;
    let llmCost: number | undefined;
    let cachedResults: number | undefined;
    if (!isQuick) {
    try {
      const structural = new StructuralAnalyzer();
      // #298 — Layer 2 now discovers artifacts below the scan root, and
      // `createBackup` (line ~1827) has already copied `CLAUDE.md`,
      // `config.json` and `.claude/settings.json` into
      // `.hackmyagent-backup/<stamp>/` by the time this runs. Without this
      // predicate a `--fix` run reports every semantic finding twice, once for
      // the live file and once for its own backup. Passed as `isOwnBackupDir`
      // rather than a directory NAME: a name is a suppression token the
      // scanned tree can plant (#305/#309), while the identity check excludes
      // THIS RUN's backup and nothing else.
      const structuralFindings = await structural.analyze(targetDir, {
        isExcludedDir: (dir) => this.isOwnBackupDir(dir),
      });
      const converted = toSecurityFindings(
        structuralFindings,
        (file) => this.readArtifactForCitation(targetDir, file),
      );
      findings.push(...converted);
      layer2Count = converted.length;
    } catch {
      // Structural analysis failure is non-fatal
    }
    }

    // Layer 3: LLM analysis (only in deep mode + API key)
    if ((isDeepScan || options.deep) && process.env.ANTHROPIC_API_KEY) {
      try {
        const structural = new StructuralAnalyzer();
        // Same exclusion as Layer 2 above, and it costs money here: every
        // duplicated backup copy would be a billed LLM call.
        const files = await structural.discoverFiles(targetDir, {
          isExcludedDir: (dir) => this.isOwnBackupDir(dir),
        });
        const llm = new LLMAnalyzer({
          apiKey: process.env.ANTHROPIC_API_KEY,
          onProgress: options.onProgress,
        });
        const llmResult = await llm.analyze(files);
        const converted = toSecurityFindings(
          llmResult.findings,
          (file) => this.readArtifactForCitation(targetDir, file),
        );
        findings.push(...converted);
        layer3Count = converted.length;
        llmCost = llmResult.cost;
        cachedResults = llmResult.cachedResults;

        // #462 — a file Layer 3 could not read an answer for is REPORTED, not
        // counted as examined. The old code returned `[]` for an unparseable
        // response, so a scanned file that made the analyst's answer unreadable
        // scored exactly like a file with nothing in it. Measured: content
        // asking for a bracketed note after the JSON suppressed every finding in
        // 4 trials of 4 while the analyst reported the credentials every time.
        for (const missed of llmResult.unanalyzed) {
          findings.push({
            checkId: 'SEM-LLM-NOT-ANALYZED',
            name: 'Deep analysis did not complete for this file',
            description:
              'Layer 3 sent this file for semantic analysis and did not get back a result it could read, so this file has NOT been analyzed for the credential shapes only Layer 3 detects.',
            category: 'Credential Protection',
            severity: 'medium',
            passed: false,
            message: `${missed.path} was not analyzed: ${missed.reason}. This is a gap in coverage, not a clean result — the checks that did run are unaffected.`,
            fixable: false,
            file: missed.path,
            fix: `Re-run the deep scan: ${this.cliName} secure ${shellQuote(targetDir)} --deep. If it repeats on the same file, the file's own content may be interfering with the analysis; the other layers' findings for it still stand.`,
          } as SecurityFindingDraft);
        }
      } catch {
        // LLM analysis failure is non-fatal — fall back to Layer 2 only
      }
    }

    // Enrich findings with attack taxonomy mapping. Runs after Layer 2/3 so
    // semantic findings whose upstream `SemanticFinding.attackClass` is
    // unset get a default mapping from `TAXONOMY_MAP`. Inline `attackClass:`
    // values on the SemanticFinding take precedence — the helper only sets
    // the field when `getAttackClass()` returns a non-empty value AND the
    // finding does not already carry one.
    enrichWithTaxonomy(findings);

    // A fix write that did not land is now reported, not just absorbed.
    // Revoking the flag alone made the run look like the fix was never
    // attempted: the user saw an ordinary unfixed finding whose remedy was
    // `secure --fix` — the command that had just failed — with no way to tell
    // "not attempted" from "attempted and the filesystem refused". Re-running
    // then loops with no diagnosis. One finding names every file, so the
    // signal cannot be lost among per-check noise.
    if (backupFailure) {
      // The remedy has to match the CAUSE. Every cause used to be described as a
      // permission problem ("make the target writable", "a read-only mount, a
      // container volume, or a checkout owned by another user"), which is simply
      // wrong for a backup base HMA refused on its own: making a symlink writable
      // changes nothing, and the sentence sends the user to look at the wrong
      // thing. `backupSetupError` carries the reason so this can dispatch on it.
      const basePath = path.join(targetDir, BACKUP_DIR_NAME);
      const rerun = `${this.cliName} secure ${shellQuote(targetDir)} --fix`;
      const CAUSES: Record<string, { fix: string; guidance: string }> = {
        'HMA-BACKUP-SYMLINK': {
          fix: `Replace ${shellQuote(basePath)} with a real directory, or remove it, then re-run: ${rerun}`,
          guidance:
            `${BACKUP_DIR_NAME} is a symbolic link. Backups are never written through a link, because `
            + 'the copies would land wherever the link points — outside the directory you asked to '
            + 'scan, and outside what `rollback` can restore from. Nothing was written and nothing '
            + 'was changed. Replace it with a real directory to enable auto-fix.',
        },
        'HMA-BACKUP-NOT-DIR': {
          fix: `Remove or rename ${shellQuote(basePath)}, then re-run: ${rerun}`,
          guidance:
            `Something that is not a directory already occupies ${BACKUP_DIR_NAME}, so there is `
            + 'nowhere to store the copies auto-fix would need. Nothing was written and nothing was '
            + 'changed.',
        },
        'HMA-BACKUP-OUTSIDE-TREE': {
          fix: `Replace ${shellQuote(basePath)} with a real directory inside the project, then re-run: ${rerun}`,
          guidance:
            `${BACKUP_DIR_NAME} resolves to a location outside the directory being scanned. Backups `
            + 'stay inside the tree they belong to, so the run detected only. Nothing was written '
            + 'and nothing was changed.',
        },
        'HMA-BACKUP-NO-NEW-DIR': {
          fix: `Re-run: ${rerun}`,
          guidance:
            'Auto-fix creates a backup directory that must be provably new, and the name it chose '
            + 'was already taken on every attempt. That is transient — re-running takes a fresh '
            + 'name. Nothing was written and nothing was changed.',
        },
      };
      const cause = CAUSES[backupFailure.code ?? ''];
      findings.push({
        checkId: 'FIX-BACKUP-FAILED',
        name: 'Auto-Fix Skipped: Backup Could Not Be Created',
        description: 'No fixes were applied because no backup could be taken',
        category: 'hardening',
        severity: 'medium',
        passed: false,
        // The reason, in words, not just an error code: for a refusal HMA decided
        // on its own the code was `Error`, which told the user nothing.
        message: `Backup failed: ${backupFailure.message} --fix was skipped and this run only `
          + 'detected. Findings below are unmodified.',
        file: path.basename(targetDir),
        fixable: false,
        fix: cause?.fix ?? `Make the target writable, then re-run: ${rerun}`,
        guidance: cause?.guidance
          ?? 'Applying fixes without a backup would leave nothing to roll back to, so the run detects only. Every finding below reflects the tree as it is on disk. This usually means a read-only mount, a container volume, or a checkout owned by another user.',
      });
    }

    if (this.fixWriteFailures.length > 0) {
      // De-duplicated by path: two checks can attempt a write on the same file
      // (SKILL-001 and SKILL-004 both target one SKILL.md), which reported
      // "2 auto-fix writes failed (EPERM): skills/x/SKILL.md, skills/x/SKILL.md".
      const seen = new Set<string>();
      const failed = this.fixWriteFailures
        .map(f => ({ ...f, rel: path.relative(targetDir, f.file) || path.basename(f.file) }))
        .filter(f => (seen.has(f.rel) ? false : (seen.add(f.rel), true)));
      const codes = [...new Set(failed.map(f => f.code))].join(', ');
      findings.push({
        checkId: 'FIX-WRITE-FAILED',
        name: 'Auto-Fix Could Not Be Written',
        description: 'A fix was computed but could not be written to disk',
        category: 'hardening',
        severity: 'medium',
        passed: false,
        // One line per file, carrying the REASON in words (#347.4). The code
        // alone was all that reached the user, and a code is not a sentence: a
        // reader who saw `FIX-WRITE-UNCONTAINED` next to guidance about
        // read-only mounts went looking for a permissions problem that was not
        // there. `resolveFixWriteTarget` already phrases each refusal; this
        // stops it dying inside the scanner.
        message: `${failed.length} auto-fix write${failed.length === 1 ? '' : 's'} failed (${codes}): `
          + failed.map(f => `${f.rel} — ${f.message}`).join('; '),
        file: failed[0].rel,
        fixable: false,
        // The remedy depends on the cause. Making a file writable does nothing
        // for a link that leaves the tree, and telling a user to do it is the
        // dead-end citation the per-finding protocol exists to forbid.
        fix: failed.every(f => f.code.startsWith('FIX-WRITE-'))
          ? `Point the listed path at a file inside the scanned directory, then re-run: ${this.cliName} secure --fix`
          : `Make the file writable, then re-run: ${this.cliName} secure --fix`,
        guidance:
          'The issue these fixes address is still present on disk. Each file above says why its '
          + 'write did not land. A write is refused outright when its destination would leave the '
          + 'scanned directory — a symbolic link pointing outside it is the common case, and '
          + 'following it would modify a file you did not ask HackMyAgent to touch. A write can '
          + 'also fail because the file is read-only or immutable, the filesystem is mounted '
          + 'read-only, the volume is full, or a security policy denies it. Findings for those '
          + 'files are reported as unfixed, so the score reflects the tree as it actually is.',
      });
    }

    // Record what the static fixes actually created, hashed, so rollback can
    // remove those files without guessing (#262). Sourced from the fixed
    // findings' own file attribution rather than "every backup candidate that
    // is absent", which is what made the pre-0.25.1 rollback delete files the
    // user wrote. The governance auto-fix runs after this returns, so the CLI
    // calls recordCreatedFiles again for SOUL.md.
    //
    // Placed ABOVE the semantic pass, and that ordering is a durability rule
    // rather than a preference (#499). The manifest is what `rollback` reads to
    // know which files HMA generated, and the window between "the fix is on
    // disk" and "the manifest says so" is a window in which an interrupt leaves
    // `rollback` reporting `[+] Rollback complete` over a tree it did not
    // restore. That window used to be ~45ms; running the semantic pass first
    // would put a model load and a whole compile set inside it — measured at
    // ~3.4s on a three-file fixture, and it scales with the tree. Both inputs
    // are settled by now (the semantic layer never sets `fixed` and never
    // writes), so nothing is lost by persisting before the pass rather than
    // after it.
    if (shouldFix && backupPath) {
      await this.recordCreatedFiles(
        targetDir,
        backupPath,
        [
          ...findings.filter(f => f.fixed && f.file).map(f => f.file as string),
          // Plus every path a fix actually wrote. `recordCreatedFiles` still
          // records only paths HMA OBSERVED missing — at backup time, or
          // proven absent immediately before the write — and guards each with
          // a sha256, so widening the candidate list cannot make rollback
          // delete a file the user wrote.
          ...this.fixWritePaths,
        ],
      );
    }

    // #499 — the semantic pass runs HERE, inside the ledger's window and ahead
    // of everything that reads the ledger. See `ScanOptions.semanticPass` for
    // why the placement is the fix rather than an optimisation.
    //
    // Deliberately not wrapped in `this.coverage.run(...)`: an empty method
    // stack is what makes the successful reads unattributable and therefore
    // dropped, holding this change to the failure channel. Wrapping it would
    // silently fold every semantic read into `filesExamined` and into whichever
    // category the method registered — the wide change that was considered and
    // rejected.
    if (options.semanticPass) {
      // Deliberately NOT wrapped in try/catch. Before #499 this pass ran as a
      // statement after `scan()` returned, so a throw inside it killed the
      // command outright — loudly. Catching it here because the call moved
      // would convert that crash into a scan that quietly reports a
      // semantic-free result as though it were complete, which is the same
      // false-assurance shape this ledger exists to remove. Relocating the call
      // must not change what a failure costs.
      //
      // `dropPathlessNoiseFloor`, because that is exactly what the caller used
      // to hand the semantic pass: `cli.ts` read `result.allFindings`, and
      // `allFindings` is this filter applied to this array. Passing the raw
      // array instead would quietly widen the merge input, which is the kind of
      // drift that turns a relocation into a behaviour change.
      const mergeInput = dropPathlessNoiseFloor(findings, projectType);
      // What the noise-floor filter removed, kept aside rather than discarded.
      //
      // The merge input has to be the filtered set — that is exactly what the
      // caller used to hand the pass. But `findings` is ALSO the array
      // `unevidencedFailures` is counted from further down (it iterates for
      // `!f.file`), and those pathless records are precisely what the filter
      // drops. Replacing the array with the merge result alone deleted them:
      // measured, `unevidencedFailures` fell 41 -> 0 on ai-trust and 45 -> 1 on
      // secretless, silently removing the one line that tells a reader a
      // "categories clear" report is hiding ~40 checks that failed with nothing
      // to point at (#421). A false-assurance regression of the same class this
      // fix exists to close, caused by the fix. Pre-#499 the pass ran after
      // `scan()` returned, so `findings` still held them.
      const keptForMerge = new Set(mergeInput);
      const noiseFloor = findings.filter((f) => !keptForMerge.has(f));
      const semantic = await options.semanticPass({
        targetDir,
        findings: mergeInput,
        projectType,
      });
      if (semantic?.findings) {
        // Replace rather than append: the semantic pass MERGES (its contract is
        // defense-in-depth — static findings can be upgraded but never
        // suppressed), so it returns the whole set, and appending would
        // duplicate every static finding it was handed.
        findings.length = 0;
        findings.push(...semantic.findings, ...noiseFloor);
      }
    }

    // #438 — inputs the scan found inside the target and could not read.
    //
    // This is the channel the PATHS travel on. The coverage object carries the
    // count and the errno codes and deliberately carries no filenames (a
    // single-file scan normalises its target into a generated temp directory,
    // and emitting read paths put that name into `--json`), so without a
    // finding the user would be told a file was unreadable and never which one
    // — the dead end the per-finding protocol forbids.
    //
    // MEDIUM, not HIGH, and the reasoning is #462's verbatim: an unreadable
    // file is frequently an environment fact rather than an attack, and raising
    // it would turn a permissions quirk into a red pipeline, which is what
    // pushes people to bypass a gate. The verdict channel says the true thing
    // instead — this run did not examine everything it found — through the exit
    // code, which `cli.ts` settles once, above every output channel.
    // Every unreadable path gets a finding, and `retainAfterPathSuppression`
    // keeps that finding OUT of `.hmaignore` path suppression: a path rule
    // scopes what is reported about a file's contents and cannot make an
    // unread file read, and `outOfScope` renders as a bare count on two
    // channels and not at all on three, so scoping it out was "exit 0 with
    // nothing said" on the channels CI reads (#438, #591).
    //
    // Filtering the finding out here instead was the first attempt and it was
    // worse than the defect it fixed: it turned "exit 2 with nothing named" into
    // "exit 0 with nothing said". The disclosure INVERTED — content the scan
    // could read and scoped out was disclosed, content it could NOT read and
    // scoped out was not, so the case carrying less information carried less
    // warning. This repo's own `.hmaignore` scopes `src/hardening/` and
    // `src/nanomind-core/`, so that silence reached real trees.
    //
    // The exit-code unit (`allUnreadableInputs`) is then counted over this same
    // list, unscoped, so the finding, the count and the exit code cannot
    // disagree about a file (#590).
    const unreadable: { path: string; code: string; kind: 'file' | 'directory'; rel: string; obstructedBy?: string }[] = [];
    for (const u of this.coverage.unreadablePaths()) {
      const rel = path.relative(targetDir, u.path) || path.basename(u.path);
      // A permission denial on a file inside a directory this user cannot
      // ENTER is the directory's fault, and the remedy has to say so (#515).
      const permission = u.code === 'EACCES' || u.code === 'EPERM';
      const obstructedBy = permission ? await this.unsearchableAncestor(u.path, targetDir) : undefined;
      unreadable.push({ ...u, rel, ...(obstructedBy ? { obstructedBy } : {}) });
    }
    this.unreadableAll = unreadable;
    for (const u of unreadable) {
      // ONE finding per path, not one naming the first of N — see
      // `buildUnreadInputFinding`, extracted to module scope so the local
      // `check` arm can emit the identical finding through the same
      // errno->remedy logic rather than a second copy (#508 / #494 class).
      findings.push(buildUnreadInputFinding(u, { cliName: this.cliName, targetDir }));
    }

    if (this.fixWritesIntoForeignArchive.length > 0) {
      const rels = [...new Set(this.fixWritesIntoForeignArchive.map(
        (f) => path.relative(targetDir, f) || path.basename(f),
      ))];
      findings.push({
        checkId: 'FIX-FOREIGN-ARCHIVE',
        // Was "Fix Applied Inside Another Project's Backup". Neither this name
        // nor the guidance below may assert that a project is there: what was
        // established is that an ancestor directory IS what
        // `<its parent>/.hackmyagent-backup` resolves to, and a vendored tree
        // carrying that name satisfies that truthfully. Proving a project sits
        // beside it would mean trusting files the scanned tree wrote.
        name: 'Fix Applied Inside a Nested Backup Directory',
        description: `${rels.length} file${rels.length === 1 ? '' : 's'} rewritten inside a nested backup directory`,
        category: 'hardening',
        severity: 'low',
        // `passed: false` so it is SHOWN. A `passed: true` finding is filtered
        // out of the report, which is how the first version of this disclosure
        // managed to exist in the code and appear nowhere on screen — the same
        // failure as putting it in the changelog.
        passed: false,
        message: rels.join(', '),
        file: rels[0],
        fixable: false,
        fix: `${this.cliName} rollback ${citationTarget(targetDir)}`,
        guidance:
          'These files sit under a directory below the one you scanned that resolves to '
          + '`.hackmyagent-backup` — the name HackMyAgent stores a tree\'s backups in. They were '
          + 'rewritten like any other file, and this run copied the originals into its own backup '
          + 'first, so nothing is lost. If that directory IS another project\'s backup archive, '
          + 'running `rollback` inside that project will now restore the rewritten copy rather than '
          + 'the original, and will report success — roll back from the directory you scanned '
          + 'instead. If it is a vendored or copied tree that merely carries the name, no rollback '
          + 'is affected and the rewrite is the ordinary fix.',
      });
    }

    // Verify fixes: re-scan fixed files to confirm issues are actually resolved
    let reportFixVerification = false;
    if (shouldFix) {
      const fixedFindings = findings.filter(f => f.fixed && f.file);
      // #374 — this scan has a second job. It is a context-free scan of the
      // post-fix tree, which makes it the only thing in the run that knows what
      // the user's NEXT scan will score: `backupContext` exists only inside a
      // `--fix` run, so the archive this run created is excluded here and
      // included by every later scan (deliberately — `:4769`). Both numbers came
      // from this run, and they described different trees.
      //
      // So it runs whenever this run left copies in its archive, not only when
      // a fix landed: a `--fix` that repaired nothing still archives its backup
      // candidates up front, and its score still has to be the one that comes
      // back.
      //
      // BE HONEST ABOUT THIS GATE: it does not gate. `covered` is seeded from
      // `existingFiles` PLUS `absentAtBackup` (`:8244`), and `absentAtBackup` is
      // the list of static candidates that do NOT exist, so `covered.size` is 34
      // on an empty directory — the full `BACKUP_FILES.length` — and this is
      // therefore effectively unconditional. (An earlier draft of this comment
      // said "~22", read off a regex that split the list on commas inside its own
      // comments. Measured: 34.) Every
      // `secure --fix` now runs a second full scan, where before it ran one only
      // when a fix had landed. That is a cost regression, not a wrong number, and
      // the honest gate — "did the archive actually receive a copy" — needs
      // `manifest.existingFiles` plumbed onto `backupContext`, which is backup
      // bookkeeping this codebase has broken repeatedly (#300, #313, #327, #329).
      // Not worth doing in a release whose point is that a number is trustworthy.
      // Filed as #381.
      const archiveHoldsCopies = (this.backupContext?.covered.size ?? 0) > 0;
      if (fixedFindings.length > 0 || archiveHoldsCopies) {
        // Re-run a targeted scan (no fix, just detect) to verify.
        //
        // This scan has to be the NEXT SCAN, not merely another scan. Its findings
        // are adopted into this run's score below, so every option that decides
        // which checks run has to come from the run it is standing in for.
        // Building the options fresh here inherited none of them, and the default
        // is `standard`: a `--fix --scan-depth quick` run therefore adopted Layer-2
        // findings from its own archive that `isQuick` (`:2138`) means the user's
        // next quick scan can never report. Measured on a fixture whose archived
        // `.cursor/mcp.json` holds a token: announced rawScore 72, immediate quick
        // rescan 85. That is #374 exactly, through a second door — the displayed
        // score only agreed because the #259 clamp floored both to 69, and `--json`
        // published the contradiction as `rawScore` regardless.
        //
        // `deep` is deliberately NOT threaded, and `scanDepth` is capped below it.
        //
        // Threading it was tried and reverted the same day. Layer 3 (`:2162`) fires
        // on `options.deep` and puts file CONTENT on the wire to the Anthropic API.
        // Its archive exclusion is `isOwnBackupDir`, whose FIRST STATEMENT returns
        // false whenever there is no `backupContext` — and this verify scanner is a
        // fresh instance that has none. So a threaded `deep` walked Layer 3
        // into the archive this run had just written and transmitted the only
        // remaining PLAINTEXT copies of the credentials the same run had redacted
        // out of the live files. Measured: 2 LLM payloads before, 4 after, the two
        // extra ones carrying the token bytes.
        //
        // A `--deep` user consents to their live files being analysed. Re-sending a
        // secret AFTER removing it, out of an artifact presented as a local rollback
        // aid, is a different bargain and was not one this tool disclosed. Cost was
        // never the reason to avoid it; that is.
        //
        // The price is real and is disclosed instead of hidden: on a `--fix --deep`
        // with an API key set, the announced score does not include Layer-3 findings
        // inside the archive, so it can read higher than the next `--deep` scan.
        // Layer 1 and Layer 2 archive findings — every credential detector among
        // them — are still counted, so the number is not the pre-#374 number.
        // Tracked as #386; the transmission hole itself is #385, and a plain
        // `secure --deep` still walks any archive in the tree because of it.
        const verifyDepth: ScanDepth = scanDepth === 'deep' ? 'standard' : scanDepth;
        const verifyScanner = new HardeningScanner();
        const verifyResult = await verifyScanner.scan({
          targetDir,
          autoFix: false,
          ignore: ignoredChecks.size > 0 ? [...ignoredChecks] : [],
          cliName: this.cliName,
          scanDepth: verifyDepth,
          ignorePaths: options.ignorePaths,
          isNpmPackage: options.isNpmPackage,
        });

        // A finding's `file` is one stand-in for what can be a multi-file
        // issue: `PERM-001` reports `permissionIssues[0]`, the head of a
        // fixed-order array. When a fix lands on the head and fails on a
        // later entry, the head SHIFTS between the scan and the re-scan
        // ('secrets.json' -> '.env'), a key built from it stops matching,
        // and a fix that never landed is confirmed (HIGH-3).
        //
        // So compare on every path a finding covers, not just its
        // representative one. The union with `file` matters as much as
        // `details.files`: checks like GIT-001 point `file` at a constant
        // ('.gitignore') and use `details.files` for the evidence that
        // motivated it, so dropping either side can lose the still-failing
        // path. Union on both sides can only make verification stricter,
        // never looser — and under-claiming a repair is the safe direction.
        // Hoisted to `coveredFilesOf` so `.hmaignore` suppression uses the
        // SAME notion of "which paths does this finding speak for" that
        // verification does (#280) — the two disagreeing is what let one
        // ignored path delete a multi-file finding.
        const coveredFiles = (f: SecurityFindingDraft): string[] => this.coveredFilesOf(f);

        // Compare against the verify scan's UNFILTERED findings. Its
        // `findings` has already been through the user-facing filter below,
        // which drops paths matching `.hmaignore` — and it drops on `file`,
        // the very attribution that shifts. So a repo with `.env` in its
        // `.hmaignore` walked the still-failing finding straight out of the
        // list it was being compared against, and the union above confirmed a
        // chmod that never landed: `2/2 fixes confirmed`, 98/100, exit 0,
        // `.env` still 0644. Comparing a raw list against a filtered one is
        // the same asymmetry as comparing on a shifting key, one layer up.
        //
        // Ignoring a path suppresses reporting on it. It does not turn a fix
        // that failed there into a fix that succeeded — HMA still attempted
        // the write.
        const verifyFindings = verifyResult.allFindings ?? verifyResult.findings;

        // checkId -> every path still failing that check after the fix pass.
        const stillFailing = new Map<string, Set<string>>();
        for (const f of verifyFindings) {
          if (f.passed || f.fixed) continue;
          let bucket = stillFailing.get(f.checkId);
          if (!bucket) {
            bucket = new Set<string>();
            stillFailing.set(f.checkId, bucket);
          }
          for (const p of coveredFiles(f)) bucket.add(p);
        }

        for (const finding of fixedFindings) {
          const failingPaths = stillFailing.get(finding.checkId);
          const covered = coveredFiles(finding);
          finding.fixVerified = !failingPaths || !covered.some(p => failingPaths.has(p));
          if (finding.fixVerified) continue;

          finding.fixMessage = (finding.fixMessage || '') + ' [FIX NOT VERIFIED - issue may persist]';

          // The check did not pass, so stop saying it did.
          //
          // Thirteen checks report `passed: <check>Fixed` and flip `passed`
          // true the moment they apply a fix. This block is the authority
          // that learns the fix did not land, and until now it recorded that
          // only in `fixVerified` — a second field every consumer had to
          // remember to consult. `countsAgainstScore` does (it tests
          // `fixVerified` BEFORE `passed`), so the score counted the finding
          // and the clamp fired; every surface reading the raw field did not,
          // so the finding vanished from the report while the number it
          // caused stayed. Measured on a repo with an incomplete `.gitignore`
          // and a committable `credentials.json`:
          //
          //   Security  ━━━ 69/100  (score capped from 89 to 69 — verdict is
          //                          fail-direction)
          //   Verdict   Usable with caveats.
          //   ── Findings ──   1 low
          //
          // — the GIT-002 HIGH driving the cap reported nowhere. That is #259
          // inverted, and it only ever worked for `PERM-001`, which keeps
          // `passed: false` while fixing.
          //
          // Clearing it here fixes the findings block, the category summary,
          // the verdict, `--format asp`, the opt-in telemetry payload and
          // `secure-openclaw` at once, instead of teaching ~20 call sites a
          // two-field rule. `countsAgainstScore` is unaffected: its first
          // branch already returns true for this shape.
          finding.passed = false;

          // An unverified finding is now reported like any other outstanding
          // issue, so its location has to be true. The pre-fix `file` and
          // `message` describe the pre-fix tree: `PERM-001` names
          // 'secrets.json' — the file the run REPAIRED — while '.env', still
          // world-readable, is named nowhere. Re-point at the survivor.
          //
          // The re-scan is the authority. It is a real scan of the post-fix
          // tree, so its own finding for this check already carries the
          // correct file, message and evidence, computed by the check itself.
          // Copying beats re-deriving: checks disagree on what `file` means
          // (GIT-001 points at the '.gitignore' it would edit, PERM-001 at an
          // offending file), and only the check knows which.
          // `f.file` is required rather than assumed: today `scan()` returns
          // `filteredFindings`, which already drops fileless findings, but
          // re-pointing a finding at an undefined location would be worse
          // than leaving the stale one, so don't depend on that invariant.
          const survivors = verifyFindings.filter(
            f => f.checkId === finding.checkId
              && !f.passed && !f.fixed && !!f.file
              && coveredFiles(f).some(p => covered.includes(p)),
          );

          // Re-point only onto a path the report can actually show. The
          // filter below runs AFTER this block and drops ignored paths, so
          // re-pointing onto one would delete this finding from the report
          // outright — trading a false "verified" for a silent disappearance,
          // which is no better. When every survivor is ignored the finding
          // keeps its original attribution and still counts as unverified.
          const survivor = survivors.find(
            f => !this.isPathIgnored(f.file as string, allIgnoredPaths),
          );
          if (survivor) {
            finding.file = survivor.file;
            finding.line = survivor.line;
            finding.message = survivor.message;
            // Copied, not aliased — `verifyResult` is discarded here, and a
            // shared reference would let a later mutation reach both. Guarded
            // like `evidence`: an absent one must not erase real evidence.
            if (survivor.details) finding.details = { ...survivor.details };
            // Only when the survivor actually carries evidence — copying an
            // absent one would strip a field that is mandatory from v0.22.
            if (survivor.evidence) finding.evidence = survivor.evidence;
          }

          // The finding's own `manualFix` was built from the PRE-fix file
          // list, so it names files this run already repaired. Carry the
          // survivor's — recomputed against the post-fix tree — or drop it
          // rather than ship a stale command under a field documented as the
          // remedy to use.
          finding.manualFix = survivor?.manualFix;

          // `fix` names the auto-fix that just failed, so following it re-runs
          // the failure. Cite the manual equivalent the check supplies.
          finding.fix = finding.manualFix
            ?? 'Auto-fix did not resolve this. Apply the change manually, then re-scan to confirm.';
        }

        // Emitted after the report filter below, not here: this line counted
        // every fixed finding while the CLI's summary counts only the ones
        // that survive into `result.findings`, so a single run printed two
        // different denominators four lines apart — "Fix verification: 1/2
        // fixes confirmed" above "Attempted 1 fix, none confirmed". Both go
        // to the same reader, who is left deciding which number is wrong.
        reportFixVerification = fixedFindings.length > 0;

        // #374 — adopt the findings this scan produced inside THIS RUN's own
        // archive, so the score is computed over the tree the next scan sees.
        //
        // This is deliberately NOT the other repair. Excluding the archive from
        // scoring would hand any scanned tree a suppression token and would
        // reopen #305/#309/#341; `isOwnBackupDir`, `resolveArchiveBase` and the
        // walk exclusion are all untouched here, and a pre-existing archive is
        // still an ordinary reported finding. What changes is only WHICH TREE the
        // announced number describes. The archived copy of a credential is real,
        // so it counts — it just has to count in both numbers, not one.
        //
        // Safe against the rewrite hazard the exclusion exists for: this runs
        // after every fix write has already happened, so nothing here can send
        // `--fix` back into its own backup.
        //
        // Scoped to archive-located findings, not "every finding the verify scan
        // has and we do not". A finding whose `file` attribution SHIFTED between
        // the two scans — the PERM-001 head-shift this block already deals with
        // above — looks novel under a (checkId, file) key, and adopting it would
        // count one issue twice and penalise the score for a repair that landed.
        // Keyed with a space: a checkId is `[A-Z0-9-]+` and never contains one,
        // so the first space splits the pair unambiguously however the path is
        // spelled. (A NUL separator is the conventional choice and is what this
        // was first written with — it is also a raw control byte in source,
        // invisible in every diff, which `render-source-gate` rightly rejects.)
        const alreadyHeld = new Map<string, SecurityFindingDraft>();
        for (const f of findings) {
          if (f.file) alreadyHeld.set(`${f.checkId} ${f.file}`, f);
        }
        const adopted: SecurityFindingDraft[] = [];
        for (const f of verifyResult.findings) {
          if (!f.file) continue;
          // Identity, not spelling (#317) — and only a proven `yes`. `unknown`
          // means an ancestor the filesystem would not describe, which is not
          // evidence that a path is ours; treating it as ours would let the
          // shifted-attribution case back in through the one door this filter
          // exists to close.
          if (await this.isInsideOwnBackup(path.resolve(targetDir, f.file)) !== 'yes') continue;
          const key = `${f.checkId} ${f.file}`;
          // If a finding is already in this run's list, adopting it again would
          // double-count it. Skipping it silently would be worse in the other
          // direction: it would stay unflagged, and `scoreExcludingOwnArchive`
          // (`:949`) derives the live-tree number by DROPPING flagged findings, so
          // an archive copy would count as live tree and the report would tell the
          // user those points do not come back when the archive goes — the inverse
          // of what that line exists to say. So flag it where it already sits, and
          // adopt only what is genuinely new.
          //
          // NO PRODUCER REACHES THIS BRANCH TODAY, and an earlier version of this
          // comment claimed one did — that `keyFiles`/`namedSensitive` do not
          // exclude the archive, so some archive findings are already in the list.
          // That is false: `SENSITIVE_NAMES` and `keyFiles` feed `presentSensitive`
          // into GIT-001/GIT-002's `details.files`, and those findings carry the
          // CONSTANT `.gitignore` as their `file`. Nothing sets a finding's `file`
          // to a path inside this run's own archive. Verified three ways: an
          // instrumented full suite (229 files, 0 hits), a kitchen-sink fixture of
          // every sensitive name and `BACKUP_FILES` shape (35 findings, 17 flagged,
          // 0 hits), and reverting this branch entirely (all 5 suite tests still
          // pass). It is kept as the correct behaviour for the day the Layer-2
          // wiring changes — which nothing guards (#382) — not because it fires.
          const held = alreadyHeld.get(key);
          if (held) { held.inOwnArchive = true; continue; }
          alreadyHeld.set(key, f);
          f.inOwnArchive = true;
          adopted.push(f);
        }
        findings.push(...adopted);
      }
    }

    // Filter findings to only show real, actionable issues:
    // 1. Only failed checks (passed: false)
    // 2. Only checks with a file path (concrete findings, not generic advice)
    // 3. Only checks that apply to this project type (e.g., no SQL checks on MCP servers)
    //
    // What the USER suppressed is handled separately, below: those findings are
    // MARKED and kept, not dropped (#450). The three suppression predicates used
    // to sit in this filter, and because the score is computed from whatever
    // survives it, naming a check on the command line removed that check's
    // penalties and RAISED the score.
    let filteredFindings = findings.filter((f) => {
      // Keep fixed findings (so users can see what was fixed)
      // Otherwise, only show failed checks
      if (!f.fixed && f.passed) return false;

      // Only show concrete findings (has a file path)
      if (!f.file) return false;

      // Only show checks relevant to this project type
      if (!this.findingAppliesTo(f, projectType)) return false;

      return true;
    });

    // #450 — user suppression, and the line between the two kinds of it.
    //
    // SUPPRESSING A CHECK ID is not a scope change. The check ran over the whole
    // tree and matched something; removing it removes a penalty. That is what
    // made `--ignore CONFIG-004` move `corpus/repo/buggy/leaky-env-example` from
    // 69/100 exit 1 to 98/100 exit 0 with the credential verdict gone and nothing
    // in the output naming the suppression. These are MARKED and kept, so the
    // score, the verdict band and every channel's exit code still see them, and
    // only the renderer drops them from the list.
    //
    // EXCLUDING A PATH is a scope change, and is scored as one. `test-fixtures/`
    // in an `.hmaignore` means "this part of the tree is not my product", which
    // is the same statement as scanning a subdirectory, and a smaller target
    // honestly scores differently. Treating it as a penalty to keep was measured
    // and rejected: it took HMA's own repo from 100/100 to 0/100 with 25 critical,
    // every one of them in deliberately-vulnerable fixtures that are excluded
    // from the published package. A number that is useless is not more honest
    // than a number that is scoped, PROVIDED the scope is disclosed — and the
    // disclosure is the half that was missing before, not the arithmetic.
    // `scan-soul`'s profile path is the precedent: skipped domains leave the
    // denominator and are named on a `Scope` line.
    //
    // So: path exclusions leave the scored set and are reported as scope;
    // check-ID suppressions stay in it and are reported as suppression.
    const pathExcluded: SecurityFindingDraft[] = [];
    for (const f of filteredFindings) {
      if (ignoredChecks.has(f.checkId.toUpperCase())) {
        f.suppressed = true;
        f.suppressedBy = 'ignore-flag';
      } else if (this.isCheckIdSuppressed(f.checkId, suppressedCheckPatterns)) {
        f.suppressed = true;
        f.suppressedBy = 'hmaignore-check';
      } else if (!this.retainAfterPathSuppression(f, allIgnoredPaths)) {
        // #280's re-pointing behaviour is preserved: `retainAfterPathSuppression`
        // returns true for a multi-file finding while ANY covered path survives,
        // and has already re-pointed `file` onto a survivor by the time it does.
        // Only a finding whose every covered path is ignored reaches here, so a
        // partial ignore still keeps its finding and still scores — which is the
        // #280 rule, unchanged.
        f.suppressed = true;
        f.suppressedBy = 'hmaignore-path';
        pathExcluded.push(f);
      }
    }
    // Both kinds leave `findings`; they differ in what happens to the SCORE.
    //
    // The first cut of this fix kept check-ID-suppressed findings in the array
    // so that every scoring and exit path would inherit the correction for free.
    // That was measured and rejected. `findings` is not read only by renderers
    // and scorers: it also drives the `--fix` governance auto-fix, the Registry
    // publish payload, `allFindings` in `--json`, and the openclaw and nemoclaw
    // report paths. Leaving suppressed entries in it made `secure --fix --ignore
    // X` WRITE a SOUL.md for the suppressed check, and made `--json` ship the
    // suppressed finding's `evidence.lines[].content` — a plaintext credential —
    // two keys away from a disclosure record built to exclude exactly that. The
    // claimed failure mode, "a display site that forgets to filter is loud and
    // safe", was wrong: a forgotten site writes to disk and publishes to a
    // registry.
    //
    // So `findings` keeps its old meaning, every one of those consumers is
    // unchanged from 0.27.0, and the correction is applied where the defect
    // actually is — the score and the gate, via `suppressed`, which
    // `scoreWithSuppressed` adds back.
    const suppressed = summarizeSuppressed(
      filteredFindings.filter((f) => f.suppressedBy && f.suppressedBy !== 'hmaignore-path'),
    );
    const outOfScope = summarizeSuppressed(pathExcluded);

    filteredFindings = filteredFindings.filter((f) => !f.suppressed);

    // #421 — which FAILED findings did the scanner silence on its own?
    //
    // Derived as a separate pass over the same inputs rather than folded into
    // the filter above, so the filter's behaviour is unchanged by inspection.
    // A finding counts here only if it failed, did not survive, and was not
    // suppressed at the USER's request — `--ignore` and `.hmaignore` are
    // disclosed through `ignored`, and re-reporting them would punish the user
    // for a choice they made.
    //
    // What remains splits in two, and the split matters more than the total:
    //
    //  - WITH a file: the check matched something in the tree and the finding
    //    was dropped anyway, because its prefix is out of scope for the
    //    detected project type. That is a real detection, hidden. It is the
    //    only kind that may withdraw a category's `clear`.
    //  - WITHOUT a file: the check reported the ABSENCE of a mitigation and
    //    has nothing to point at — "no rate limiting detected" on a library
    //    with no HTTP server. A clean three-file library carries ~45 of these,
    //    2 of them nominally critical. Nothing was found, so `clear` is not
    //    made false by them, and surfacing them by category would be a wall of
    //    FUD with no path forward. Counted, not named.
    const survived = new Set<SecurityFindingDraft>(filteredFindings);
    const suppressedFailures: Array<{
      checkId: string;
      name: string;
      category: string;
      severity: string;
    }> = [];
    let unevidencedFailures = 0;
    for (const f of findings) {
      if (f.passed && !f.fixed) continue;
      if (survived.has(f)) continue;
      if (ignoredChecks.has(f.checkId.toUpperCase())) continue;
      if (this.isCheckIdSuppressed(f.checkId, suppressedCheckPatterns)) continue;
      if (!this.retainAfterPathSuppression(f, allIgnoredPaths)) continue;
      if (!f.file) {
        unevidencedFailures++;
        continue;
      }
      // Identity only. No `file`, no `message` — see the field's contract.
      suppressedFailures.push({
        checkId: f.checkId,
        name: f.name,
        category: f.category,
        severity: f.severity,
      });
    }

    // Deliberately carries no counts. This line used to read "Fix
    // verification: 1/2 fixes confirmed" four lines above the CLI's
    // "Attempted 1 fix, none confirmed" — two denominators for one run,
    // printed to the same reader, who is left deciding which is wrong.
    //
    // The scanner cannot fix that by counting more carefully, because it
    // cannot know what its caller will drop afterwards: `cli.ts` re-filters
    // `result.findings` with `!f.passed` at five recalculation sites, which
    // discards a SUCCESSFULLY fixed finding (`passed: true, fixed: true`)
    // that this filter deliberately keeps. So the count belongs where the
    // display is. The CLI's summary block already reports verified and
    // unconfirmed accurately; this is progress, not data.
    if (reportFixVerification && options.onProgress) {
      options.onProgress('Verifying applied fixes...');
    }

    // #450 — the scored set is the reported findings PLUS the penalties of the
    // check IDs the caller suppressed. Suppressing a check is a display choice;
    // it does not make the tree safer, and before this it moved
    // `corpus/repo/buggy/leaky-env-example` from 69/100 exit 1 to 98/100 exit 0.
    // Path exclusions are NOT here: those are a scope statement and are reported
    // separately on `outOfScope`.
    const scoredFindings = [
      ...filteredFindings,
      ...(expandSuppressed(suppressed) as unknown as SecurityFindingDraft[]),
    ];

    // Calculate score (only on applicable findings, plus suppressed penalties)
    const { score: rawScore, maxScore } = this.calculateScore(scoredFindings);

    // #259 governance floor. A SOUL-only governance subversion barely dents
    // the infra-weighted composite, so `secure` on the malicious
    // permissive-overrides-soul fixture printed 76/100 — the green "good"
    // band — directly above `Verdict  Not safe as-is.` The direction contract
    // held everywhere else (exit 1, red verdict, findings listed); only the
    // number disagreed, and the number is what a reader anchors on.
    //
    // The clamp is applied here rather than at render time so `--json` and
    // the Registry carry the same figure the terminal shows; a display-only
    // fix would leave every programmatic consumer reading 76. `rawScore` is
    // preserved, so this adds information rather than destroying it — the
    // same shape as the scan-soul #206/#251 clamp.
    const { score, clamped: scoreClamped } = clampScoreToVerdictBand(rawScore, scoredFindings);

    // #374 — the live-tree view of the SAME findings set. `score` above is the
    // number the next scan at the SAME DEPTH will produce — exactly so for `quick`
    // and `standard`, and with one documented exception for `--deep`, where the
    // verify scan is capped at `standard` so it cannot transmit this run's archive
    // to the LLM (#385/#386). This is what the tree is worth once the archived copy
    // is rotated and deleted, and the report names it so a post-fix number that
    // went DOWN is attributable rather than mysterious.
    const scoreExcludingArchive = scoreExcludingOwnArchive(filteredFindings);

    // In dry-run mode, mark fixable failed findings with wouldFix
    if (dryRun && autoFix) {
      for (const finding of filteredFindings) {
        if (!finding.passed && finding.fixable) {
          finding.wouldFix = true;
        }
      }
    }

    // Determine if all fixes completed successfully (atomic)
    const hasFixedFindings = filteredFindings.some((f) => f.fixed);
    const atomicFix = shouldFix ? !fixFailed && hasFixedFindings : undefined;

    // Route point 4. Both returned arrays are filters of `findings`, so a draft
    // that survives both used to be THE SAME OBJECT in each — `filteredFindings`
    // is `findings.filter(...)` (:3122, :3204) and `dropPathlessNoiseFloor` is
    // another filter over `findings`.
    //
    // Emitting each array independently would quietly end that. `emitFinding`
    // returns a new object, so the two channels would hold separate copies and a
    // post-scan mutation of `result.findings[i]` would stop reaching
    // `result.allFindings` — `cli.ts:11630` demotes severity exactly that way.
    // No consumer depends on it today (`eval` never reads `allFindings`, and the
    // `secure` path re-derives both from one array at `cli.ts:4718`), so this is
    // a latent hazard rather than a live defect — but it is one a future reader
    // would have no way to see, and preserving identity costs a Map.
    //
    // It also halves the work: a finding in both channels is redacted once.
    const emitted = new Map<SecurityFindingDraft, ReturnType<typeof emitFinding>>();
    const emitOnce = (f: SecurityFindingDraft) => {
      const seen = emitted.get(f);
      if (seen) return seen;
      const fresh = emitFinding(f);
      emitted.set(f, fresh);
      return fresh;
    };

    return {
      timestamp: new Date(),
      platform,
      projectType,
      // Route point 4: the last construction before any channel. Everything
      // above this line is a DRAFT — the 68 accumulators, the 65 check methods
      // that fill them, and every helper that filters, scores or enriches them
      // — and the two redaction fields do not exist until here. `scan()`'s
      // return is the narrowest point that covers the 253 `scanner.ts` literals
      // plus `assembly-scanner`, `external-scanner` and `nanomind-analyzer`.
      findings: filteredFindings.map(emitOnce),
      // allFindings is consumed by benchmark, OASB-2 composite, and the
      // corpus release-smoke harness. Drop true noise-floor findings —
      // pathless failed findings whose check doesn't apply to this
      // project type (issue #131 / #130). Pathless findings whose check
      // DOES apply (a check that found real evidence but failed to
      // attribute a file) are preserved as legitimate detections.
      // `allFindings` is a SECOND channel, not a view of the first: benchmark,
      // the OASB-2 composite and the corpus release-smoke harness read it, and
      // two of the four measured JSON leak paths were under `$.allFindings[…]`.
      // It emits independently for that reason.
      allFindings: dropPathlessNoiseFloor(findings, projectType).map(emitOnce),
      score,
      rawScore,
      scoreClamped,
      scoreExcludingOwnArchive: scoreExcludingArchive,
      maxScore,
      backupPath,
      dryRun: dryRun && autoFix ? true : undefined,
      atomicFix,
      ignored: ignoredChecks.size > 0 ? Array.from(ignoredChecks) : undefined,
      // #450 — findings an `.hmaignore` path rule put out of scope. They are NOT
      // in `findings` and NOT in the score, and this is the only record that the
      // scan was narrowed, so it is what makes the narrowing non-silent.
      outOfScope: outOfScope.length > 0 ? outOfScope : undefined,
      // #450 — the check IDs the caller suppressed. NOT in `findings` (that
      // array feeds --fix, publish and every report format), but their
      // penalties ARE in `score`, and every later re-score must add them back
      // via `expandSuppressed` or the laundering returns.
      suppressed: suppressed.length > 0 ? suppressed : undefined,
      semanticAnalysis: (layer2Count > 0 || layer3Count > 0) ? {
        layer2Findings: layer2Count,
        layer3Findings: layer3Count,
        llmCost,
        cachedResults,
      } : undefined,
      // What this run actually examined, measured rather than configured.
      // The renderer derives the Categories / Checks lines from this, so a
      // category with no executed check can no longer print as clear.
      coverage: {
        filesExamined: this.coverage.filesExamined,
        executions: this.coverage.records,
        truncations: this.coverage.caps,
        // Counts, never paths — a single-file scan normalises its target into
        // a generated temp directory, and emitting read paths leaked that name.
        filesReadByCategory: this.coverage.categoryFileCounts(),
        suppressedFailures,
        unevidencedFailures,
        // Counts and errno codes, never paths — same rule as the line above.
        // Every recorded unread input, deliberately unscoped: a path rule
        // cannot make an unread file read, and `retainAfterPathSuppression`
        // keeps the matching finding visible for the same reason. This is the
        // number `cli.ts` settles the exit code on (#590).
        unreadableInputs: this.allUnreadableInputs(),
      },
    };
  }

  private async detectPlatform(targetDir: string): Promise<string> {
    const platforms: string[] = [];

    try {
      await fs.access(path.join(targetDir, 'CLAUDE.md'));
      platforms.push('claude-code');
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.cursor'));
      platforms.push('cursor');
    } catch {}

    try {
      await fs.access(path.join(targetDir, 'mcp.json'));
      platforms.push('mcp');
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.claude'));
      if (!platforms.includes('claude-code')) {
        platforms.push('claude-code');
      }
    } catch {}

    // OpenClaw detection
    try {
      await fs.access(path.join(targetDir, '.openclaw'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.moltbot'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    try {
      await fs.access(path.join(targetDir, '.clawdbot'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    // Check for openclaw.json
    try {
      await fs.access(path.join(targetDir, 'openclaw.json'));
      if (!platforms.includes('openclaw')) {
        platforms.push('openclaw');
      }
    } catch {}

    // Check for SKILL.md files (OpenClaw skill project)
    try {
      const files = await fs.readdir(targetDir);
      if (files.some(f => f === 'SKILL.md' || f.endsWith('.skill.md'))) {
        if (!platforms.includes('openclaw')) {
          platforms.push('openclaw');
        }
      }
    } catch {}

    if (platforms.length === 0) {
      return 'generic';
    }

    return platforms.join('+');
  }

  /**
   * Detect the project type based on package.json and project structure
   */
  private async detectProjectType(targetDir: string): Promise<ProjectType> {
    // Check for OpenClaw project indicators (check first as it's more specific)
    const openclawIndicators = ['.openclaw', '.moltbot', '.clawdbot', 'SKILL.md', 'HEARTBEAT.md', 'openclaw.json'];
    for (const indicator of openclawIndicators) {
      try {
        await fs.access(path.join(targetDir, indicator));
        return 'openclaw';
      } catch {}
    }

    // Check for *.skill.md files at root level (OpenClaw skill project)
    try {
      const files = await fs.readdir(targetDir);
      if (files.some(f => f.endsWith('.skill.md'))) {
        return 'openclaw';
      }
    } catch {}

    // Check for skills/ subdirectory with SKILL.md files (common OpenClaw layout)
    try {
      await fs.access(path.join(targetDir, 'skills'));
      return 'openclaw';
    } catch {}

    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);

      // Check dependencies for framework detection
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      // Check for MCP server BEFORE cli -- MCP servers often have bin fields
      if (
        allDeps['@modelcontextprotocol/sdk'] ||
        allDeps['mcp'] ||
        pkg.name?.includes('mcp')
      ) {
        return 'mcp';
      }

      // Check for SDK/API client packages (requires 2+ signals).
      // Must run before CLI check: some SDKs ship CLI shims (e.g., openai)
      // but are primarily libraries.
      if (this.detectSDKPackage(pkg, allDeps)) {
        return 'sdk';
      }

      // Check if it's a CLI tool (has bin field)
      if (pkg.bin) {
        return 'cli';
      }

      // Check for web frameworks
      if (
        allDeps['react'] ||
        allDeps['vue'] ||
        allDeps['svelte'] ||
        allDeps['@angular/core'] ||
        allDeps['next'] ||
        allDeps['nuxt']
      ) {
        return 'webapp';
      }

      // Check for API frameworks
      if (
        allDeps['express'] ||
        allDeps['fastify'] ||
        allDeps['koa'] ||
        allDeps['hapi'] ||
        allDeps['@hapi/hapi'] ||
        allDeps['restify']
      ) {
        return 'api';
      }

      // Default to library if it has main/exports but no clear type
      if (pkg.main || pkg.exports || pkg.module) {
        return 'library';
      }
    } catch {
      // No package.json or invalid JSON
    }

    // Check for Python projects
    try {
      const setupPath = path.join(targetDir, 'setup.py');
      await fs.access(setupPath);
      return 'library';
    } catch {}

    try {
      const pyprojectPath = path.join(targetDir, 'pyproject.toml');
      const content = await fs.readFile(pyprojectPath, 'utf-8');
      if (content.includes('fastapi') || content.includes('flask') || content.includes('django')) {
        return 'api';
      }
      return 'library';
    } catch {}

    // Default to library for generic projects
    return 'library';
  }

  /**
   * Detect if a package is an SDK/API client. Requires 2+ independent
   * signals to avoid false positives (a random library with axios isn't
   * necessarily an SDK).
   */
  private detectSDKPackage(
    pkg: Record<string, unknown>,
    allDeps: Record<string, string>,
  ): boolean {
    const name = ((pkg.name as string) ?? '').toLowerCase();
    const desc = ((pkg.description as string) ?? '').toLowerCase();
    const keywords = (pkg.keywords as string[]) ?? [];

    // Signal 1: Package name contains SDK/client indicators
    const nameSignals = ['/sdk', '-sdk', '-client', 'api-client', '-api']
      .some(s => name.includes(s)) || name.endsWith('sdk');

    // Signal 2: Description mentions SDK/client/wrapper/library-for-API patterns
    const descSignals = [
      'sdk', 'client library', 'api client', 'api wrapper', 'official client',
      'library for the', 'library for', 'client for the', 'client for',
    ].some(s => desc.includes(s)) && desc.includes('api');

    // Signal 3: Has library exports (main/exports). SDKs may also ship CLI
    // shims, so we don't exclude on bin presence.
    const hasLibraryExports = !!(pkg.main || pkg.exports || pkg.module);

    // Signal 4: Depends on HTTP clients
    const httpDeps = ['node-fetch', 'axios', 'got', 'undici', 'cross-fetch', 'ky', 'superagent']
      .some(d => d in allDeps);

    // Signal 5: Keywords include sdk/client
    const kwSignals = keywords.some(k =>
      ['sdk', 'client', 'api-client', 'wrapper'].includes(k.toLowerCase()),
    );

    // Signal 6: Description pattern "for the X API" -- strong signal that
    // this is an API client library
    const forApiPattern = /\bfor\s+the\s+\w+\s+api\b/i.test(desc) ||
      /\b(official|typescript|javascript|node)\s+\w*\s*(library|client|sdk)\b/i.test(desc);

    const signalCount = [
      nameSignals,
      descSignals,
      hasLibraryExports && httpDeps,
      kwSignals,
      forApiPattern && hasLibraryExports,
    ].filter(Boolean).length;
    return signalCount >= 2;
  }

  /**
   * Check if a finding applies to the given project type.
   *
   * Delegates to the exported `findingAppliesTo` so the scanner's own filter
   * and the CLI's post-NanoMind-merge filter cannot drift apart. They were two
   * separate copies of the same loop; the copies agreed by luck, and only one
   * of them would have been fixed (#421).
   */
  findingAppliesTo(finding: SecurityFindingDraft, projectType: ProjectType): boolean {
    return findingAppliesTo(finding, projectType);
  }

  /**
   * Whether a finding would be reported at all — the same three conditions
   * `scanInner` gates on, exposed for the same reason `findingAppliesTo` is
   * (#457). Five CLI call sites had re-spelled this predicate by hand and
   * `reapplyIgnoreFilters` had not, so the suppression accounting disagreed with
   * the display set about what a suppression could possibly withhold.
   */
  isReportableFinding(finding: SecurityFindingDraft, projectType: ProjectType): boolean {
    return isReportableFinding(finding, projectType);
  }

  private async checkCredentialExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const envVarsToAdd: Set<string> = new Set();

    // Credential patterns with their env var names (stricter to avoid false positives)
    const credentialPatterns = [
      { name: 'Anthropic API Key', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/g, envVar: 'ANTHROPIC_API_KEY' },
      { name: 'OpenAI API Key', pattern: /sk-proj-[a-zA-Z0-9]{20,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48,}/g, envVar: 'OPENAI_API_KEY' },
      { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, envVar: 'AWS_ACCESS_KEY_ID' },
      { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'GitHub Token', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g, envVar: 'GITHUB_TOKEN' },
      { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, envVar: 'GOOGLE_API_KEY' },
      { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, envVar: 'STRIPE_SECRET_KEY' },
    ];

    // Files to check for credentials. secrets.json / credentials.json
    // added in #250 — they were previously unscanned even though their
    // names promise exactly this content.
    //
    // #292 — this was a fixed ROOT-relative probe list, so a credential in
    // `src/config.json` was invisible while the identical token in
    // `./config.json` scored 69/100 with CRED-001 + SEM-CRED-002. The list
    // below is now the canonical root ORDER only; the actual set of files
    // comes from a recursive basename match at any depth.
    const rootProbeOrder = [
      'config.json',
      'config.yaml',
      'config.yml',
      'mcp.json',
      'settings.json',
      'secrets.json',
      'credentials.json',
      '.env',
      '.env.local',
      'CLAUDE.md',
    ];

    // Root files first, in their historical order, then everything deeper in
    // sorted order. Preserving the root sequence keeps finding order — and so
    // the byte-compared corpus goldens — stable for trees that only have
    // root-level config, which is every pre-existing fixture.
    //
    // The root names are probed UNCONDITIONALLY, exactly as before, rather
    // than being filtered through the walk's results. The walk is bounded and
    // can return `complete: false` on a pathological or unreadable tree;
    // gating the root probe on it would let a deep/unreadable directory
    // REMOVE detection that exists today. This change may only ever add
    // locations, never subtract them. Absent files are skipped by the same
    // readFile catch as before.
    const { configFiles: discovered } = await this.collectSensitiveArtifacts(targetDir);
    const nested = discovered.filter((rel) => rel.includes(path.sep)).sort();
    const filesToCheck = [...rootProbeOrder, ...nested];

    for (const filename of filesToCheck) {
      const filePath = path.join(targetDir, filename);
      try {
        let content = await fs.readFile(filePath, 'utf-8');
        const lines = content.split('\n');
        // #310, second harm — detection reads the file AS IT ARRIVED; only the
        // fix mutates `lines`. The loops are pattern-major, so with detection
        // reading the working copy an earlier pattern's replacement removed a
        // LATER pattern's credential from the line before that pattern was ever
        // examined. `${AKIA…_ghp_…}` reported "AWS Access Key" alone: the
        // GitHub token was deleted from the file and never named, so the user
        // rotates one key and leaves the other live. Which secret vanished
        // depended on `credentialPatterns` order.
        const originalLines = [...lines];
        let fileModified = false;
        const keysFoundInFile: Array<{ name: string; line: number }> = [];

        // #292 — basename, not the whole relative path: `filename` is now
        // `sub/.env` for a nested hit, and a raw `startsWith` would classify it
        // as a normal config file and REWRITE it in place.
        const isEnvFile = path.basename(filename).startsWith('.env');
        // #309/#314 — a file inside a backup archive is never auto-fixed:
        // rewriting it would destroy the copy `rollback` restores from. Not
        // attempted at all rather than attempted and refused, so the finding
        // carries a remediation that WORKS instead of a `secure --fix` that this
        // same guard would decline.
        //
        // #326 — asked ONCE per file, and the answer drives both the fix
        // attempt and the wording. It used to be asked twice, and the second
        // question was a different, stronger one ("is this PROVABLY our
        // archive?") whose positive answer emitted `rm -rf`. See the guidance
        // below for why that question can no longer be asked of the tree.
        //
        // #341 — and this one is no longer asked of the tree either. A `yes`
        // means the file is inside the backup directory HackMyAgent uses for
        // THIS tree, decided by identity. An `unknown` is left to the write gate,
        // which has its own cause for it and its own channel to report it: the
        // remediation here stays `secure --fix`, because on an ancestor the
        // filesystem momentarily would not describe, that command is still the
        // right one to run.
        const inArchive = (await this.isInsideArchiveBase(filePath, targetDir)) === 'yes';

        for (const { name, pattern, envVar } of credentialPatterns) {
          // Check each line for credentials
          for (let i = 0; i < lines.length; i++) {
            pattern.lastIndex = 0;
            // #281 — was `pattern.test(line) && !line.includes('${'+envVar+'}')`.
            // The second half is a SUBSTRING test over the whole line, so
            // appending ` ${ANTHROPIC_API_KEY}` to a live key silenced the
            // CRITICAL entirely. Now the exemption applies only to a match
            // that is itself inside a well-formed reference.
            if (hasCredentialOutsideEnvRef(originalLines[i], pattern)) {
              keysFoundInFile.push({ name, line: i + 1 });

              // Fix: replace credential with env var reference (but NOT in .env files
              // where the actual value is supposed to live, and never inside a
              // backup archive — both decided once, above).
              if (autoFix && !isEnvFile && !inArchive) {
                // #301 — a key wrapped in braces has to lose the braces with
                // it. Replacing only the inner match turns `"${ghp_aaa…}"`
                // into `"${${GITHUB_TOKEN}}"`: nested, expanded by no shell,
                // and still not the value anyone wanted.
                //
                // #308 — the whole ENCLOSING span, not just the exact-wrapper
                // shape, so padded spans (`${MY_ghp_…}`) lose their braces too.
                //
                // #310 — but bounded to a span that IS a reference. See
                // `replaceCredentialWithEnvRef`: the previous regex paired any
                // `${` with the next `}` and destroyed unrelated config data.
                lines[i] = replaceCredentialWithEnvRef(lines[i], pattern, envVar);
                fileModified = true;
                envVarsToAdd.add(envVar);
              }
            }
          }
        }

        // Report one finding per file with exposed credentials
        if (keysFoundInFile.length > 0) {
          const keyNames = [...new Set(keysFoundInFile.map((k) => k.name))];
          const firstLine = keysFoundInFile[0].line;

          if (fileModified) {
            const credContent = lines.join('\n');
            fileModified = await this.applyFixWrite(filePath, credContent);
            if (fileModified) content = credContent;
          }

          // #326 — HackMyAgent no longer claims to know who created a
          // `.hackmyagent-backup`-named directory, and never emits `rm -rf` for
          // one.
          //
          // #319 made the claim conditional on the archive's `.manifest.json`
          // LISTING the cited file. That manifest is a file in the scanned tree,
          // inside the attacker's own directory: they control its location AND
          // its contents, so one array element restored the fabricated citation
          // in full — `rm -rf` against `important-lib/` holding `main.js` and
          // `lib.js`, under "This is the copy `--fix` saved". A credential
          // directly in the base aimed the same deletion at the WHOLE
          // `.hackmyagent-backup`, destroying real prior-run backups.
          //
          // Fifth instance of one class: #304 a `\`-folded path, #305 a name,
          // #309 a manifest shape, #317 a case-sensitive compare, #326 a
          // manifest array element. Every one of them was a STRING the scanned
          // tree could write, used as proof of a property of the filesystem.
          //
          // So the question is not asked. The only non-forgeable evidence
          // available without new state is the `dev`+`ino` of a directory THIS
          // run created — and a this-run backup is already excluded from
          // detection, so there is no case left where proof exists and the
          // citation is wanted. A cross-run claim would need state HMA holds and
          // the tree cannot write (a per-user record of the identities it
          // created, or a MAC over the manifest keyed outside the tree); both
          // buy one convenience command in exchange for new state and its
          // failure modes, against a downside — deleting a directory that is not
          // ours — that is unrecoverable. The wording below states what is true
          // in both cases, names the verify step, and leaves the deletion to the
          // one party who can tell which case it is.
          findings.push({
            checkId: 'CRED-001',
            name: 'Exposed Credential',
            description: `${keyNames.join(', ')} found in plaintext`,
            category: 'credentials',
            severity: 'critical',
            passed: fileModified,
            message: keyNames.join(', '),
            file: filename,
            line: firstLine,
            // .env files can't be auto-fixed (that's where values belong);
            // archives must not be (rewriting them destroys the rollback copy).
            fixable: !isEnvFile && !inArchive,
            fixed: fileModified,
            fix: inArchive
              ? 'Rotate the credential, then remove this plaintext copy by hand'
              : isEnvFile
                ? 'Add .env to .gitignore to prevent committing secrets'
                : `${this.cliName} secure --fix`,
            guidance: inArchive
              ? 'Rotate the credential: it has been on disk in plaintext. Clearing the copy is yours to do — this file sits '
                + `inside \`${BACKUP_DIR_NAME}\`, the directory HackMyAgent stores this tree's backups in, which it never `
                + 'auto-edits (rewriting a backup would destroy what `rollback` restores from) and never offers to delete, '
                + 'because it cannot tell which run wrote a given copy. Check the live file first: '
                + `\`${this.cliName} secure\` should report no credential outside this directory.`
              : isEnvFile
                ? 'Credentials in .env are expected but the file must be in .gitignore. Run `hackmyagent secure --fix` to create a .gitignore.'
                : 'Replaces hardcoded credentials with ${ENV_VAR} references. Store actual values in your .env file, which should be in .gitignore.',
          });
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    // Create .env.example if we fixed any credentials
    if (autoFix && envVarsToAdd.size > 0) {
      const envExamplePath = path.join(targetDir, '.env.example');
      let envExampleContent = '# Environment variables\n\n';
      for (const envVar of envVarsToAdd) {
        envExampleContent += `${envVar}=\n`;
      }
      await this.applyFixWrite(envExamplePath, envExampleContent);
    }

    return findings;
  }

  private async checkClaudeMd(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const claudeMdPath = path.join(targetDir, 'CLAUDE.md');

    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      const lines = content.split('\n');
      let credentialLine: number | undefined;
      let credentialType: string | undefined;

      // Check for credentials in CLAUDE.md
      for (const { name, pattern } of CREDENTIAL_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.test(lines[i])) {
            credentialLine = i + 1;
            credentialType = name;
            break;
          }
        }
        if (credentialLine) break;
      }

      // Only report if credentials found
      if (credentialLine) {
        findings.push({
          checkId: 'CLAUDE-001',
          name: 'Credential in CLAUDE.md',
          description: `${credentialType} found in CLAUDE.md`,
          category: 'claude-code',
          severity: 'critical',
          passed: false,
          message: 'Remove credentials from CLAUDE.md',
          file: 'CLAUDE.md',
          line: credentialLine,
          fixable: false,
          fix: 'npx secretless-ai init',
          guidance: 'CLAUDE.md is sent to your AI provider on every request. Credentials here are exposed to the model and extractable via prompt injection. Run opena2a protect . to encrypt them into a secure vault.',
        });
      }
    } catch {
      // CLAUDE.md doesn't exist, that's fine - no finding needed
    }

    return findings;
  }

  private async checkMcpConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      const config = JSON.parse(content);

      // Check for dangerous filesystem access
      let hasRootAccess = false;
      let hasUnrestrictedShell = false;
      let mcp001Fixed = false;

      if (config.servers) {
        for (const [name, server] of Object.entries(config.servers as Record<string, { command?: string; args?: string[] }>)) {
          // Check for root filesystem access
          if (server.args) {
            const rootIndex = server.args.findIndex((arg: string) => arg === '/');
            const homeIndex = server.args.findIndex((arg: string) => arg === '~');

            if (rootIndex !== -1 || homeIndex !== -1) {
              hasRootAccess = true;

              if (autoFix) {
                // Replace "/" with "./data" and "~" with "./"
                if (rootIndex !== -1) {
                  server.args[rootIndex] = './data';
                }
                if (homeIndex !== -1) {
                  server.args[homeIndex] = './';
                }
                mcp001Fixed = true;
              }
            }
          }

          // Check for unrestricted shell access
          if (
            name.includes('shell') ||
            server.command?.includes('shell')
          ) {
            // Shell server without allowedCommands is dangerous
            if (!server.args?.some((arg: string) => arg.includes('allowed'))) {
              hasUnrestrictedShell = true;
            }
          }
        }
      }

      // Save fixed config. `mcp001Fixed` was set on the in-memory mutation
      // above, so it has to be revoked when the write does not land —
      // otherwise the finding reports `passed: true` for a config still
      // scoped at `/` on disk.
      if (mcp001Fixed) {
        mcp001Fixed = await this.applyFixWrite(mcpConfigPath, JSON.stringify(config, null, 2));
      }

      // Only report if there's an issue
      if (hasRootAccess) {
        findings.push({
          checkId: 'MCP-001',
          name: 'MCP Root Filesystem Access',
          description: 'Server has access to / or ~ directory',
          category: 'mcp',
          severity: 'high',
          passed: mcp001Fixed,
          message: 'Restrict filesystem access to specific directories',
          file: 'mcp.json',
          fixable: true,
          fixed: mcp001Fixed,
          fix: `${this.cliName} secure --fix`,
          guidance: 'Root or home directory access lets MCP servers read/write any file on the system. Restrict to project-relative paths (./data or ./) to limit blast radius.',
        });
      }

      if (hasUnrestrictedShell) {
        findings.push({
          checkId: 'MCP-002',
          name: 'Unrestricted Shell Server',
          description: 'Shell server has no command restrictions',
          category: 'mcp',
          severity: 'critical',
          passed: false,
          message: 'Add allowedCommands to restrict shell access',
          file: 'mcp.json',
          fixable: false,
          fix: 'Add "allowedCommands": ["ls", "cat", "grep"] to the shell server config in mcp.json',
          guidance: 'Unrestricted shell access lets the AI execute any command including destructive operations. Whitelisting specific commands limits what can be run.',
        });
      }
    } catch {
      // mcp.json doesn't exist - no findings needed
    }

    return findings;
  }

  /**
   * Guarantee the backup can undo a write to `filePath` before it happens.
   * Returns false when it cannot, and the caller must then not write (#300).
   *
   * The backup candidate set used to be a static, root-relative list
   * (`BACKUP_FILES`), predicted ahead of the scan. Every widening of
   * DETECTION therefore silently widened the set of files `--fix` rewrites
   * WITHOUT widening the set it can restore. #292 widened CRED-001 to
   * config-shaped files at any depth and this is what shipped:
   *
   *   before   config/production.json + src/config.json  = a live token
   *   --fix    both -> ${GITHUB_TOKEN}
   *   backup   holds only package.json
   *   rollback "Restored 1 modified file", exit 0
   *   after    both still redacted, original bytes unrecoverable
   *
   * Irreversible data loss behind an explicit success message. Extending the
   * static list would have closed that one instance and left the next
   * widening — #298 is already queued — to reopen it, so the coverage is
   * derived from the WRITE instead of predicted before it: whatever a fix is
   * about to touch is captured now, at the one choke point every fix write
   * already goes through.
   *
   * Fail-safe in every direction. No backup context, a path outside the
   * scanned tree, or a failed copy all return false, and the write is
   * abandoned and reported as FIX-WRITE-FAILED — the user keeps their bytes
   * and is told the fix did not land, which is the recoverable outcome. A
   * file that does not exist yet is a creation, not an overwrite: nothing to
   * copy, so it is recorded as an absent candidate and left to
   * `recordCreatedFiles`, which hash-verifies before rollback removes it.
   */
  private async ensureBackupCovers(filePath: string): Promise<boolean> {
    const ctx = this.backupContext;
    if (!ctx) return false;

    const rel = this.toTargetRelativePath(filePath, ctx.targetDir);
    if (!rel) return false; // escapes the scanned tree — not ours to rewrite
    if (ctx.covered.has(rel)) return true;

    // `copyFile` follows symlinks, matching `createBackup`: the fix sites
    // write THROUGH a link, so the bytes at the far end are what has to be
    // recoverable. See the symlink note in `createBackup`.
    //
    // Copy FROM `filePath` — the path this write will actually land on — and
    // never from a path rebuilt out of `rel`. `rel` is a normalized
    // description of `filePath`, and re-deriving the source from it was #304:
    // the guard protected a path that was not the one being written.
    let existed = true;
    try {
      const destPath = path.join(ctx.backupDir, rel);
      await fs.mkdir(path.dirname(destPath), { recursive: true });
      await fs.copyFile(filePath, destPath);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') return false;
      // ENOENT is overloaded here and only ONE of its meanings is a creation.
      // It is also raised for a dangling symlink (the entry exists and the fix
      // writes THROUGH it), for a backup directory that vanished mid-run, and
      // for any source that resolves somewhere unexpected. So absence is
      // PROVEN against the real path rather than inferred from an errno —
      // inferring it is what made the guard authorise the write it exists to
      // gate. `lstat`, not `stat`: a dangling symlink is an entry that exists,
      // so it is not a creation, and it has no recoverable copy — fail safe.
      if (!(await this.isGenuinelyAbsent(filePath))) return false;
      existed = false;
    }

    // Persist before returning: `recordCreatedFiles` re-reads this file from
    // disk, and `rollback` is a separate process. An in-memory-only update
    // would restore nothing.
    if (!(await this.appendToBackupManifest(ctx.backupDir, rel, existed))) return false;
    ctx.covered.add(rel);
    return true;
  }

  /**
   * True when this path is inside the backup THIS RUN just created.
   *
   * #309 — the only exclusion left, and the only one that can be justified.
   * Every previous version decided whether to suppress a CRITICAL by reading
   * the scanned tree, which is the attacker's own filesystem:
   *
   *   #292/#302  ancestor directory NAMED `.hackmyagent-backup`
   *              -> the name was a one-word suppression token
   *   #305       name + a `.manifest.json` + a live counterpart
   *              -> the manifest is 70 bytes of JSON with two array keys, and
   *                 "is really a copy" was an EXISTENCE test that never
   *                 compared content. A forged manifest plus a benign decoy at
   *                 the mirrored path restored the bypass exactly: identical
   *                 credential bytes, `.notabackup` 69/100 with the CRITICAL,
   *                 `.hackmyagent-backup` 96/100 and silent. Two variants
   *                 needed no decoy at all — a dangling symlink, and an
   *                 ENOTDIR counterpart where the errno was read as "exists".
   *
   * Three rounds, three replacements of one attacker-suppliable token with
   * another. So the property is no longer taken from the tree at all: the run's
   * own `backupDir` is a path HMA chose this run, and nothing in the scanned
   * tree can name it. `createBackup` runs before every check, so without this
   * the same run would report the credential twice — once in the live file and
   * once in the copy HMA made microseconds earlier.
   *
   * A PRE-EXISTING archive is deliberately NOT excluded. After `--fix` the live
   * file holds `${GITHUB_TOKEN}` and the archive holds the only remaining
   * plaintext copy of the secret, so it is not a duplicate of anything —
   * suppressing it would mean hiding a plaintext credential that HMA itself
   * created. It reports, with a fix line that is not `secure --fix` (the write
   * guard refuses to edit archives) and, since #326, one that neither claims HMA
   * created the directory nor offers to delete it.
   *
   * #317 — the fourth round, and the one that made the shape of the class
   * unmistakable. `ctx.backupDir` was compared with `isPathWithinDirectory`, a
   * case-SENSITIVE `path.resolve` prefix compare, so the property was still a
   * STRING describing the directory rather than the directory. One pre-existing
   * `.HACKMYAGENT-BACKUP` on a case-insensitive filesystem (the macOS default)
   * was enough: `mkdir` adopted it, `readdir` returned the original casing, the
   * compare said no, and `--fix` redacted its own backup while `rollback`
   * restored the redaction and reported a clean revert. Measured: the archived
   * copy held `${GITHUB_TOKEN}` 200ms after the original was read.
   *
   * So the question is asked of the FILESYSTEM. `isOwnBackupDir` compares
   * `dev`+`ino`, which no spelling of a path can change.
   *
   * This variant answers the question for a FILE, by walking its ancestors. It
   * costs a `stat` per level, which is affordable at the write gate (a few
   * dozen calls per run) and is not affordable per scanned file — hence the
   * separate primitive the walks use.
   */
  private async isInsideOwnBackup(absPath: string): Promise<'yes' | 'no' | 'unknown'> {
    const ctx = this.backupContext;
    if (!ctx) return 'no';
    // Sound positive, no syscall. Only the negative needs the filesystem.
    if (this.isPathWithinDirectory(absPath, ctx.backupDir)) return 'yes';

    let dir = path.dirname(path.resolve(absPath));
    // Bounded: a path with more than 64 components is not something to keep
    // stat-ing, and the answer for anything that deep is "not our backup".
    for (let i = 0; i < 64; i++) {
      const probe = await identityOf(dir);
      if (sameIdentity(identityOrUndefined(probe), ctx.backupIdent)) return 'yes';
      // #333 — an ancestor the filesystem would not describe leaves the question
      // OPEN. Reported as such rather than collapsed into "no", because the
      // caller here is the write gate and "no" there authorises the write.
      if (probe.kind === 'unknown') return 'unknown';
      const parent = path.dirname(dir);
      if (parent === dir) return 'no'; // filesystem root
      dir = parent;
    }
    return 'no';
  }

  /**
   * True when `dirPath` is the backup directory this run created, or lies
   * inside it — decided by identity.
   *
   * This is the primitive the walks use, and it is asked once per directory
   * rather than once per file: a walk that does not descend into the backup
   * cannot produce a path inside it, and one that does (the config walk keeps
   * walking so `keyFiles`/`namedSensitive` semantics stay untouched) carries the
   * answer down its own recursion. That keeps the syscall cost at one `stat`
   * per directory of a `--fix` run, and zero for a detect-only scan.
   *
   * An unreadable directory is deliberately answered "not ours" HERE: the
   * consequence is that the directory is SCANNED, so a credential inside it is
   * still reported. That is the fail-closed direction for detection, and it is
   * the opposite of the direction the write gate needs — see `isInsideOwnBackup`
   * (#333).
   */
  /**
   * Is this file inside the backup directory HackMyAgent uses for this tree?
   *
   * #341 — this replaces a chain of six guards that each described the backup
   * directory with a value the scanned tree could write. The last of them gated
   * a case-folded NAME match on the directory holding a `.manifest.json` — never
   * opened, never parsed, an `fs.stat().isFile()` on a file in the tree being
   * judged. `printf '{}' > …/.manifest.json` restored the harm #331 had just
   * measured: a credential `--fix` would have redacted, left in plaintext. And
   * the exact-name half required no evidence at all, so it left the same
   * credential in plaintext with no forgery at all.
   *
   * The question is asked of the FILESYSTEM instead. `resolveArchiveBase` is a
   * path HackMyAgent derives from the target the user named; the ancestor walk
   * compares `dev`+`ino`, so no spelling — case, Unicode fold, symlink, `..` —
   * changes the answer, and there is no per-spelling rule left to bypass.
   *
   * Three-valued for the same reason `isInsideOwnBackup` is (#333): the caller
   * is a write gate, "no" there AUTHORISES the write, and an ancestor the
   * filesystem would not describe proves nothing in either direction.
   *
   * Memoized per DIRECTORY. The answer is a property of the directory, every
   * file in one shares it, and the walk consults the cache for ancestors — so a
   * scan costs about one `stat` per directory rather than one per file.
   */
  private async isInsideArchiveBase(
    absPath: string,
    targetDir: string,
  ): Promise<'yes' | 'no' | 'unknown'> {
    let base = this.archiveBases.get(targetDir);
    if (base === undefined) {
      base = await resolveArchiveBase(targetDir);
      this.archiveBases.set(targetDir, base);
    }
    // A base HackMyAgent could not resolve leaves the question OPEN. "No base
    // here" would authorise the write, which is the direction that rewrites a
    // previous run's backup.
    if (base.kind === 'unknown') return 'unknown';
    if (base.kind === 'none') return 'no';
    let dir = path.dirname(path.resolve(absPath));
    const asked: string[] = [];
    let answer: 'yes' | 'no' | 'unknown' = 'no';
    // Bounded for the same reason the identity walk is: a path more than 64
    // components deep is not something to keep stat-ing.
    for (let i = 0; i < 64; i++) {
      const cached = this.archiveDirAnswers.get(dir);
      if (cached) { answer = cached; break; }
      asked.push(dir);
      // A lexical hit is a sound POSITIVE — same spelling, same directory — and
      // it is the common case for a real archive, so the syscall is spent only
      // when the cheap compare says no.
      if (this.isPathWithinDirectory(dir, base.real) || dir === base.real) { answer = 'yes'; break; }
      const probe = await identityOf(dir);
      if (sameIdentity(identityOrUndefined(probe), base.ident)) { answer = 'yes'; break; }
      if (probe.kind === 'unknown') { answer = 'unknown'; break; }
      const parent = path.dirname(dir);
      if (parent === dir) break; // filesystem root, and it is not the base
      dir = parent;
    }
    // Only a settled answer is memoized for the whole chain: a 'yes' or a 'no'
    // holds for every directory asked on the way, an 'unknown' holds only for
    // the level that could not be read.
    if (answer !== 'unknown') for (const d of asked) this.archiveDirAnswers.set(d, answer);
    return answer;
  }

  /**
   * Does this path run through a directory that IS what
   * `<its parent>/.hackmyagent-backup` resolves to, below the scanned tree?
   *
   * Only ever used to add a sentence of advice (see `applyFixWrite`). It gates
   * nothing, suppresses nothing and deletes nothing.
   *
   * It used to compare the ancestor NAMES against `.hackmyagent-backup`
   * exactly, and the two halves of that were wrong in opposite directions.
   *
   * It fired where there is no nested project. `vendor/.hackmyagent-backup/`
   * `lib/config/production.json` carries the exact lowercase name, and the note
   * then told the user their file sat in "a `.hackmyagent-backup` directory
   * belonging to a project nested under the one you scanned" — a claim about
   * the tree that nothing had established. The reasoning that an exact name
   * avoids a false claim was simply wrong: an exact name is the easiest of all
   * the spellings for a vendored tree to carry.
   *
   * And it was SILENT on the case it exists for. On a case-insensitive
   * filesystem, a base created as `.HACKMYAGENT-BACKUP` is adopted by `mkdir`
   * and every later run writes through that spelling — #317's scenario. The
   * exact compare misses it, so a real nested project got no disclosure at all,
   * and `rollback <child>` there restores the redaction over the redaction and
   * reports success. That half is invisible on Linux CI, where the two names
   * are two directories.
   *
   * So it asks the filesystem instead: for each ancestor `A`, is `A` the same
   * directory as `<dirname(A)>/.hackmyagent-backup`, by `dev`+`ino` through
   * `realpath.native`? On a case-insensitive filesystem `.HACKMYAGENT-BACKUP`
   * answers yes, and on a case-sensitive one it answers no because there it
   * really is a different directory that no HackMyAgent run writes.
   *
   * What identity CANNOT establish is that a project is there — the vendor
   * directory is also, truthfully, what that name resolves to. Nothing short of
   * opening files in the scanned tree could, and a claim resting on those is
   * forgeable by whoever wrote them, which is the class this stack spent six
   * rounds removing. So the finding no longer asserts it: it says what was
   * observed and makes the consequence conditional. See the guidance in
   * `FIX-FOREIGN-ARCHIVE`.
   */
  private async resolvesToANestedArchive(absPath: string, targetDir: string): Promise<boolean> {
    const rel = path.relative(targetDir, absPath);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return false;

    let dir = path.dirname(path.resolve(absPath));
    const targetResolved = path.resolve(targetDir);
    // Bounded like every other ancestor walk here: a path more than 64
    // components deep is not something to keep stat-ing.
    for (let i = 0; i < 64 && dir !== targetResolved; i++) {
      const cached = this.nestedArchiveDirs.get(dir);
      const answer = cached ?? await this.isBackupBaseByIdentity(dir);
      this.nestedArchiveDirs.set(dir, answer);
      if (answer) return true;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return false;
  }

  /**
   * Is `dir` the directory `<dirname(dir)>/.hackmyagent-backup` reaches?
   *
   * THREE-VALUED, and the direction is the opposite of the one every other
   * probe in this file takes — deliberately, because the consequence is.
   *
   * Only ENOENT proves the answer is no: nothing is named `.hackmyagent-backup`
   * beside this directory, so this directory is not it. Every other errno
   * establishes nothing, and the two mistakes do not cost the same. Saying
   * nothing when the answer was yes is D5 — a nested project whose `rollback`
   * now restores a redaction over a redaction and reports success, with no line
   * anywhere. Saying something when the answer was no costs one conditional
   * sentence in a report, and the sentence already names the condition.
   *
   * So an unreadable probe fires the note. This is the same reasoning as the
   * retention rule — "anything the filesystem declines to answer counts as
   * holding a copy, because the cost of being wrong in that direction is the
   * user's last bytes" — pointed at a different asymmetry, and NOT the same
   * conclusion, which is why it is written out rather than copied.
   *
   * Rare in practice: reaching this at all means HackMyAgent is fixing a file
   * inside `dir`, so `dir` and its parent are already traversable.
   */
  private async isBackupBaseByIdentity(dir: string): Promise<boolean> {
    const canonical = path.join(path.dirname(dir), BACKUP_DIR_NAME);
    let canonicalReal: string;
    try {
      // `realpath.native` for the reason #334 established: on macOS the JS
      // implementation returns the spelling it was GIVEN, so it cannot tell a
      // case-variant apart, while the native one returns the spelling on disk.
      canonicalReal = fsSync.realpathSync.native(canonical);
    } catch (err) {
      return (err as NodeJS.ErrnoException)?.code !== 'ENOENT';
    }
    const [here, there] = await Promise.all([identityOf(dir), identityOf(canonicalReal)]);
    if (here.kind === 'unknown' || there.kind === 'unknown') return true;
    return sameIdentity(identityOrUndefined(here), identityOrUndefined(there));
  }

  /**
   * The scanned file's own bytes, for recovering a citation line at the
   * semantic → SecurityFinding boundary (#368).
   *
   * `file` is target-relative as the semantic engine reports it. Returns
   * undefined on any read failure — a finding with no line is the honest
   * outcome, and a throw here would take out the whole Layer 2 conversion.
   */
  private readArtifactForCitation(targetDir: string, file: string): string | undefined {
    try {
      return fsSync.readFileSync(path.resolve(targetDir, file), 'utf-8');
    } catch {
      return undefined;
    }
  }

  private async isOwnBackupDir(dirPath: string): Promise<boolean> {
    const ctx = this.backupContext;
    if (!ctx) return false;
    // A lexical hit is a sound POSITIVE — same spelling, same directory. It is
    // only the NEGATIVE that cannot be trusted, so the syscall is spent only
    // when the cheap compare says no.
    if (this.isPathWithinDirectory(dirPath, ctx.backupDir)) return true;
    return sameIdentity(identityOrUndefined(await identityOf(dirPath)), ctx.backupIdent);
  }

  /**
   * True only when nothing exists at `filePath` — proven, not inferred.
   *
   * This is the sole evidence that a fix write is a CREATION rather than an
   * overwrite, and `recordCreatedFiles` turns that classification into a
   * rollback-time `unlink`. So it fails safe in every unclear direction: an
   * entry that exists is not a creation, and an `lstat` that fails for any
   * other reason (EACCES, ELOOP, EIO) proves nothing, so it is not a creation
   * either. `lstat` deliberately does not follow symlinks — a dangling link
   * is an entry the user put there, and deleting it at rollback would destroy
   * something HMA did not create.
   */
  private async isGenuinelyAbsent(filePath: string): Promise<boolean> {
    try {
      await fs.lstat(filePath);
      return false;
    } catch (err) {
      return (err as NodeJS.ErrnoException)?.code === 'ENOENT';
    }
  }

  /**
   * Add one path to the on-disk manifest, into `existingFiles` (rollback
   * restores it) or `absentAtBackup` (rollback may remove it once
   * `recordCreatedFiles` proves HMA generated it). Returns false if the
   * manifest cannot be read or written, which makes the write unrecoverable
   * and so must abandon it.
   */
  private async appendToBackupManifest(
    backupDir: string,
    rel: string,
    existed: boolean,
  ): Promise<boolean> {
    const manifestPath = path.join(backupDir, '.manifest.json');
    try {
      const manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
      // Write-time absences go in their OWN list. See `absentAtFixWrite`.
      const list = existed
        ? manifest.existingFiles
        : (manifest.absentAtFixWrite ??= []);
      if (!list.includes(rel)) list.push(rel);
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Take a backup for a mutation that happens OUTSIDE `scan()` (#271).
   *
   * Standalone `harden-soul` rewrites a governance file — measured at
   * 113 -> 19055 bytes — and took no backup at all, so there was nothing for
   * `rollback` to restore. `rollback` then read whatever manifest a previous
   * `secure --fix` had left and printed `[+] Rollback complete` at exit 0,
   * having never heard of the file that changed.
   *
   * Every other mutation in the product is gated on a recoverable copy. This is
   * the same guarantee for the one command that reached the filesystem without
   * going through `scan()`.
   *
   * Returns the backup directory, or null when no backup could be taken — and a
   * null must abandon the write, exactly as `scan()` skips fixing when
   * `createBackup` throws. Applying a fix with nothing to roll back to is the
   * outcome this whole mechanism exists to prevent.
   */
  async beginExternalBackup(targetDir: string): Promise<string | null> {
    try {
      const backupPath = await this.createBackup(targetDir);
      if (!this.lastBackupIdent) return null;
      this.backupContext = {
        backupDir: backupPath,
        backupIdent: this.lastBackupIdent,
        targetDir,
        covered: new Set(this.lastBackupCovered),
      };
      return backupPath;
    } catch {
      return null;
    }
  }

  /**
   * The guard `secure --fix` hands to `hardenSoul` (#271).
   *
   * `harden-soul` runs AFTER `scan()` returns, from the CLI, on this same
   * instance — the run's backup context is still live, which is what lets the
   * governance write be gated by the same recoverability rule as every fix
   * write inside the scan.
   *
   * Returns false when no recoverable copy could be made, and `hardenSoul` then
   * declines the write rather than modifying a file `rollback` cannot put back.
   * Before this, `BACKUP_FILES` carried a hand-copied subset of the governance
   * names and the other eight were modified with no manifest entry at all.
   */
  async ensureGovernanceBackup(targetDir: string, relPath: string): Promise<boolean> {
    return this.ensureBackupCovers(path.join(targetDir, relPath));
  }

  /**
   * Where a fix write will actually land, or null when it must not happen.
   *
   * Returns the RESOLVED destination so every later gate and the write itself
   * agree on one path. A refusal is recorded in `fixWriteFailures` with its own
   * cause, so the user is told the fix did not land and why — an unfixed
   * finding whose remedy is the command that just silently declined is the
   * outcome #327 spent a round removing.
   *
   * With no backup context there is no tree to contain against and nothing has
   * made a recoverable copy, so the path is handed back unchanged and
   * `ensureBackupCovers` refuses it below under BACKUP-UNCOVERED. That is the
   * pre-existing behaviour for that case and this must not quietly restate it
   * as a containment failure.
   */
  private async resolveFixWriteTarget(requestedPath: string): Promise<string | null> {
    const ctx = this.backupContext;
    if (!ctx) return requestedPath;

    const rel = this.toTargetRelativePath(requestedPath, ctx.targetDir);
    if (rel === null) {
      this.fixWriteFailures.push({
        file: requestedPath,
        code: 'FIX-WRITE-ESCAPES-TREE',
        message: 'not written: its path points outside the scanned directory',
      });
      return null;
    }

    let targetReal: string;
    try {
      targetReal = await fs.realpath(ctx.targetDir);
    } catch {
      this.fixWriteFailures.push({
        file: requestedPath,
        code: 'FIX-WRITE-TARGET-UNRESOLVABLE',
        message: 'not written: the scanned directory could not be resolved, so '
          + 'HackMyAgent cannot tell whether this write would stay inside it',
      });
      return null;
    }

    const dest = await containResolveInsideTree(targetReal, rel, { followLeafLink: true });
    if (!dest.ok) {
      this.fixWriteFailures.push({
        file: requestedPath,
        code: 'FIX-WRITE-UNCONTAINED',
        message: `not written: ${describeResolveRefusal(dest.cause)}`,
      });
      return null;
    }

    // Decide on REAL paths, hand back the caller's SPELLING.
    //
    // `dest.path` is anchored on `realpath(targetDir)` while everything
    // downstream — `ensureBackupCovers`, `toTargetRelativePath`, the manifest
    // key, `isInsideArchiveBase` — is anchored on `ctx.targetDir` as the caller
    // spelled it. Returning the resolved path directly mixes the two frames,
    // and on any host where the scan root has a symlinked ancestor the two
    // disagree for every file. macOS is that host by default: `/var` is a link
    // to `/private/var`, so a scan under `mkdtemp()` produced
    // `path.relative('/var/…/repo', '/private/var/…/repo/shared/x')` =
    // `../../../../../../private/var/…`, which reads as an escape, and every
    // fix write in a temp tree was refused as BACKUP-UNCOVERED.
    //
    // Re-anchoring is safe precisely because the containment DECISION was
    // already made above, on resolved paths: `targetReal` and `ctx.targetDir`
    // name the same directory, so the two spellings name the same file. This
    // returns where to write, not whether to.
    const relFromReal = path.relative(targetReal, dest.path);
    return relFromReal ? path.join(ctx.targetDir, relFromReal) : ctx.targetDir;
  }

  /**
   * Apply a fix write. Returns whether it landed; never throws.
   *
   * Every auto-fix write used to be a bare `await fs.writeFile` sitting
   * inside the same `try` as its own `findings.push`, under a `catch` that
   * exists to mean "this config file isn't here". So an unwritable target —
   * immutable flag, read-only mount, EPERM, a restrictive MAC policy — threw
   * past the push, and the finding was never created at all. Not downgraded,
   * not marked unverified: absent. The scan then scored as though the issue
   * had never been detected, which is strictly worse than never running the
   * fix. Measured on an MCP project with an unwritable `mcp.json`: `secure`
   * reports `MCP-001` HIGH at 69/100 clamped, `secure --fix` reported
   * 100/100 with no finding and the root-scoped config still on disk.
   *
   * Returning a boolean instead of throwing keeps the failure local to the
   * fix and lets the check report what is actually true: the issue is still
   * there, and the fix did not land.
   */
  private async applyFixWrite(requestedPath: string, content: string): Promise<boolean> {
    // #270 — CONTAIN THE DESTINATION FIRST, and act on what comes back.
    //
    // Everything below this block — the archive identity probes, the backup
    // coverage guarantee, the write itself — used to operate on the caller's
    // spelling. `toTargetRelativePath` is purely lexical, so a symlinked leaf
    // sitting inside the tree passed every one of those gates and `fs.writeFile`
    // then followed it wherever it pointed. Measured on merged main: a repo
    // shipping `.gitignore -> ../shared.gitignore` had the out-of-tree file
    // rewritten 21 -> 85 bytes, exit 0, "Fixed 1 issue (1 verified)".
    //
    // `rollback` has refused to restore through a link that leaves the tree
    // since #351. The write side following one anywhere was the asymmetry, so
    // both sides now ask `resolveInsideTree` the same question with the same
    // `followLeafLink: true` semantics: follow an in-tree link (an ordinary
    // dotfile-sharing layout, which #327 established must keep working), refuse
    // one that leaves.
    //
    // Resolving BEFORE the gates rather than after is deliberate. A link is a
    // way to make a path be spelled one thing and mean another, and every gate
    // below decides something about what the write will HIT — so each one has to
    // see the destination, not the spelling. Resolving after would re-open
    // #304's defect (the guard protected a path that was not the one written) in
    // a new place.
    const filePath = await this.resolveFixWriteTarget(requestedPath);
    if (filePath === null) return false;

    // #314 — never rewrite a backup archive, HMA's own or a previous run's.
    // #300/#304 gate RECOVERABILITY: they guarantee a copy exists before a
    // write. They do not stop `--fix` from redacting the archive the user
    // RESTORES from, and once #309 stopped excluding archives from detection
    // this became reachable for every prior run's backup. Refusing is
    // fail-safe, so this may key on the directory name.
    //
    // #317 — the name test is anchored on `ctx.targetDir`, so it answers "is
    // this an archive inside the scanned tree". The run's OWN backup is also
    // asked about by identity, because the two are not the same question: the
    // name test needs `filePath` and `targetDir` to be spelled compatibly, and
    // trusting that they are is how the last four rounds started.
    //
    // #341 — the archive half no longer walks the path's SEGMENTS looking for a
    // name. It asks whether the file is inside the backup directory this tree
    // uses, decided by identity. That covers a previous run's backup, this run's
    // own, and every respelling of either, and it stops recognising directories
    // that merely carry the name — which is what left a
    // `vendor/.hackmyagent-backup/lib/…` credential in plaintext.
    const ctx = this.backupContext;
    const ownBackup = ctx ? await this.isInsideOwnBackup(filePath) : 'no';
    const inArchive = ctx ? await this.isInsideArchiveBase(filePath, ctx.targetDir) : 'no';
    // #341, second-order — a write that lands inside ANOTHER tree's backup is
    // allowed (this run has already made a recoverable copy), but it degrades
    // that tree's own rollback: `rollback <child>` will restore the redaction
    // over the redaction and report success. The bytes are recoverable only
    // through `rollback <this target>`, and nothing said so — the disclosure
    // lived in a changelog sentence, which is not a place a user looks.
    //
    // Decided by IDENTITY, not by a name. It gates no decision, so the cost of
    // recognising one directory too many is a sentence of advice, while the cost
    // of recognising one too few is a silent false "Rollback complete" in a tree
    // the user thinks they can recover — and an exact-name test got BOTH wrong,
    // firing on a vendored directory carrying the name and missing a real
    // nested base spelled `.HACKMYAGENT-BACKUP` on a case-insensitive disk.
    if (ctx && inArchive === 'no' && await this.resolvesToANestedArchive(filePath, ctx.targetDir)) {
      this.fixWritesIntoForeignArchive.push(filePath);
    }
    if (ownBackup === 'yes' || inArchive === 'yes') {
      this.fixWriteFailures.push({
        file: filePath,
        code: 'BACKUP-ARCHIVE',
        message: 'not written: this is a backup archive, and rewriting it would '
          + 'destroy the copy rollback restores from',
      });
      return false;
    }
    // #333 — an identity probe that FAILED is not a "no". The write gate is the
    // one caller for which "not our backup" authorises the write, so an
    // ancestor the filesystem would not describe has to stop it, with its own
    // cause rather than under a claim about a backup archive nobody established.
    if (ownBackup === 'unknown' || inArchive === 'unknown') {
      this.fixWriteFailures.push({
        file: filePath,
        code: 'BACKUP-IDENTITY-UNKNOWN',
        message: 'not written: a directory above this path could not be examined, so '
          + 'HackMyAgent cannot rule out that this is its own backup',
      });
      return false;
    }
    // #300 — a write the backup cannot undo is not a fix, it is data loss.
    // Reported through the same channel as a filesystem refusal, because to
    // the user it is the same outcome: the issue is still there and the fix
    // did not land.
    if (!(await this.ensureBackupCovers(filePath))) {
      this.fixWriteFailures.push({
        file: filePath,
        code: 'BACKUP-UNCOVERED',
        message: 'not written: no recoverable backup copy could be made for this path',
      });
      return false;
    }
    try {
      await fs.writeFile(filePath, content);
      // Recorded regardless of whether any finding names this path, so
      // `recordCreatedFiles` can decide what was GENERATED without relying
      // on finding attribution.
      this.fixWritePaths.push(filePath);
      return true;
    } catch (err) {
      // Recorded, not swallowed. Returning a bare `false` made these sites
      // quieter than the gateway path they were modelled on: the user saw an
      // ordinary unfixed finding whose remedy was `secure --fix` — the
      // command that had just silently failed — with no way to tell "never
      // attempted" from "attempted and the filesystem refused". `scan()`
      // turns this list into one FIX-WRITE-FAILED finding.
      const e = err as NodeJS.ErrnoException;
      this.fixWriteFailures.push({
        file: filePath,
        code: e?.code || (err instanceof Error ? err.name : 'UnknownError'),
        message: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  private async checkFilePermissions(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Files that should have restricted permissions
    const sensitiveFiles = [
      'secrets.json',
      '.env',
      '.env.local',
      'credentials.json',
      'auth.json',
    ];

    const permissionIssues: string[] = [];

    for (const filename of sensitiveFiles) {
      const filePath = path.join(targetDir, filename);
      try {
        const stats = await fs.stat(filePath);
        const mode = stats.mode & 0o777;

        // Check if world-readable (others have read permission)
        if (mode & 0o004) {
          permissionIssues.push(filename);

          if (autoFix) {
            // Routed through the failure recorder like every other mutation.
            // A thrown chmod (immutable flag, restrictive policy) was swallowed
            // by the enclosing `catch`, so the finding still reported
            // `fixed: true` with "Changed permissions to 600" on a file that
            // was still world-readable, and nothing anywhere said the write
            // had failed.
            //
            // #270 — contained like every other mutation. `chmod` follows
            // symlinks, so `secrets.json -> ~/.ssh/id_rsa` in a scanned repo
            // re-moded a file outside the tree. This is the same class as the
            // fix writes and it is not reached through `applyFixWrite`, so the
            // sweep has to name it explicitly rather than assume the chokepoint
            // covers everything that mutates the filesystem.
            const modePath = await this.resolveFixWriteTarget(filePath);
            if (modePath !== null) {
              try {
                await fs.chmod(modePath, 0o600);
              } catch (err) {
                const e = err as NodeJS.ErrnoException;
                this.fixWriteFailures.push({
                  file: filePath,
                  code: e?.code || (err instanceof Error ? err.name : 'UnknownError'),
                  message: err instanceof Error ? err.message : String(err),
                });
              }
            }
          }
        }
      } catch {
        // File doesn't exist, skip
      }
    }

    const passed = permissionIssues.length === 0;
    findings.push({
      checkId: 'PERM-001',
      name: 'Sensitive File Permissions',
      description: 'Sensitive files have overly permissive permissions',
      category: 'permissions',
      severity: 'high',
      passed,
      message: passed
        ? 'All sensitive files have appropriate permissions'
        : `Files with overly permissive permissions: ${permissionIssues.join(', ')}`,
      // `file` makes the failing finding survive the user-facing
      // concrete-findings filter (#250).
      file: passed ? undefined : permissionIssues[0],
      fixable: true,
      fixed: autoFix && !passed,
      fix: passed ? undefined : `${this.cliName} secure --fix`,
      // Cited instead of `fix` when the chmod above was swallowed (immutable
      // flag, read-only mount, restrictive MAC policy) and verification
      // proved the file is still world-readable. Names only the files that
      // are still failing, because the re-scan recomputes this list.
      manualFix: passed ? undefined : chmodFix(permissionIssues),
      fixMessage: autoFix && !passed ? 'Changed permissions to 600' : undefined,
      details: passed ? undefined : { files: permissionIssues },
      guidance: 'Overly broad file permissions let any user on the system read sensitive config files that may contain credentials or API keys.',
    });

    return findings;
  }

  private async checkGitSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Existence-aware severity (#250): a missing or incomplete .gitignore
    // is a LOW hardening advisory on its own; it becomes a HIGH exposure
    // only when a file matching an uncovered pattern actually exists.
    // `walkComplete=false` means the walk could not prove absence (deep
    // or unreadable tree), so we must not downgrade to LOW on an empty
    // result — that would recreate the silent-miss the adversarial
    // review caught.
    const { keyFiles, namedSensitive, complete: walkComplete } =
      await this.collectSensitiveArtifacts(targetDir);

    // GIT-001: Check for missing .gitignore
    const gitignorePath = path.join(targetDir, '.gitignore');
    let gitignoreExists = false;
    let gitignoreContent = '';

    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
      gitignoreExists = true;
    } catch {}

    // Default .gitignore content
    const defaultGitignore = `# Secrets and credentials
.env
.env.*
secrets.json
credentials.json
*.pem
*.key

# IDE
.idea/
.vscode/

# Dependencies
node_modules/

# Build
dist/
`;

    let git001Fixed = false;
    if (!gitignoreExists && autoFix) {
      git001Fixed = await this.applyFixWrite(gitignorePath, defaultGitignore);
      if (git001Fixed) {
        gitignoreContent = defaultGitignore;
        gitignoreExists = true;
      }
    }

    // Only report if .gitignore is missing.
    // Severity is existence-aware (#250): LOW as a pure hardening
    // advisory, HIGH when sensitive files are actually present with
    // nothing ignoring them. Un-ignored .env exposure stays owned by
    // GIT-003 (content-calibrated), so it does not escalate GIT-001.
    if (!gitignoreExists || git001Fixed) {
      const presentSensitive = [...keyFiles, ...namedSensitive];
      // HIGH when a sensitive file is actually present, OR when the walk
      // could not prove absence (fail-safe): a missing .gitignore over an
      // unverifiable tree is treated as exposure, not hygiene advice.
      const git001Exposed = presentSensitive.length > 0 || !walkComplete;
      const git001Named = presentSensitive.slice(0, 3).join(', ');
      findings.push({
        checkId: 'GIT-001',
        name: 'Missing .gitignore',
        description: presentSensitive.length > 0
          ? `No .gitignore and sensitive files present: ${git001Named}${presentSensitive.length > 3 ? ` (+${presentSensitive.length - 3} more)` : ''}`
          : git001Exposed
            ? 'No .gitignore and the project tree could not be fully scanned for sensitive files'
            : 'No .gitignore file to prevent accidental commits',
        category: 'git',
        severity: git001Exposed ? 'high' : 'low',
        passed: git001Fixed,
        message: 'Create .gitignore to protect sensitive files',
        file: '.gitignore',
        fixable: true,
        fixed: git001Fixed,
        fix: `${this.cliName} secure --fix`,
        details: presentSensitive.length > 0 ? { files: presentSensitive } : undefined,
        guidance: presentSensitive.length > 0
          ? `Sensitive files (${git001Named}) exist in this project with no .gitignore — a single git add . commits them. Create a .gitignore now; if any were already committed, rotate them and run git rm --cached on each.`
          : git001Exposed
            ? 'This project has no .gitignore and its tree is too large or partly unreadable to fully verify no keys or secrets files are present. Add a .gitignore covering .env, secrets.json, *.pem, *.key and confirm no such files are tracked.'
            : 'Without .gitignore, sensitive files (.env, secrets.json, *.pem, *.key) can be accidentally committed to version control and exposed.',
      });
    }

    // GIT-002: Check for missing sensitive patterns in .gitignore
    // Only check if .gitignore exists — GIT-001 handles creation
    if (gitignoreExists) {
      const sensitivePatterns = ['.env', 'secrets.json', '*.pem', '*.key'];
      const missingPatterns: string[] = [];

      // Line-aware presence check (#250): a comment or substring mention
      // of a pattern no longer counts as covering it.
      for (const pattern of sensitivePatterns) {
        if (!this.gitignorePatternCovered(pattern, gitignoreContent)) {
          missingPatterns.push(pattern);
        }
      }

      let git002Fixed = false;
      if (missingPatterns.length > 0 && autoFix) {
        const patternsToAdd = '\n# Security patterns (auto-added)\n' + missingPatterns.join('\n') + '\n';
        const git002Content = gitignoreContent + patternsToAdd;
        git002Fixed = await this.applyFixWrite(gitignorePath, git002Content);
        if (git002Fixed) gitignoreContent = git002Content;
      }

      // Exposure is computed authoritatively (git check-ignore) over ALL
      // present sensitive files — NOT gated on the textual missingPatterns
      // list — so a file that a catch-all `*` "covers" textually but a
      // negation re-includes is still caught (#250 adversarial reviews).
      // Un-ignored .env exposure stays owned by GIT-003, so .env-basename
      // files are excluded here.
      const presentSensitive = [
        ...keyFiles,
        ...namedSensitive.filter((f) => {
          const b = path.basename(f);
          return b === 'secrets.json' || b === 'credentials.json';
        }),
      ];
      const exposedFiles = await this.committableSensitiveFiles(
        targetDir,
        presentSensitive,
        gitignoreContent,
      );

      // Fire when the gitignore is missing hygiene patterns OR a present
      // sensitive file is actually committable.
      if (missingPatterns.length > 0 || exposedFiles.length > 0) {
        // Escalate to HIGH when a committable file is present, OR when the
        // walk could not prove absence for a key/secrets pattern (fail-safe).
        const nonEnvMissing = missingPatterns.some((p) => p !== '.env');
        const git002Exposed = exposedFiles.length > 0;
        const git002Unverifiable = !git002Exposed && !walkComplete && nonEnvMissing;
        const git002High = git002Exposed || git002Unverifiable;
        const missingLabel = missingPatterns.length > 0 ? missingPatterns.join(', ') : '(patterns present)';

        findings.push({
          checkId: 'GIT-002',
          name: 'Incomplete .gitignore',
          description: git002Exposed
            ? `Committable sensitive files present: ${exposedFiles.slice(0, 3).join(', ')}${exposedFiles.length > 3 ? ` (+${exposedFiles.length - 3} more)` : ''}`
            : git002Unverifiable
              ? `Missing: ${missingLabel} (project tree could not be fully scanned to confirm no matching files exist)`
              : `Missing: ${missingLabel} (no committable matching files found)`,
          category: 'git',
          severity: git002High ? 'high' : 'low',
          passed: git002Fixed,
          message: missingPatterns.length > 0 ? `Add patterns: ${missingPatterns.join(', ')}` : 'Ignore or remove the committable sensitive files',
          file: '.gitignore',
          fixable: true,
          fixed: git002Fixed,
          fix: `${this.cliName} secure --fix`,
          details: git002Exposed ? { files: exposedFiles } : undefined,
          guidance: git002Exposed
            ? `These sensitive files are not git-ignored and would be committed by a single git add . (${exposedFiles.slice(0, 3).join(', ')}). Ignore them; if any was already committed, rotate its contents and run git rm --cached on it.`
            : git002Unverifiable
              ? `The .gitignore is missing ${missingLabel} and the project tree is too large or partly unreadable to confirm no matching key or secrets files exist. Add the patterns and verify no such files are tracked.`
              : `No committable files match the missing patterns yet, but adding them now (${missingLabel}) means a future key or secrets file is never committed by accident.`,
        });
      }
    }

    // GIT-003: Check if .env exists but not in .gitignore
    let envExists = false;
    try {
      await fs.access(path.join(targetDir, '.env'));
      envExists = true;
    } catch {}

    // Re-read gitignore in case we modified it
    try {
      gitignoreContent = await fs.readFile(gitignorePath, 'utf-8');
    } catch {}

    // Authoritative committability (#250 adversarial reviews): a comment,
    // substring mention, root-anchored/dir-only rule, or a `.env.*`-only
    // rule no longer wrongly counts as ignoring `.env`. git check-ignore
    // decides in a git repo; the heuristic backstops non-git targets.
    const envAtRisk =
      envExists && (await this.committableSensitiveFiles(targetDir, ['.env'], gitignoreContent)).length > 0;

    let git003Fixed = false;
    if (envAtRisk && autoFix) {
      const git003Content = gitignoreContent + '\n.env\n';
      git003Fixed = await this.applyFixWrite(gitignorePath, git003Content);
      if (git003Fixed) gitignoreContent = git003Content;
    }

    // Only report if .env is at risk
    if (envAtRisk) {
      // GIT-003 severity is calibrated by content, not mere presence (#242).
      // An un-ignored `.env` that actually holds a secret is real exposure
      // (CRITICAL — floors the downstream opena2a composite); a secret-less
      // `.env` (config-only, e.g. PORT=3000) is preventive hygiene (HIGH).
      // The guidance is conditional too — we don't claim "contains API keys"
      // when the file demonstrably does not.
      let envContent = '';
      try {
        envContent = await fs.readFile(path.join(targetDir, '.env'), 'utf-8');
      } catch {}
      const hasSecrets = envBodyContainsSecrets(envContent);

      findings.push({
        checkId: 'GIT-003',
        name: '.env Not Ignored',
        description: hasSecrets
          ? '.env contains secret-like values but is not in .gitignore - credentials may be committed'
          : '.env exists but not in .gitignore - secrets added later may be committed',
        category: 'git',
        severity: hasSecrets ? 'critical' : 'high',
        passed: git003Fixed,
        message: 'Add .env to .gitignore',
        file: '.env',
        fixable: true,
        fixed: git003Fixed,
        fix: `${this.cliName} secure --fix`,
        guidance: hasSecrets
          ? '.env contains API keys or secrets. Without .gitignore protection, a single git add . can expose all credentials in your repository history.'
          : 'No secrets detected in this .env yet, but .env files are where credentials accumulate. Add .env to .gitignore now so a future key is never committed by accident.',
      });
    }

    return findings;
  }

  private async checkNetworkSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    let mcpContent = '';
    try {
      mcpContent = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(mcpContent);
    } catch {}

    // NET-001: Check for servers bound to 0.0.0.0
    let boundToAllInterfaces = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg.includes('0.0.0.0'))) {
          boundToAllInterfaces = true;
          break;
        }
      }
    }

    let net001Fixed = false;
    if (boundToAllInterfaces && autoFix && mcpContent) {
      // Replace 0.0.0.0 with 127.0.0.1 in the file
      const fixedContent = mcpContent.replace(/0\.0\.0\.0/g, '127.0.0.1');
      net001Fixed = await this.applyFixWrite(mcpConfigPath, fixedContent);
    }

    // Only report if bound to 0.0.0.0
    if (boundToAllInterfaces) {
      findings.push({
        checkId: 'NET-001',
        name: 'Server Bound to All Interfaces',
        description: 'Server bound to 0.0.0.0 - accessible from any network',
        category: 'network',
        severity: 'critical',
        passed: net001Fixed,
        message: 'Change 0.0.0.0 to 127.0.0.1',
        file: 'mcp.json',
        fixable: true,
        fixed: net001Fixed,
        fix: `${this.cliName} secure --fix`,
        guidance: 'Binding to 0.0.0.0 exposes the server to the entire network. Use 127.0.0.1 for local-only access. If remote access is needed, use a reverse proxy with authentication.',
      });
    }

    // NET-002: Check for remote MCP servers without TLS
    let hasInsecureRemote = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { url?: string }>)) {
        if (server.url && server.url.startsWith('http://')) {
          hasInsecureRemote = true;
          break;
        }
      }
    }

    // Only report if insecure remote found
    if (hasInsecureRemote) {
      findings.push({
        checkId: 'NET-002',
        name: 'Remote MCP Without TLS',
        description: 'Remote server using HTTP instead of HTTPS',
        category: 'network',
        severity: 'high',
        passed: false,
        message: 'Change http:// to https://',
        file: 'mcp.json',
        fixable: false,
        fix: 'Update URL to https:// in mcp.json',
        guidance: 'HTTP traffic is unencrypted and vulnerable to man-in-the-middle attacks. An attacker on the network can intercept and modify MCP server communications.',
      });
    }

    return findings;
  }

  private async checkMcpAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // Credential patterns with their env var names for auto-fix (stricter patterns to reduce false positives)
    const credPatterns = [
      { name: 'ANTHROPIC_API_KEY', pattern: /sk-ant-api\d{2}-[a-zA-Z0-9_-]{20,}/, envVar: 'ANTHROPIC_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-proj-[a-zA-Z0-9]{20,}/, envVar: 'OPENAI_API_KEY' },
      { name: 'OPENAI_API_KEY', pattern: /sk-[a-zA-Z0-9]{48,}/, envVar: 'OPENAI_API_KEY' },
      { name: 'GITHUB_TOKEN', pattern: /ghp_[a-zA-Z0-9]{36}/, envVar: 'GITHUB_TOKEN' },
      { name: 'GITHUB_TOKEN', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/, envVar: 'GITHUB_TOKEN' },
      { name: 'GOOGLE_API_KEY', pattern: /AIza[0-9A-Za-z_-]{35}/, envVar: 'GOOGLE_API_KEY' },
      { name: 'STRIPE_KEY', pattern: /sk_live_[0-9a-zA-Z]{24,}/, envVar: 'STRIPE_SECRET_KEY' },
      { name: 'SLACK_TOKEN', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/, envVar: 'SLACK_TOKEN' },
      { name: 'SENDGRID_KEY', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/, envVar: 'SENDGRID_API_KEY' },
    ];

    // MCP-003: Check for secrets in env vars
    let hasHardcodedSecrets = false;
    let mcp003Fixed = false;

    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { env?: Record<string, string> }>)) {
        if (server.env) {
          for (const [key, value] of Object.entries(server.env)) {
            // Check if value is a hardcoded secret (not a reference).
            // #281 — the guard was `!value.includes('${')`, looser even than
            // CRED-001's: ANY value containing `${` anywhere was exempt, so
            // `"sk-ant-api03-<live> ${X}"` passed clean. Now each candidate
            // match is tested for whether it sits outside a well-formed
            // reference.
            if (typeof value === 'string') {
              for (const { pattern, envVar } of credPatterns) {
                if (hasCredentialOutsideEnvRef(value, pattern)) {
                  hasHardcodedSecrets = true;

                  if (autoFix) {
                    // Replace with env var reference
                    server.env[key] = '${' + envVar + '}';
                    mcp003Fixed = true;
                  }
                  break;
                }
              }
            }
          }
        }
      }

      // Save fixed config
      if (mcp003Fixed) {
        mcp003Fixed = await this.applyFixWrite(mcpConfigPath, JSON.stringify(mcpConfig, null, 2));
      }
    }

    // Only report if hardcoded secrets found
    if (hasHardcodedSecrets) {
      findings.push({
        checkId: 'MCP-003',
        name: 'Hardcoded Secrets in MCP',
        description: 'Secrets found in MCP env vars',
        category: 'mcp',
        severity: 'critical',
        passed: mcp003Fixed,
        message: 'Use ${ENV_VAR} references instead',
        file: 'mcp.json',
        fixable: true,
        fixed: mcp003Fixed,
        fix: `${this.cliName} secure --fix`,
        guidance: 'Hardcoded API keys in mcp.json are exposed to anyone with repo access. Run opena2a protect . to encrypt them into a secure vault — keys are injected at runtime, never stored as plaintext.',
      });
    }

    // MCP-004: Check for default credentials
    const defaultPasswords = ['postgres', 'password', 'admin', 'root', '123456', 'default'];
    let hasDefaultCreds = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args) {
          const argsStr = server.args.join(' ').toLowerCase();
          for (const pwd of defaultPasswords) {
            if (argsStr.includes(`password`) && argsStr.includes(pwd)) {
              hasDefaultCreds = true;
              break;
            }
          }
        }
      }
    }

    // Only report if default credentials found
    if (hasDefaultCreds) {
      findings.push({
        checkId: 'MCP-004',
        name: 'Default Credentials',
        description: 'MCP server using default password',
        category: 'mcp',
        severity: 'critical',
        passed: false,
        message: 'Change to strong unique password',
        file: 'mcp.json',
        fixable: false,
        fix: 'openssl rand -base64 24',
        guidance: 'Default passwords (postgres, admin, root, etc.) are the first thing attackers try. Generate a strong random password and update mcp.json.',
      });
    }

    // MCP-005: Check for wildcard tool access
    let hasWildcardTools = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { allowedTools?: string[] }>)) {
        if (server.allowedTools?.includes('*')) {
          hasWildcardTools = true;
          break;
        }
      }
    }

    // Only report if wildcard tools found
    if (hasWildcardTools) {
      findings.push({
        checkId: 'MCP-005',
        name: 'Wildcard Tool Access',
        description: 'Server allows all tools (*)',
        category: 'mcp',
        severity: 'high',
        passed: false,
        message: 'Restrict to specific tools needed',
        file: 'mcp.json',
        fixable: false,
        fix: 'Replace "*" with specific tool names in allowedTools (e.g., ["read_file", "list_directory"])',
        guidance: 'Wildcard tool access gives the AI unrestricted capabilities. Limit to only the tools your workflow actually needs to reduce attack surface.',
      });
    }

    return findings;
  }

  private async checkClaudeAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const claudeSettingsPath = path.join(targetDir, '.claude', 'settings.json');

    // `.claude/settings.json`, parsed the way `detect` parses it (#363).
    //
    // Two ways this used to disagree with `detect` on the same file, both
    // leaving `secure` — the CI gate — as the one that missed: bare
    // `JSON.parse` choked on the `//` comments and trailing commas that Claude
    // Code itself accepts, and a prose allow entry was invisible without the
    // callback `detect` passes.
    //
    // ONE file, deliberately. A loop that also read `settings.local.json` and
    // reassigned this variable was tried and reverted: `CLAUDE-003` reads the
    // same variable, so adding a gitignored `settings.local.json` SILENCED a
    // CRITICAL `sudo` + `rm -rf` finding on `settings.json` and downgraded the
    // verdict. Covering a second file has to give each file its own read, not
    // share one slot between two checks; it is filed as its own issue rather
    // than bolted on here.
    let claudeSettings: unknown = null;
    let claudeSettingsLines: string[] = [];
    try {
      const content = await fs.readFile(claudeSettingsPath, 'utf-8');
      const parsed = parseAiConfig(content, 'settings.json');
      if (parsed !== undefined) {
        claudeSettings = parsed;
        claudeSettingsLines = content.split('\n');
      }
    } catch {}

    // CLAUDE-002: Check for overly permissive allowed commands
    //
    // #363 — this used to be `perm.includes('(*)') || perm === 'Bash(*)' || …`,
    // which misses every documented wildcard spelling but one: `Bash(*:*)` does
    // not contain the substring `(*)`, and neither do `mcp__*`, `Read(//**)`,
    // `WebFetch(domain:*)`, a bare tool name, or `defaultMode:
    // "bypassPermissions"`, which turns permissions off wholesale. `secure` is
    // the CI gate, so the command most users run was the one that missed this
    // while `detect` reported HIGH on the same file.
    //
    // It now shares ONE vocabulary with `detect` (#364,
    // `src/scanner/permission-vocabulary.ts`) so the next spelling is added
    // once and the two commands cannot disagree in direction again. The walk
    // reads permission KEYS and never descends into `deny` — a deny list is
    // supposed to be full of wildcards, and reading one as a grant is how the
    // remediation ends up telling the reader to delete `Read(*.key)`.
    const overlyPermissive = claudeSettings ? walkConfigForGrants(claudeSettings, proseAllowEntry) : undefined;

    // Only report if overly permissive
    if (overlyPermissive) {
      // The SHARED locator, not a local `indexOf`. A settings-level grant is
      // synthesised — `defaultMode: acceptEdits` is not a substring of
      // `"defaultMode": "acceptEdits"` — so a plain substring search returned
      // nothing and this rendered a HIGH with no line number at all, while
      // `detect` cited `:2` for the same file.
      findings.push({
        checkId: 'CLAUDE-002',
        name: 'Overly Permissive Permissions',
        // `entry` is raw by contract (the line locator matches it against the
        // file), so it is escaped HERE, at the point it becomes report text.
        // `reason` and `fix` arrive escaped from the vocabulary.
        // Redacted AND capped, not merely escaped. A permission entry can carry
        // a credential — `Bash(* -H "x-api-key: sk-…")` is a legal allow entry —
        // and this description lands in CI logs. It was previously the one
        // surface that skipped `redactLikelySecrets` entirely.
        description: `Settings allow unrestricted tool access: "${forFinding(overlyPermissive.entry)}" ${forFinding(overlyPermissive.reason)}`,
        category: 'claude-code',
        severity: 'high',
        passed: false,
        message: 'Scope permissions to specific paths',
        file: path.join('.claude', 'settings.json'),
        fixable: false,
        fix: forFinding(overlyPermissive.fix),
        guidance: 'Wildcard permissions give the AI unrestricted shell, read, or write access. Scope each permission to the specific commands and paths your workflow needs. Entries in the deny list are restrictions and are never reported here.',
      });
    }

    // CLAUDE-003: Check for dangerous Bash patterns
    let hasDangerousBash = false;
    const dangerousPatterns = ['rm -rf', 'rm -r', 'chmod 777', 'curl | sh', 'wget | sh', 'sudo'];
    // `permissions.allow` only. `deny` carries these same strings by design —
    // `Bash(rm -rf *)` in a deny list is the rule that STOPS the agent doing it.
    const permissions = (claudeSettings as { permissions?: { allow?: string[] } } | null)?.permissions;
    if (Array.isArray(permissions?.allow)) {
      for (const perm of permissions.allow) {
        if (typeof perm !== 'string') continue;
        if (perm.startsWith('Bash(')) {
          for (const dangerous of dangerousPatterns) {
            if (perm.includes(dangerous)) {
              hasDangerousBash = true;
              break;
            }
          }
        }
      }
    }

    // Only report if dangerous Bash patterns found
    if (hasDangerousBash) {
      findings.push({
        checkId: 'CLAUDE-003',
        name: 'Dangerous Bash Permissions',
        description: 'Allows destructive shell commands',
        category: 'claude-code',
        severity: 'critical',
        passed: false,
        message: 'Remove rm -rf, sudo, etc.',
        file: '.claude/settings.json',
        fixable: false,
        fix: 'Remove rm -rf, sudo, chmod 777 patterns from the allow list in .claude/settings.json',
        guidance: 'Allowing destructive commands means a single AI mistake can delete files, escalate privileges, or weaken permissions. Restrict to safe, reversible operations.',
      });
    }

    return findings;
  }

  private async checkCursorConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Check multiple Cursor config locations
    const cursorPaths = [
      path.join(targetDir, '.cursor', 'rules'),
      path.join(targetDir, '.cursorrules'),
    ];

    let hasCredentialsInRules = false;
    for (const cursorPath of cursorPaths) {
      try {
        const content = await fs.readFile(cursorPath, 'utf-8');
        for (const { pattern } of CREDENTIAL_PATTERNS) {
          if (pattern.test(content)) {
            hasCredentialsInRules = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'CURSOR-001',
      name: 'Cursor Rules Contain Credentials',
      description: 'Cursor configuration files contain exposed credentials',
      category: 'cursor',
      severity: 'critical',
      passed: !hasCredentialsInRules,
      message: hasCredentialsInRules
        ? 'Cursor rules contain exposed credentials'
        : 'No credentials found in Cursor rules',
      fixable: false,
      fix: hasCredentialsInRules ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'Cursor rules files are often committed to git. Credentials embedded there get pushed to remotes where anyone with repo access can extract them.',
    });

    return findings;
  }

  private async checkVscodeConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const vscodeMcpPath = path.join(targetDir, '.vscode', 'mcp.json');

    let vscodeConfig: Record<string, unknown> | null = null;
    let vscodeContent = '';
    try {
      vscodeContent = await fs.readFile(vscodeMcpPath, 'utf-8');
      vscodeConfig = JSON.parse(vscodeContent);
    } catch {}

    // VSCODE-001: Check for credentials in VSCode MCP config
    let hasCredentials = false;
    for (const { pattern } of CREDENTIAL_PATTERNS) {
      if (pattern.test(vscodeContent)) {
        hasCredentials = true;
        break;
      }
    }

    findings.push({
      checkId: 'VSCODE-001',
      name: 'VSCode MCP Config Credentials',
      description: 'VSCode MCP configuration contains exposed credentials',
      category: 'vscode',
      severity: 'critical',
      passed: !hasCredentials,
      message: hasCredentials
        ? 'VSCode MCP config contains exposed credentials'
        : 'No credentials in VSCode MCP config',
      fixable: false,
      guidance: 'MCP config files are shared across workspaces and often committed to repos. Credentials there are exposed to every tool and extension that reads the config.',
    });

    // VSCODE-002: Check for overly permissive paths
    let hasRootAccess = false;
    if (vscodeConfig?.servers) {
      for (const [, server] of Object.entries(vscodeConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg === '/' || arg === '~')) {
          hasRootAccess = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'VSCODE-002',
      name: 'VSCode MCP Root Access',
      description: 'VSCode MCP server has root or home directory access',
      category: 'vscode',
      severity: 'high',
      passed: !hasRootAccess,
      message: hasRootAccess
        ? 'VSCode MCP server has dangerous filesystem access'
        : 'VSCode MCP filesystem access is scoped',
      fixable: false,
      guidance: 'An MCP server with root or home directory access can read SSH keys, cloud credentials, and any file on the system. Scope access to the project directory only.',
    });

    return findings;
  }

  /**
   * Bounded recursive walk collecting sensitive artifacts for the
   * existence-aware git/credential checks (#250). Skips node_modules and
   * .git, never follows symlinks, and is bounded by depth and entry count
   * so a hostile tree cannot stall the scan.
   *
   * `complete` is false when the walk could NOT exhaustively verify the
   * tree — a depth or entry bound was hit with directories still
   * unvisited, or a directory was unreadable. Callers MUST NOT treat an
   * empty result from an incomplete walk as "nothing sensitive exists":
   * absence is only trustworthy when `complete` is true. This is the
   * fail-safe that stops a deep or unreadable key from silently
   * downgrading a git-hygiene finding (adversarial-review finding, #250).
   *
   * `.pem` files are content-gated: certificate-only PEM bundles (e.g. CA
   * chains) are public material and are excluded; anything carrying a
   * PRIVATE KEY block — or content we cannot positively identify as
   * certificate-only, such as binary DER — is treated as a private key
   * (fail-safe toward detection).
   *
   * Bounds are deliberately generous (depth 25, 50k entries) so that
   * real repositories walk to completion; `complete=false` is reserved
   * for genuinely pathological trees, where staying conservative costs a
   * rare false HIGH rather than a silent miss.
   */
  private async collectSensitiveArtifacts(targetDir: string): Promise<{
    keyFiles: string[];
    namedSensitive: string[];
    configFiles: string[];
    complete: boolean;
  }> {
    const keyFiles: string[] = [];
    const namedSensitive: string[] = [];
    const configFiles: string[] = [];
    const SENSITIVE_NAMES = new Set(['secrets.json', 'credentials.json']);
    const MAX_DEPTH = 25;
    const MAX_ENTRIES = 50000;
    let entries = 0;
    let complete = true;

    // A non-directory target (single-file scan, e.g. `secure SKILL.md`)
    // has no tree to walk and no place for a key to hide — that is a
    // complete result, not an unverifiable one. Only a genuinely
    // unreadable *directory* below counts as incomplete.
    try {
      const rootStat = await fs.stat(targetDir);
      if (!rootStat.isDirectory()) return { keyFiles, namedSensitive, configFiles, complete: true };
    } catch {
      return { keyFiles, namedSensitive, configFiles, complete: true };
    }

    const targetRoot = path.resolve(targetDir);

    // node_modules is skipped for cost. Each skipped node_modules dir is
    // recorded; after the walk we ask git whether it is actually ignored.
    // If any is committable, a key inside it is reachable, so the walk
    // cannot claim completeness (#250 adversarial reviews). `.git` is
    // never committable, so skipping it never affects completeness.
    const skippedNodeModules: string[] = [];

    /**
     * `insideOwnBackup` travels DOWN the recursion instead of being recomputed
     * per file. #317 made the per-file version a case-sensitive prefix compare
     * on a path string; the identity check that replaces it costs a `stat`, and
     * spending one per directory (only during a `--fix` run, since a detect-only
     * scan has no backup context) is what keeps the correct answer affordable.
     */
    const walk = async (dir: string, depth: number, insideOwnBackup: boolean): Promise<void> => {
      if (entries >= MAX_ENTRIES) {
        complete = false;
        return;
      }
      let dirents;
      try {
        dirents = await fs.readdir(dir, { withFileTypes: true });
      } catch (err) {
        // An unreadable directory (EACCES, etc.) means we cannot verify
        // its contents — a key could hide there. Do not assume clean. The
        // directory itself is a lost input of the directory kind, recorded
        // where it was discovered (#588).
        noteListFailure(dir, (err as NodeJS.ErrnoException | null)?.code);
        complete = false;
        return;
      }
      for (const dirent of dirents) {
        if (entries++ >= MAX_ENTRIES) {
          complete = false;
          return;
        }
        if (dirent.isSymbolicLink()) continue;
        const abs = path.join(dir, dirent.name);
        // Containment assertion: readdir only yields single-component
        // names (never `..`/`/`), so `abs` is always inside `targetRoot`;
        // this is belt-and-suspenders so no processing (open/read/stat)
        // ever touches a path outside the scan root even if that invariant
        // were ever violated.
        const absResolved = path.resolve(abs);
        if (absResolved !== targetRoot && !absResolved.startsWith(targetRoot + path.sep)) {
          complete = false;
          continue;
        }
        if (dirent.isDirectory()) {
          if (dirent.name === '.git') continue;
          if (dirent.name === 'node_modules') {
            skippedNodeModules.push(path.relative(targetDir, abs));
            continue;
          }
          if (depth + 1 > MAX_DEPTH) {
            // A real subtree exists below the depth bound — we did not
            // look inside it, so absence is no longer provable.
            complete = false;
            continue;
          }
          // Re-lstat before descending: guards a TOCTOU where the entry is
          // swapped for a symlink between readdir and the recursive walk,
          // which would otherwise let the scan follow a link outside the
          // tree. If it is no longer a real directory, skip it.
          try {
            const st = await fs.lstat(abs);
            if (!st.isDirectory()) continue;
          } catch (err) {
            // The dirent said directory; an `lstat` that rejects here is the
            // parent denying search, and `abs` is a directory the scan could
            // not list (#588).
            noteListFailure(abs, (err as NodeJS.ErrnoException | null)?.code);
            complete = false;
            continue;
          }
          await walk(abs, depth + 1, insideOwnBackup || (await this.isOwnBackupDir(abs)));
          continue;
        }
        if (!dirent.isFile()) continue;
        const rel = path.relative(targetDir, abs);
        if (SENSITIVE_NAMES.has(dirent.name)) namedSensitive.push(rel);
        // #292 — config-shaped files at ANY depth, not just the scan root.
        // Config-shaped by filename (`src/config.json`) or by location
        // (`config/production.json`, whose basename says nothing).
        //
        // `.hackmyagent-backup/` is excluded, and that exclusion is load-
        // bearing rather than cosmetic. It holds verbatim copies of the very
        // files this check rewrites, so descending into it made `--fix`
        // rewrite its own backups: the credential was substituted inside the
        // backup copy, `rollback` then restored the ALREADY-REDACTED content,
        // and the original was unrecoverable. It also double-counted every
        // finding (one for the live file, one for its backup). Scoped to the
        // config list rather than the whole walk so `keyFiles` /
        // `namedSensitive` semantics are untouched.
        //
        // #302 — the test is on every path segment, not on the prefix. `rel`
        // is relative to the SCAN ROOT, so `startsWith` only ever recognised
        // a backup directory sitting AT that root, and scanning one level up
        // walked straight back into it as `child/.hackmyagent-backup/…`. That
        // reopened all three consequences one directory higher, which is not
        // an exotic invocation: `secure ~/projects` over a tree where any one
        // project has been secured before.
        //
        // #305/#309 — the exclusion is now THIS RUN's own backup directory and
        // nothing else. Matching a name, or a name plus a forgeable manifest,
        // handed the scanned tree a suppression token; a pre-existing archive
        // holds a real plaintext secret and is reported. See
        // `isInsideOwnBackup`.
        //
        // #317 — and the directory is recognised by `dev`+`ino`, decided on the
        // way in by `isOwnBackupDir`, never by comparing this file's path
        // against a string.
        if (isConfigShapedFile(dirent.name, path.basename(dir)) && !insideOwnBackup) {
          configFiles.push(rel);
        }
        if (dirent.name.endsWith('.key')) {
          keyFiles.push(rel);
        } else if (dirent.name.endsWith('.pem')) {
          if (await this.pemLooksPrivate(abs, targetDir)) keyFiles.push(rel);
        }
      }
    };

    // The scan root itself is never the backup directory: `createBackup` always
    // puts it at least two levels below the target.
    await walk(targetDir, 0, false);

    // A skipped node_modules only breaks completeness if git would commit
    // a sensitive file hidden inside it. Ask git directly (ls-files over
    // real entries, honoring the full ignore stack INCLUDING negations —
    // so a `!node_modules/vendor/secret.key` re-include is caught, which a
    // synthetic path probe would miss). In a non-git target committability
    // is moot, so the skip is safe.
    if (skippedNodeModules.length > 0) {
      if (await this.hasCommittableSensitiveUnder(targetDir, skippedNodeModules)) {
        complete = false;
      }
    }

    // Deterministic order. `readdir` order is filesystem-dependent, and the
    // corpus goldens are byte-compared, so an unsorted list would make golden
    // stability a property of the host filesystem.
    configFiles.sort();

    return { keyFiles, namedSensitive, configFiles, complete };
  }

  /**
   * True when git would commit (track, or leave un-ignored) any
   * sensitive-typed file under the given directories. Uses
   * `git ls-files --cached --others --exclude-standard` so the answer
   * honors the entire ignore stack and negations over the REAL tree —
   * no synthetic paths. Tri-state error direction (#250 4th-review-of-
   * hardening): a non-git target or missing git binary means
   * committability is moot → `false` (safe skip); a git error on a real
   * invocation (timeout, maxBuffer) could NOT determine committability →
   * `true` (conservative → the caller marks the scan incomplete rather
   * than award a false clean bill). Only used for the node_modules
   * completeness backstop.
   */
  private async hasCommittableSensitiveUnder(targetDir: string, dirRels: string[]): Promise<boolean> {
    if (dirRels.length === 0) return false;
    const absTarget = path.resolve(targetDir);
    const pathspecs = dirRels.map((d) => `${d.split(path.sep).join('/')}/`);
    // null = moot (non-git / no git binary); 'UNCERTAIN' = git error we
    // must treat conservatively; string = ls-files output.
    const out = await new Promise<string | null | 'UNCERTAIN'>((resolve) => {
      let child;
      try {
        child = execFile(
          'git',
          ['-c', 'core.excludesFile=/dev/null', '-C', absTarget,
            'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', ...pathspecs],
          { timeout: 10000, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, encoding: 'utf8' },
          (err, stdout) => {
            if (!err) { resolve(String(stdout ?? '')); return; }
            const errno = (err as NodeJS.ErrnoException | null)?.code;
            const code = (err as (Error & { code?: number }) | null)?.code;
            // 128 = not a git repo; ENOENT = git binary missing → moot.
            if (code === 128 || errno === 'ENOENT') { resolve(null); return; }
            // Anything else (timeout/SIGKILL, maxBuffer, unexpected) →
            // could not determine → conservative.
            resolve('UNCERTAIN');
          },
        );
      } catch {
        // Synchronous spawn failure (e.g. git binary missing) → moot.
        resolve(null);
        return;
      }
      // No stdin for ls-files; ensure the pipe is closed. Stream errors
      // (EPIPE when git exits first) arrive as ASYNC 'error' events that
      // the try/catch cannot see — without a listener they crash the
      // process. The execFile callback above still settles the promise.
      child.stdin?.on('error', () => { /* async pipe error — settled via exit code */ });
      try { child.stdin?.end(); } catch { /* ignore */ }
    });
    if (out === null) return false;         // moot → safe skip
    if (out === 'UNCERTAIN') return true;   // fail-safe → mark incomplete
    const isSensitive = (p: string): boolean => {
      const base = path.posix.basename(p);
      return base.endsWith('.key') || base.endsWith('.pem') ||
        base === 'secrets.json' || base === 'credentials.json' ||
        base === '.env' || base.startsWith('.env.');
    };
    return out.split('\0').filter(Boolean).some(isSensitive);
  }

  /**
   * Content gate for `.pem` files. Returns false only when the content
   * is positively identified as certificate-only public material;
   * PRIVATE KEY blocks, unreadable files, oversized files, and
   * unidentifiable content (binary DER) all return true (fail-safe).
   *
   * Reads at most MAX_PEM_BYTES into a FIXED buffer (never `readFile`),
   * so memory is bounded regardless of the real on-disk size — a huge or
   * mid-scan-grown `.pem` cannot exhaust memory. A file that does not fit
   * in the cap cannot be positively cleared and is flagged. `filePath` is
   * also confined to `boundsRoot`: a resolved path escaping the scan root
   * (only reachable via a mid-scan symlink swap) is flagged, never read.
   */
  private async pemLooksPrivate(filePath: string, boundsRoot: string): Promise<boolean> {
    const MAX_PEM_BYTES = 5 * 1024 * 1024;
    const rootResolved = path.resolve(boundsRoot);
    const resolved = path.resolve(filePath);
    if (resolved !== rootResolved && !resolved.startsWith(rootResolved + path.sep)) {
      return true; // outside the scan root — do not read, treat as suspect
    }
    let fh;
    try {
      fh = await fs.open(resolved, 'r');
      // Short-circuit oversized files without reading: a `.pem` larger
      // than the cap cannot be positively cleared, so flag it.
      const { size } = await fh.stat();
      if (size > MAX_PEM_BYTES) return true;
      const buf = Buffer.alloc(MAX_PEM_BYTES);
      const { bytesRead } = await fh.read(buf, 0, MAX_PEM_BYTES, 0);
      const head = buf.subarray(0, bytesRead).toString('utf-8');
      if (/PRIVATE KEY/.test(head)) return true;
      // Only clear as public if we saw a certificate AND read the whole
      // file (a private block could sit beyond a cap-sized read).
      if (/BEGIN CERTIFICATE/.test(head) && bytesRead < MAX_PEM_BYTES) return false;
      return true;
    } catch {
      return true;
    } finally {
      try { await fh?.close(); } catch { /* ignore */ }
    }
  }

  /**
   * Authoritative committability check via `git check-ignore`. Given
   * relative paths under `targetDir`, returns the subset git would
   * actually COMMIT (i.e. NOT ignored — honoring the full .gitignore
   * stack, nested ignores, negations, .git/info/exclude, and global
   * excludes), or `null` when the target is not a git work tree or git
   * is unavailable. This replaces hand-rolled gitignore matching for the
   * exposure decision, which repeatedly diverged from real git semantics
   * (negations, root-anchoring, dir-only rules — #250 adversarial
   * reviews). `null` signals the caller to fall back to the conservative
   * text heuristic.
   */
  private async gitCommittable(targetDir: string, relPaths: string[]): Promise<string[] | null> {
    if (relPaths.length === 0) return [];
    // `git` is invoked via execFile with a fixed argv array — no shell is
    // spawned, so path contents are never shell-interpreted. targetDir is
    // passed as the VALUE of `-C` (never as a flag) and paths are fed only
    // on NUL-delimited stdin (never as argv), so neither can be argument-
    // injected. As defense in depth we still (a) require an absolute
    // targetDir and (b) partition off any path containing a control
    // character (\0/\n/\r) — a real POSIX filename cannot contain \0, and
    // such pathological names are treated as committable (escalate),
    // never silently dropped.
    const absTarget = path.resolve(targetDir);
    const posixPaths = relPaths.map((p) => p.split(path.sep).join('/'));
    const suspicious = posixPaths.filter((p) => /[\0\n\r]/.test(p));
    const safePaths = posixPaths.filter((p) => !/[\0\n\r]/.test(p));
    const ignored = await new Promise<Set<string> | null>((resolve) => {
      let child;
      try {
        child = execFile(
          'git',
          // core.excludesFile=/dev/null drops the developer's GLOBAL git
          // excludes so committability depends only on the repo's own
          // committed .gitignore stack — deterministic across machines and
          // correct for advising on a shared repo (a key "protected" only
          // by a teammate-less global ignore is not actually protected).
          ['-c', 'core.excludesFile=/dev/null', '-C', absTarget, 'check-ignore', '--stdin', '-z'],
          // SIGKILL on timeout: an unkillable-by-SIGTERM git (e.g. a
          // wedged network .git) is force-reaped rather than leaked.
          { timeout: 10000, killSignal: 'SIGKILL', maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' },
          (err, stdout) => {
            // exit 0 = some ignored (stdout lists them); exit 1 = none
            // ignored (empty stdout); exit 128 / ENOENT = not a git repo
            // or git missing → null (caller falls back to the heuristic).
            const e = err as (Error & { code?: number; code2?: string }) | null;
            const errno = (err as NodeJS.ErrnoException | null)?.code;
            if (e && e.code !== 1 && (e.code === 128 || errno === 'ENOENT' || typeof e.code !== 'number')) {
              resolve(null);
              return;
            }
            const out = String(stdout ?? '');
            resolve(new Set(out.split('\0').filter(Boolean)));
          },
        );
      } catch {
        resolve(null);
        return;
      }
      // A payload larger than the pipe buffer whose child exits early
      // (exit 128: not a repo) errors ASYNCHRONOUSLY — an 'error' event on
      // stdin, invisible to the try/catch below. Without a listener that
      // event is an uncaught exception that kills the whole process (the
      // v0.25.0 release-run failure). The execFile callback above still
      // settles the promise from the child's exit code, and a partially
      // delivered payload can only SHRINK the ignored set (paths git never
      // read as committable → false-HIGH), never mark a committable file
      // ignored — the documented safe direction.
      child.stdin?.on('error', () => { /* async pipe error — settled via exit code */ });
      try {
        // Only control-char-free paths are sent to git; suspicious ones
        // are handled separately below.
        child.stdin?.end(safePaths.join('\0'));
      } catch {
        resolve(null);
      }
    });
    if (ignored === null) return null;
    // Committable = safe paths git did not ignore, PLUS every suspicious
    // (control-char) path (fail-safe: treat as exposed, never drop).
    return [...safePaths.filter((p) => !ignored.has(p)), ...suspicious];
  }

  /**
   * Effective (non-comment, non-blank, non-negation) `.gitignore` rules,
   * each trimmed and CR-stripped. Leading `**​/` is stripped (globstar
   * prefix is match-anywhere, same as the bare form). A leading `/` is
   * NOT stripped: a root-anchored rule is narrower than the bare form and
   * must not be treated as equivalent (adversarial-review finding, #250).
   */
  private gitignoreRules(gitignoreContent: string): string[] {
    return gitignoreContent
      .split('\n')
      .map((l) => l.replace(/\r$/, '').trim())
      .filter((l) => l && !l.startsWith('#') && !l.startsWith('!'))
      .map((l) => l.replace(/^\*\*\//, ''));
  }

  /**
   * True when the hygiene pattern (`.env` / `secrets.json` / `*.pem` /
   * `*.key`) is genuinely present as a match-anywhere rule, not merely
   * mentioned as a substring or covered by a narrower root-anchored rule.
   * Fixes the pre-existing substring bug where `# rotate secrets.json`
   * suppressed the missing-pattern finding (adversarial-review, #250).
   * A catch-all `*` / `**` also counts as covering.
   */
  private gitignorePatternCovered(pattern: string, gitignoreContent: string): boolean {
    return this.gitignoreRules(gitignoreContent).some((rule) => {
      if (rule === '*' || rule === '**') return true;
      if (rule === pattern) return true;
      // `.env*` (but not `.env.*`) matches the bare `.env` file too.
      if (pattern === '.env' && rule === '.env*') return true;
      return false;
    });
  }

  /**
   * FALLBACK-only heuristic (used when `git check-ignore` is unavailable —
   * a non-git target). True when a concrete relative file path looks
   * ignored. Deliberately conservative in the SAFE direction:
   *   - if the .gitignore contains ANY negation (`!`) rule, returns false
   *     (a negation may re-include the file; do not claim ignored);
   *   - a trailing-slash rule (`foo/`) is directory-only and never
   *     matches a same-named FILE, only paths under it;
   *   - a leading `/` anchors to the repo root.
   * On uncertainty it returns false (treat as committable → escalate).
   * Authoritative committability comes from git check-ignore; this only
   * backstops non-git scans (adversarial-review findings, #250).
   */
  private gitignoreFileIgnoredHeuristic(rel: string, gitignoreContent: string): boolean {
    // Any negation rule → cannot safely claim ignored.
    if (gitignoreContent.split('\n').some((l) => l.trim().startsWith('!'))) return false;
    const posix = rel.split(path.sep).join('/');
    const base = path.posix.basename(posix);
    return this.gitignoreRules(gitignoreContent).some((rule) => {
      if (rule === '*' || rule === '**') return true;
      const anchored = rule.startsWith('/');
      const body = anchored ? rule.slice(1) : rule;
      const dirOnly = body.endsWith('/');
      const name = dirOnly ? body.slice(0, -1) : body;
      if (!name) return false;
      // Directory-prefix match (applies to dir-only and bare-dir rules).
      if (posix.startsWith(name + '/')) return true;
      // A trailing-slash rule is directory-only — it never matches a file.
      if (dirOnly) return false;
      // Exact full-path match.
      if (name === posix) return true;
      // Anchored non-dir rules match only at the repo root.
      if (anchored) return name === posix;
      // Basename match (non-anchored bare name applies at any depth).
      if (name === base) return true;
      // `*.ext` glob.
      if (name.startsWith('*.') && base.endsWith(name.slice(1))) return true;
      // `prefix*` glob on the basename (covers `prefix.*` too).
      if (name.endsWith('*')) {
        const prefix = name.slice(0, -1);
        if (prefix && !prefix.includes('/') && base.startsWith(prefix)) return true;
      }
      return false;
    });
  }

  /**
   * Of the given present sensitive files, which would git actually COMMIT
   * (are NOT ignored)? Uses `git check-ignore` when the target is a git
   * work tree (authoritative — handles negations, nested ignores, dir
   * rules, global excludes); falls back to the conservative text
   * heuristic otherwise. Returns relative posix paths.
   */
  private async committableSensitiveFiles(targetDir: string, relPaths: string[], gitignoreContent: string): Promise<string[]> {
    if (relPaths.length === 0) return [];
    const viaGit = await this.gitCommittable(targetDir, relPaths);
    if (viaGit !== null) return viaGit;
    return relPaths
      .map((p) => p.split(path.sep).join('/'))
      .filter((p) => !this.gitignoreFileIgnoredHeuristic(p, gitignoreContent));
  }

  private async checkCredentialsAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // CRED-002: Check for private key files. Recursive (bounded) since
    // #250 — a key at certs/server.pem is exactly as committable as one
    // at the root — and carries `file` so the finding survives the
    // user-facing concrete-findings filter.
    const { keyFiles: foundKeys, complete: keyScanComplete } =
      await this.collectSensitiveArtifacts(targetDir);

    if (foundKeys.length > 0) {
      findings.push({
        checkId: 'CRED-002',
        name: 'Private Key Files',
        description: 'Private key or certificate files found in project directory',
        category: 'credentials',
        severity: 'critical',
        passed: false,
        message: `Private key files found: ${foundKeys.slice(0, 5).join(', ')}${foundKeys.length > 5 ? ` (+${foundKeys.length - 5} more)` : ''} - move to secure location`,
        file: foundKeys[0],
        fixable: false,
        fix: 'Move the key outside the repository or into a secrets manager. If it was ever committed, rotate it, then run: '
          + (commandNaming(foundKeys[0], (q) => `git rm --cached ${q}`)
            ?? 'git rm --cached on the file named above (its name cannot be shown truthfully in a command).'),
        details: { files: foundKeys },
        guidance: 'Private key files (.pem, .key) in a project directory are easily committed to git. Once pushed, the keys are compromised and must be rotated.',
      });
    } else if (!keyScanComplete) {
      // No key found, but the walk could not exhaustively verify absence
      // (tree too deep/large, an unreadable directory, or an un-ignored
      // node_modules). Do NOT report clean — a key could hide in the
      // unscanned portion. Fail-safe HIGH so the scan does not award a
      // false clean bill (adversarial-review finding, #250).
      findings.push({
        checkId: 'CRED-002',
        name: 'Private Key Files',
        description: 'Private-key scan could not fully cover the project tree',
        category: 'credentials',
        severity: 'high',
        passed: false,
        message: 'Private-key scan incomplete — tree too large/deep or partly unreadable to confirm no keys are present',
        file: '.',
        fixable: false,
        fix: `List candidate key files yourself: find . -type f \\( -name '*.pem' -o -name '*.key' \\) -not -path '*/node_modules/*'`,
        guidance: 'The project tree is too large or deep, has an unreadable directory, or contains an un-ignored node_modules — so the scanner could not confirm no private keys are committed. Verify manually and ensure keys are outside the repo or in a secrets manager.',
      });
    } else {
      findings.push({
        checkId: 'CRED-002',
        name: 'Private Key Files',
        description: 'Private key or certificate files found in project directory',
        category: 'credentials',
        severity: 'critical',
        passed: true,
        message: 'No private key files found in project directory',
        fixable: false,
        guidance: 'Private key files (.pem, .key) in a project directory are easily committed to git. Once pushed, the keys are compromised and must be rotated.',
      });
    }

    // CRED-003: Check package.json for hardcoded secrets
    let hasSecretsInPackageJson = false;
    try {
      const content = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const { pattern } of CREDENTIAL_PATTERNS) {
        if (pattern.test(content)) {
          hasSecretsInPackageJson = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'CRED-003',
      name: 'Secrets in package.json',
      description: 'package.json contains hardcoded secrets',
      category: 'credentials',
      severity: 'critical',
      passed: !hasSecretsInPackageJson,
      message: hasSecretsInPackageJson
        ? 'package.json contains hardcoded secrets'
        : 'No secrets found in package.json',
      fixable: false,
      fix: hasSecretsInPackageJson ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'package.json is always committed to git and published to npm. Secrets there are visible to anyone who installs or forks your package.',
    });

    // CRED-004: Check for JWT secrets in config
    let hasJwtSecret = false;
    const configFiles = ['config.json', 'config.yaml', 'config.yml', 'settings.json'];
    for (const file of configFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        if (content.includes('jwt') && (content.includes('secret') || content.includes('key'))) {
          // Check if it's a hardcoded value (not env reference)
          if (!content.includes('${') && !content.includes('process.env')) {
            hasJwtSecret = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'CRED-004',
      name: 'JWT Secret in Config',
      description: 'JWT secret found hardcoded in configuration file',
      category: 'credentials',
      severity: 'critical',
      passed: !hasJwtSecret,
      message: hasJwtSecret
        ? 'JWT secret hardcoded in config'
        : 'No hardcoded JWT secrets found',
      fixable: false,
      fix: hasJwtSecret ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'A hardcoded JWT secret lets anyone who reads the config forge valid authentication tokens and impersonate any user.',
    });

    return findings;
  }

  private async checkPermissionsAdvanced(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // PERM-002: Check for executable config files
    const configFiles = ['config.json', 'mcp.json', 'settings.json', '.env'];
    const executableConfigs: string[] = [];

    for (const file of configFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, file));
        const mode = stats.mode & 0o777;
        if (mode & 0o111) {
          executableConfigs.push(file);
        }
      } catch {}
    }

    findings.push({
      checkId: 'PERM-002',
      name: 'Executable Config Files',
      description: 'Configuration files have executable permission',
      category: 'permissions',
      severity: 'medium',
      passed: executableConfigs.length === 0,
      message: executableConfigs.length === 0
        ? 'No config files have executable permissions'
        : `Config files with executable permission: ${executableConfigs.join(', ')}`,
      fixable: true,
      fixed: false,
      details: executableConfigs.length > 0 ? { files: executableConfigs } : undefined,
      guidance: 'Executable config files can be run as scripts. An attacker who modifies a config file with execute permission can trick the system into running arbitrary code.',
    });

    // PERM-003: Check for group-writable sensitive files
    const sensitiveFiles = ['.env', '.env.local', 'secrets.json', 'credentials.json'];
    const groupWritable: string[] = [];

    for (const file of sensitiveFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, file));
        const mode = stats.mode & 0o777;
        if (mode & 0o020) {
          groupWritable.push(file);
        }
      } catch {}
    }

    findings.push({
      checkId: 'PERM-003',
      name: 'Group-Writable Sensitive Files',
      description: 'Sensitive files have group write permission',
      category: 'permissions',
      severity: 'high',
      passed: groupWritable.length === 0,
      message: groupWritable.length === 0
        ? 'No sensitive files have group write permission'
        : `Group-writable sensitive files: ${groupWritable.join(', ')}`,
      fixable: true,
      fixed: false,
      details: groupWritable.length > 0 ? { files: groupWritable } : undefined,
      guidance: 'Group-writable sensitive files allow other users in the same group to modify credentials or inject malicious configuration values.',
    });

    return findings;
  }

  private async checkEnvironmentSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // ENV-001: Check for development mode indicators
    let devModeEnabled = false;
    const envIndicators = ['NODE_ENV=development', 'DEBUG=true', 'DEV_MODE=true'];
    const envFiles = ['.env', '.env.local', 'config.json'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const indicator of envIndicators) {
          if (content.includes(indicator)) {
            devModeEnabled = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-001',
      name: 'Development Mode Enabled',
      description: 'Development mode indicators found in configuration',
      category: 'environment',
      severity: 'medium',
      passed: !devModeEnabled,
      message: devModeEnabled
        ? 'Development mode enabled - ensure this is disabled in production'
        : 'No development mode indicators found',
      fixable: false,
      guidance: 'Development mode typically disables security features like CSRF protection, strict CORS, and error sanitization, leaving the application exposed in production.',
    });

    // ENV-002: Check for debug flags
    let hasDebugFlags = false;
    const debugPatterns = ['DEBUG=', 'VERBOSE=true', 'LOG_LEVEL=debug', 'TRACE=true'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const pattern of debugPatterns) {
          if (content.includes(pattern)) {
            hasDebugFlags = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-002',
      name: 'Debug Flags Enabled',
      description: 'Debug or verbose logging flags are enabled',
      category: 'environment',
      severity: 'low',
      passed: !hasDebugFlags,
      message: hasDebugFlags
        ? 'Debug flags enabled - may expose sensitive information in logs'
        : 'No debug flags detected',
      fixable: false,
      guidance: 'Debug and verbose logging flags can leak internal state, database queries, and credential values into log files or console output.',
    });

    // ENV-003: Check for error verbosity settings
    let verboseErrors = false;
    const errorPatterns = ['SHOW_ERRORS=true', 'DISPLAY_ERRORS=true', 'STACK_TRACE=true'];

    for (const file of envFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
        for (const pattern of errorPatterns) {
          if (content.includes(pattern)) {
            verboseErrors = true;
            break;
          }
        }
      } catch {}
    }

    findings.push({
      checkId: 'ENV-003',
      name: 'Verbose Error Messages',
      description: 'Configuration enables verbose error messages',
      category: 'environment',
      severity: 'medium',
      passed: !verboseErrors,
      message: verboseErrors
        ? 'Verbose error messages enabled - may leak sensitive information'
        : 'Error verbosity settings are appropriate',
      fixable: false,
      guidance: 'Verbose error messages expose stack traces, file paths, and internal logic to attackers, making it easier to find exploitable weaknesses.',
    });

    // ENV-004: Check for production environment validation
    let hasEnvValidation = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasEnvValidation = pkgJson.includes('dotenv') || pkgJson.includes('env-var') || pkgJson.includes('envalid');
    } catch {}

    findings.push({
      checkId: 'ENV-004',
      name: 'Environment Validation',
      description: 'No environment variable validation library detected',
      category: 'environment',
      severity: 'low',
      passed: hasEnvValidation,
      message: hasEnvValidation
        ? 'Environment validation library detected'
        : 'Consider using env validation (dotenv, envalid) to catch misconfigurations',
      fixable: false,
      guidance: 'Without environment validation, missing or malformed variables cause silent failures. A missing DB_HOST might fall back to an insecure default rather than failing fast.',
    });

    return findings;
  }

  private async checkLoggingSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // LOG-001: Check for logging configuration
    let hasLoggingConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasLoggingConfig = pkgJson.includes('winston') || pkgJson.includes('pino') || pkgJson.includes('bunyan');
    } catch {}

    findings.push({
      checkId: 'LOG-001',
      name: 'Structured Logging',
      description: 'No structured logging library detected',
      category: 'logging',
      severity: 'low',
      passed: hasLoggingConfig,
      message: hasLoggingConfig
        ? 'Structured logging library detected'
        : 'Consider using structured logging (winston, pino) for better security auditing',
      fixable: false,
      guidance: 'Unstructured console.log output is hard to filter, search, or redact. Structured logging makes it possible to automatically mask sensitive fields and detect anomalies.',
    });

    // LOG-002: Check for sensitive data in log patterns
    //
    // #421 — this check MATCHES on file content, so it is evidence-based, not
    // advice. It must carry the path it matched: `filteredFindings` drops every
    // finding without a `file` ("concrete findings, not generic advice"), so a
    // pathless LOG-002 was scored and displayed as though it had never fired.
    // Recording the path is what makes the detection reach the output at all.
    // Matches the same four spellings the literal list did
    // (`console.log(password|apiKey|secret|token`), case-insensitively, with
    // two corrections:
    //
    //  - Applied to the ORIGINAL text. The previous form searched a
    //    `toLowerCase()` copy and reported an offset from it. `toLowerCase` is
    //    not length-preserving (U+0130 lowercases to two code units), so a
    //    file could shift its own reported line number — the finding fired
    //    while its `Verify:` command pointed at an innocent line.
    //  - A trailing identifier boundary. Without it `console.log(token` also
    //    matched `console.log(tokenCount)`, which is ordinary code. That never
    //    surfaced only because the finding was being dropped; resurrecting it
    //    without the boundary would ship the false positive.
    //
    // Literal prefix, a four-way literal alternation and a lookahead: no
    // nested quantifier, so it stays linear on untrusted input.
    const sensitiveLogCall = /console\.log\((?:password|apikey|secret|token)(?![A-Za-z0-9_$])/i;

    const sensitiveLogFiles: string[] = [];
    let sensitiveLogFile: string | undefined;
    let sensitiveLogLine: number | undefined;

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        // Extension list deliberately UNCHANGED here — widening it is #414,
        // which is blocked on this fix precisely because a widened read
        // produced no observable change while the finding was being dropped.
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            // Walked line by line rather than split into an array: the content
            // is an untrusted file and `split('\n')` holds one string per line
            // live. This also yields the line number and the within-line offset
            // directly, which is what the string/comment test needs.
            let lineStart = 0;
            let lineNo = 1;
            while (lineStart <= content.length) {
              let nl = content.indexOf('\n', lineStart);
              if (nl === -1) nl = content.length;
              const lineText = content.slice(lineStart, nl);
              const m = sensitiveLogCall.exec(lineText);
              // A match inside a string literal or a comment is text, not a
              // log call — `// console.log(password) - removed` and a help
              // string quoting the bad pattern are both documentation. Reuses
              // the helper NEMO-009 already applies for exactly this.
              if (m && !isMatchInsideStringLiteral(lineText, m.index)) {
                sensitiveLogFiles.push(file);
                if (sensitiveLogFile === undefined) {
                  sensitiveLogFile = file;
                  sensitiveLogLine = lineNo;
                }
                break;
              }
              if (nl === content.length) break;
              lineStart = nl + 1;
              lineNo++;
            }
          } catch {}
        }
      }
    } catch {}

    const sensitiveInLogs = sensitiveLogFile !== undefined;

    findings.push({
      checkId: 'LOG-002',
      name: 'Sensitive Data in Logs',
      description: 'Potential sensitive data being logged',
      category: 'logging',
      severity: 'high',
      passed: !sensitiveInLogs,
      message: sensitiveInLogs
        ? 'Code may be logging sensitive data - review console.log statements'
        : 'No obvious sensitive data logging patterns found',
      // Only set when the check actually matched. A passed LOG-002 stays
      // pathless: it has no evidence to point at.
      file: sensitiveLogFile,
      // Cited ONLY when a single file matched. `.hmaignore` can re-point a
      // multi-file finding onto a surviving path (#280, `retainAfterPathSuppression`)
      // and that re-point moves `file` without moving `line` — so a line from
      // the ignored file would be printed against the surviving one, and
      // `Verify: sed -n '5p' z.js` would print nothing. No line is better than
      // a line that sends the reader somewhere the match is not.
      line: sensitiveLogFiles.length === 1 ? sensitiveLogLine : undefined,
      // EVERY matching file, not just the cited one. `.hmaignore` suppression
      // keys on all covered paths (#280), so listing one path here would let a
      // single ignored file delete a finding that also covers un-ignored ones.
      ...(sensitiveLogFiles.length > 0 ? { details: { files: sensitiveLogFiles } } : {}),
      fixable: false,
      guidance: 'Passwords, API keys, and tokens logged to console or files persist in log aggregators and crash reports, where they can be harvested by anyone with log access.',
    });

    // LOG-003: Check for log file permissions
    const logFiles = ['app.log', 'error.log', 'debug.log', 'access.log'];
    const worldReadableLogs: string[] = [];

    for (const logFile of logFiles) {
      try {
        const stats = await fs.stat(path.join(targetDir, logFile));
        const mode = stats.mode & 0o777;
        if (mode & 0o004) {
          worldReadableLogs.push(logFile);
        }
      } catch {}
    }

    findings.push({
      checkId: 'LOG-003',
      name: 'Log File Permissions',
      description: 'Log files have overly permissive permissions',
      category: 'logging',
      severity: 'medium',
      passed: worldReadableLogs.length === 0,
      message: worldReadableLogs.length === 0
        ? 'No world-readable log files found'
        : `World-readable log files: ${worldReadableLogs.join(', ')}`,
      fixable: true,
      fixed: false,
      guidance: 'World-readable log files let any local user read application logs, which often contain request details, internal errors, and sometimes credentials.',
    });

    // LOG-004: Check for audit logging capability
    let hasAuditLogging = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasAuditLogging = pkgJson.includes('audit') || pkgJson.includes('morgan') || pkgJson.includes('express-winston');
    } catch {}

    findings.push({
      checkId: 'LOG-004',
      name: 'Audit Logging',
      description: 'No audit logging capability detected',
      category: 'logging',
      severity: 'medium',
      passed: hasAuditLogging,
      message: hasAuditLogging
        ? 'Audit logging capability detected'
        : 'Consider implementing audit logging for security events',
      fixable: false,
      guidance: 'Without audit logging, there is no record of who accessed what or when. Incident response becomes guesswork without a trail of security-relevant events.',
    });

    return findings;
  }

  private async checkDependencySecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // DEP-001: Check for package-lock.json
    let hasLockFile = false;
    try {
      await fs.access(path.join(targetDir, 'package-lock.json'));
      hasLockFile = true;
    } catch {
      try {
        await fs.access(path.join(targetDir, 'yarn.lock'));
        hasLockFile = true;
      } catch {
        try {
          await fs.access(path.join(targetDir, 'pnpm-lock.yaml'));
          hasLockFile = true;
        } catch {}
      }
    }

    findings.push({
      checkId: 'DEP-001',
      name: 'Dependency Lock File',
      description: 'No dependency lock file found',
      category: 'dependencies',
      severity: 'medium',
      passed: hasLockFile,
      message: hasLockFile
        ? 'Dependency lock file present'
        : 'No lock file found - dependency versions may vary between installs',
      fixable: false,
      guidance: 'Without a lock file, npm install can resolve to different package versions on different machines, including versions with known vulnerabilities or supply-chain backdoors.',
    });

    // DEP-002: Check for known vulnerable packages
    const vulnerablePackages = ['event-stream', 'flatmap-stream', 'eslint-scope@3.7.2'];
    let hasVulnerablePackage = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const pkg of vulnerablePackages) {
        if (pkgJson.includes(pkg.split('@')[0])) {
          hasVulnerablePackage = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-002',
      name: 'Known Vulnerable Packages',
      description: 'Package.json may contain known vulnerable packages',
      category: 'dependencies',
      severity: 'critical',
      passed: !hasVulnerablePackage,
      message: hasVulnerablePackage
        ? 'Potentially vulnerable package detected - run npm audit'
        : 'No known vulnerable packages in direct dependencies',
      fixable: false,
      guidance: 'These packages have confirmed supply-chain compromises (e.g., event-stream injected a cryptocurrency-stealing payload). Remove or replace them immediately.',
    });

    // DEP-003: Check for wildcard versions
    let hasWildcardVersions = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(pkgJson);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [, version] of Object.entries(allDeps)) {
        if (version === '*' || version === 'latest') {
          hasWildcardVersions = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-003',
      name: 'Wildcard Dependency Versions',
      description: 'Package.json uses wildcard or latest versions',
      category: 'dependencies',
      severity: 'high',
      passed: !hasWildcardVersions,
      message: hasWildcardVersions
        ? 'Wildcard versions detected - pin dependencies for reproducible builds'
        : 'All dependency versions are properly specified',
      fixable: false,
      guidance: 'Wildcard (*) or "latest" versions accept any future release, including ones compromised by supply-chain attacks. Pin versions and use a lock file.',
    });

    // DEP-004: Check for npm scripts security
    let hasDangerousScripts = false;
    const dangerousScriptRegexes = [
      /curl\b.*\|\s*sh/i,        // curl ... | sh (with anything between)
      /curl\b.*\|\s*bash/i,      // curl ... | bash
      /wget\b.*\|\s*sh/i,        // wget ... | sh
      /wget\b.*\|\s*bash/i,      // wget ... | bash
      /\beval\s*\(/,             // eval(
      /\$\(curl\b/,             // $(curl
      /\$\(wget\b/,             // $(wget
    ];
    const pkgJsonPath = path.join(targetDir, 'package.json');
    try {
      const pkgJson = await fs.readFile(pkgJsonPath, 'utf-8');
      const pkg = JSON.parse(pkgJson);
      if (pkg.scripts) {
        for (const [, script] of Object.entries(pkg.scripts)) {
          if (typeof script === 'string') {
            for (const pattern of dangerousScriptRegexes) {
              if (pattern.test(script)) {
                hasDangerousScripts = true;
                break;
              }
            }
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'DEP-004',
      name: 'Dangerous npm Scripts',
      description: 'npm scripts contain potentially dangerous commands',
      category: 'dependencies',
      severity: 'critical',
      passed: !hasDangerousScripts,
      file: hasDangerousScripts ? 'package.json' : undefined,
      message: hasDangerousScripts
        ? 'Dangerous patterns in npm scripts (curl|sh, eval) - review carefully'
        : 'npm scripts appear safe',
      fixable: false,
      fix: hasDangerousScripts
        ? 'Remove the curl|sh or wget|sh pattern from package.json scripts. Replace with a pinned package install: npm install --save-exact <package>  or vendor the script with a pinned checksum.'
        : undefined,
      guidance: 'Scripts that pipe curl/wget to sh execute arbitrary remote code during npm install. An attacker who compromises the URL controls your build environment.',
    });

    return findings;
  }

  private async checkAuthSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // AUTH-001: Check for auth configuration
    let hasAuthConfig = false;
    const authIndicators = ['auth', 'authentication', 'passport', 'jwt', 'session'];

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      for (const indicator of authIndicators) {
        if (pkgJson.toLowerCase().includes(indicator)) {
          hasAuthConfig = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUTH-001',
      name: 'Authentication Configuration',
      description: 'No authentication library or configuration detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasAuthConfig,
      message: hasAuthConfig
        ? 'Authentication configuration detected'
        : 'No authentication library detected - ensure endpoints are protected',
      fixable: false,
      guidance: 'Without authentication, any network-reachable client can access your API endpoints, including reading data, triggering actions, and modifying state.',
    });

    // AUTH-002: Check for rate limiting
    let hasRateLimiting = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasRateLimiting = pkgJson.includes('rate-limit') || pkgJson.includes('express-rate-limit') || pkgJson.includes('bottleneck');
    } catch {}

    findings.push({
      checkId: 'AUTH-002',
      name: 'Rate Limiting',
      description: 'No rate limiting library detected',
      category: 'authentication',
      severity: 'high',
      passed: hasRateLimiting,
      message: hasRateLimiting
        ? 'Rate limiting library detected'
        : 'No rate limiting detected - API may be vulnerable to abuse',
      fixable: false,
      guidance: 'Without rate limiting, attackers can brute-force credentials, scrape data, or exhaust resources with automated requests at no cost.',
    });

    // AUTH-003: Check for session security
    let hasSecureSessions = false;
    const sessionIndicators = ['express-session', 'cookie-session', 'secure: true', 'httpOnly: true'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const indicator of sessionIndicators) {
              if (content.includes(indicator)) {
                hasSecureSessions = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUTH-003',
      name: 'Secure Session Configuration',
      description: 'Session security configuration not detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasSecureSessions,
      message: hasSecureSessions
        ? 'Secure session configuration detected'
        : 'Ensure sessions use secure, httpOnly cookies',
      fixable: false,
      guidance: 'Sessions without secure and httpOnly flags are vulnerable to theft via XSS attacks or network sniffing, allowing attackers to hijack authenticated sessions.',
    });

    // AUTH-004: Check for CORS configuration
    let hasCorsConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasCorsConfig = pkgJson.includes('cors');
    } catch {}

    findings.push({
      checkId: 'AUTH-004',
      name: 'CORS Configuration',
      description: 'No CORS library detected',
      category: 'authentication',
      severity: 'medium',
      passed: hasCorsConfig,
      message: hasCorsConfig
        ? 'CORS library detected'
        : 'No CORS configuration detected - ensure cross-origin requests are properly handled',
      fixable: false,
      guidance: 'Without explicit CORS configuration, browsers may block legitimate cross-origin requests or, worse, a permissive default may allow malicious sites to make authenticated requests to your API.',
    });

    return findings;
  }

  private async checkProcessSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // PROC-001: Check for Dockerfile security
    // Search common Dockerfile locations
    let hasSecureDockerfile = true;
    let dockerfilePath: string | undefined;
    const dockerfileCandidates = [
      'Dockerfile',
      'Dockerfile.prod',
      'Dockerfile.production',
      'Dockerfile.dev',
      'docker/Dockerfile',
    ];
    for (const candidate of dockerfileCandidates) {
      const candidatePath = path.join(targetDir, candidate);
      try {
        const dockerfile = await fs.readFile(candidatePath, 'utf-8');
        dockerfilePath = candidatePath;
        if (dockerfile.includes('USER root') || !dockerfile.includes('USER ')) {
          hasSecureDockerfile = false;
        }
        break; // Use the first Dockerfile found
      } catch {
        // File not found, try next candidate
      }
    }

    findings.push({
      checkId: 'PROC-001',
      name: 'Container User',
      description: 'Dockerfile runs as root or has no USER directive',
      category: 'process',
      severity: 'high',
      passed: hasSecureDockerfile,
      file: !hasSecureDockerfile && dockerfilePath ? path.relative(targetDir, dockerfilePath) : undefined,
      message: hasSecureDockerfile
        ? 'Container runs as non-root user or no Dockerfile present'
        : 'Dockerfile runs as root - add USER directive for non-root user',
      fixable: false,
      guidance: 'A container running as root means any exploit that escapes the application gets full control of the container and potentially the host system.',
    });

    // PROC-002: Check for security headers middleware
    let hasSecurityHeaders = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasSecurityHeaders = pkgJson.includes('helmet') || pkgJson.includes('security-headers');
    } catch {}

    findings.push({
      checkId: 'PROC-002',
      name: 'Security Headers',
      description: 'No security headers middleware detected',
      category: 'process',
      severity: 'medium',
      passed: hasSecurityHeaders,
      message: hasSecurityHeaders
        ? 'Security headers middleware detected (helmet)'
        : 'Consider using helmet or similar for security headers',
      fixable: false,
      guidance: 'Missing security headers (CSP, X-Frame-Options, HSTS) leave your app vulnerable to clickjacking, XSS, and protocol downgrade attacks.',
    });

    // PROC-003: Check for input validation
    let hasInputValidation = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasInputValidation = pkgJson.includes('joi') || pkgJson.includes('zod') || pkgJson.includes('yup') || pkgJson.includes('class-validator');
    } catch {}

    findings.push({
      checkId: 'PROC-003',
      name: 'Input Validation',
      description: 'No input validation library detected',
      category: 'process',
      severity: 'high',
      passed: hasInputValidation,
      message: hasInputValidation
        ? 'Input validation library detected'
        : 'No input validation library found - validate all user inputs',
      fixable: false,
      guidance: 'Without input validation, attackers can inject SQL, scripts, or malformed data that corrupts state, steals data, or crashes the application.',
    });

    // PROC-004: Check for error handling
    let hasErrorHandling = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('try') && content.includes('catch')) {
              hasErrorHandling = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'PROC-004',
      name: 'Error Handling',
      description: 'No error handling patterns detected',
      category: 'process',
      severity: 'medium',
      passed: hasErrorHandling,
      message: hasErrorHandling
        ? 'Error handling patterns detected'
        : 'Ensure proper error handling to prevent information disclosure',
      fixable: false,
      guidance: 'Unhandled errors can crash the process, leak stack traces with internal paths and variable names, and create denial-of-service conditions.',
    });

    return findings;
  }

  private async checkClaudeExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const claudeSettingsPath = path.join(targetDir, '.claude', 'settings.json');

    let claudeSettings: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(claudeSettingsPath, 'utf-8');
      claudeSettings = JSON.parse(content);
    } catch {}

    // CLAUDE-004: Check for deny rules
    const permissions = claudeSettings?.permissions as { deny?: string[] } | undefined;
    const hasDenyRules = permissions?.deny && permissions.deny.length > 0;

    findings.push({
      checkId: 'CLAUDE-004',
      name: 'Claude Deny Rules',
      description: 'No deny rules configured for Claude Code',
      category: 'claude-code',
      severity: 'medium',
      passed: hasDenyRules || !claudeSettings,
      message: hasDenyRules
        ? 'Claude Code has deny rules configured'
        : claudeSettings
          ? 'Consider adding deny rules to block dangerous operations'
          : 'No Claude settings file found',
      fixable: false,
      guidance: 'Without deny rules, Claude Code can execute any tool or command. Deny rules act as a blocklist to prevent dangerous operations like rm -rf or credential access.',
    });

    // CLAUDE-005: Check for memory/context persistence
    const memorySettings = claudeSettings?.memory as { enabled?: boolean } | undefined;
    const hasMemoryEnabled = memorySettings?.enabled === true;

    findings.push({
      checkId: 'CLAUDE-005',
      name: 'Claude Memory Persistence',
      description: 'Claude memory persistence may store sensitive context',
      category: 'claude-code',
      severity: 'low',
      passed: !hasMemoryEnabled,
      message: hasMemoryEnabled
        ? 'Claude memory enabled - be aware sensitive data may persist'
        : 'Claude memory not explicitly enabled',
      fixable: false,
      guidance: 'Persistent memory can retain API keys, internal URLs, or confidential instructions across sessions. An attacker who gains access to the memory store can extract this data.',
    });

    // CLAUDE-006: Check CLAUDE.md for sensitive instructions
    let hasSensitiveInstructions = false;
    const sensitivePatterns = ['never share', 'confidential', 'internal only', 'do not disclose'];

    try {
      const claudeMd = await fs.readFile(path.join(targetDir, 'CLAUDE.md'), 'utf-8');
      for (const pattern of sensitivePatterns) {
        if (claudeMd.toLowerCase().includes(pattern)) {
          hasSensitiveInstructions = true;
          break;
        }
      }
    } catch {}

    findings.push({
      checkId: 'CLAUDE-006',
      name: 'Sensitive Instructions in CLAUDE.md',
      description: 'CLAUDE.md may contain sensitive instructions that could be extracted',
      category: 'claude-code',
      severity: 'medium',
      passed: !hasSensitiveInstructions,
      message: hasSensitiveInstructions
        ? 'CLAUDE.md contains sensitive instructions - these may be extractable via prompt injection'
        : 'No obviously sensitive instructions detected in CLAUDE.md',
      fixable: false,
      guidance: 'CLAUDE.md is typically committed to version control. Sensitive instructions there can be extracted via prompt injection or by anyone with repo access.',
    });

    // CLAUDE-007: Check for tool timeout configuration
    const hasToolTimeout = (claudeSettings as Record<string, unknown>)?.toolTimeout !== undefined;

    findings.push({
      checkId: 'CLAUDE-007',
      name: 'Tool Timeout Configuration',
      description: 'No tool timeout configured for Claude operations',
      category: 'claude-code',
      severity: 'low',
      passed: hasToolTimeout || !claudeSettings,
      message: hasToolTimeout
        ? 'Tool timeout is configured'
        : claudeSettings
          ? 'Consider setting tool timeouts to prevent runaway operations'
          : 'No Claude settings found',
      fixable: false,
      guidance: 'Without tool timeouts, a stuck or malicious tool call can hang indefinitely, consuming resources and blocking the agent from responding.',
    });

    return findings;
  }

  private async checkMcpExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // MCP-006: Check for request timeout
    const hasTimeout = (mcpConfig as Record<string, unknown>)?.timeout !== undefined;

    findings.push({
      checkId: 'MCP-006',
      name: 'MCP Request Timeout',
      description: 'No request timeout configured for MCP servers',
      category: 'mcp',
      severity: 'medium',
      passed: hasTimeout || !mcpConfig,
      message: hasTimeout
        ? 'MCP timeout is configured'
        : mcpConfig
          ? 'Consider setting request timeouts for MCP servers'
          : 'No MCP config found',
      fixable: false,
      guidance: 'Without request timeouts, a hung or malicious MCP server can block the agent indefinitely, causing denial-of-service and preventing other tools from executing.',
    });

    // MCP-007: Check for retry limits
    const hasRetryConfig = (mcpConfig as Record<string, unknown>)?.retries !== undefined;

    findings.push({
      checkId: 'MCP-007',
      name: 'MCP Retry Limits',
      description: 'No retry limits configured for MCP servers',
      category: 'mcp',
      severity: 'low',
      passed: hasRetryConfig || !mcpConfig,
      message: hasRetryConfig
        ? 'MCP retry limits configured'
        : mcpConfig
          ? 'Consider setting retry limits to prevent infinite loops'
          : 'No MCP config found',
      fixable: false,
      guidance: 'Without retry limits, a failing MCP server can trigger infinite retry loops that waste API credits, saturate network connections, and stall the agent.',
    });

    // MCP-008: Check for localhost binding
    let allLocalhostBound = true;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[]; url?: string }>)) {
        if (server.url && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
          // Remote server is fine if using HTTPS
          continue;
        }
        if (server.args?.some((arg: string) => arg.includes('0.0.0.0'))) {
          allLocalhostBound = false;
        }
      }
    }

    findings.push({
      checkId: 'MCP-008',
      name: 'MCP Localhost Binding',
      description: 'MCP servers should bind to localhost only',
      category: 'mcp',
      severity: 'high',
      passed: allLocalhostBound,
      message: allLocalhostBound
        ? 'MCP servers properly bound to localhost'
        : 'Some MCP servers not bound to localhost - may be network accessible',
      fixable: false,
      guidance: 'MCP servers running over network (SSE/HTTP) without authentication let any network-adjacent attacker connect and issue tool calls.',
    });

    // MCP-009: Check for sensitive tool names
    const sensitiveTools = ['execute', 'shell', 'eval', 'system', 'exec', 'spawn'];
    let hasSensitiveTools = false;

    if (mcpConfig?.servers) {
      for (const [name] of Object.entries(mcpConfig.servers as Record<string, unknown>)) {
        for (const tool of sensitiveTools) {
          if (name.toLowerCase().includes(tool)) {
            hasSensitiveTools = true;
            break;
          }
        }
      }
    }

    findings.push({
      checkId: 'MCP-009',
      name: 'Sensitive MCP Tools',
      description: 'MCP configuration includes potentially dangerous tools',
      category: 'mcp',
      severity: 'high',
      passed: !hasSensitiveTools,
      message: hasSensitiveTools
        ? 'Sensitive tool names detected (shell, exec, eval) - ensure proper restrictions'
        : 'No obviously sensitive tool names in MCP config',
      fixable: false,
      guidance: 'Tools named shell, exec, or eval typically provide arbitrary code execution. A prompt injection that invokes these tools can fully compromise the host system.',
    });

    // MCP-010: Check for logging configuration
    let hasLogging = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { args?: string[] }>)) {
        if (server.args?.some((arg: string) => arg.includes('log') || arg.includes('verbose'))) {
          hasLogging = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'MCP-010',
      name: 'MCP Logging',
      description: 'MCP server logging configuration',
      category: 'mcp',
      severity: 'low',
      passed: true, // Informational
      message: hasLogging
        ? 'MCP logging appears to be configured - ensure sensitive data is not logged'
        : 'No explicit MCP logging configuration detected',
      fixable: false,
      guidance: 'Logging MCP requests and responses creates an audit trail for detecting misuse. Without it, malicious tool calls leave no trace for incident response.',
    });

    return findings;
  }

  private async checkNetworkExtended(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // NET-003: Check for HTTPS enforcement
    let hasHttpsEnforcement = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('https') || content.includes('SSL') || content.includes('TLS')) {
              hasHttpsEnforcement = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-003',
      name: 'HTTPS Configuration',
      description: 'No HTTPS/TLS configuration detected',
      category: 'network',
      severity: 'high',
      passed: hasHttpsEnforcement,
      message: hasHttpsEnforcement
        ? 'HTTPS/TLS configuration detected'
        : 'No HTTPS configuration found - ensure production uses TLS',
      fixable: false,
      guidance: 'Without TLS, all traffic including API keys, tokens, and user data is transmitted in plaintext. Anyone on the network can intercept and read it.',
    });

    // NET-004: Check for exposed debug endpoints
    let hasDebugEndpoints = false;
    const debugEndpoints = ['/debug', '/admin', '/metrics', '/health', '/status', '/__debug'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const endpoint of debugEndpoints) {
              if (content.includes(endpoint)) {
                hasDebugEndpoints = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-004',
      name: 'Debug Endpoints',
      description: 'Debug or admin endpoints may be exposed',
      category: 'network',
      severity: 'medium',
      passed: !hasDebugEndpoints,
      message: hasDebugEndpoints
        ? 'Debug/admin endpoints detected - ensure they are protected or disabled in production'
        : 'No obvious debug endpoints found',
      fixable: false,
      guidance: 'Debug and admin endpoints expose internal state, configuration, and metrics. Attackers use these to map your infrastructure and find weaknesses.',
    });

    // NET-005: Check for WebSocket security
    let hasWebsocket = false;
    let hasWsAuth = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasWebsocket = pkgJson.includes('ws') || pkgJson.includes('socket.io') || pkgJson.includes('websocket');

      if (hasWebsocket) {
        const files = await fs.readdir(targetDir);
        for (const file of files) {
          if (file.endsWith('.ts') || file.endsWith('.js')) {
            try {
              const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
              if (content.includes('verifyClient') || content.includes('handleUpgrade') || (content.includes('connection') && content.includes('auth'))) {
                hasWsAuth = true;
                break;
              }
            } catch {}
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'NET-005',
      name: 'WebSocket Security',
      description: 'WebSocket connections may lack authentication',
      category: 'network',
      severity: 'high',
      passed: !hasWebsocket || hasWsAuth,
      message: !hasWebsocket
        ? 'No WebSocket usage detected'
        : hasWsAuth
          ? 'WebSocket authentication detected'
          : 'WebSocket without obvious authentication - ensure connections are verified',
      fixable: false,
      guidance: 'Unauthenticated WebSocket connections let any client send commands to your backend. Unlike HTTP, WebSockets maintain persistent connections that bypass traditional request-based security.',
    });

    // NET-006: Check for proxy configuration
    let hasProxyConfig = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasProxyConfig = pkgJson.includes('http-proxy') || pkgJson.includes('express-http-proxy');
    } catch {}

    if (hasProxyConfig) {
      findings.push({
        checkId: 'NET-006',
        name: 'Proxy Configuration',
        description: 'HTTP proxy detected - ensure proper access controls',
        category: 'network',
        severity: 'medium',
        passed: true, // Informational
        message: 'HTTP proxy library detected - verify SSRF protections are in place',
        fixable: false,
      guidance: 'HTTP proxies without SSRF protections allow attackers to reach internal services, cloud metadata endpoints, and private networks through your server.',
      });
    }

    return findings;
  }

  private async checkAPISecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // API-001: Check for API versioning
    let hasApiVersioning = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('/api/v1') || content.includes('/api/v2') || content.includes('version')) {
              hasApiVersioning = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-001',
      name: 'API Versioning',
      description: 'API versioning not detected',
      category: 'api',
      severity: 'low',
      passed: hasApiVersioning,
      message: hasApiVersioning
        ? 'API versioning pattern detected'
        : 'Consider implementing API versioning for backwards compatibility',
      fixable: false,
      guidance: 'Without API versioning, breaking changes affect all clients immediately. Versioning enables safe deprecation and prevents accidental security regressions.',
    });

    // API-002: Check for API documentation
    let hasApiDocs = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasApiDocs = pkgJson.includes('swagger') || pkgJson.includes('openapi') || pkgJson.includes('@apidevtools');
    } catch {}

    findings.push({
      checkId: 'API-002',
      name: 'API Documentation',
      description: 'No API documentation library detected',
      category: 'api',
      severity: 'low',
      passed: hasApiDocs,
      message: hasApiDocs
        ? 'API documentation library detected'
        : 'Consider adding OpenAPI/Swagger documentation',
      fixable: false,
      guidance: 'Undocumented APIs are harder to use correctly and easier to misuse. Clear documentation reduces the chance of insecure integrations by consumers.',
    });

    // API-003: Check for API key in URL
    let hasKeyInUrl = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('apiKey=') || content.includes('api_key=') || content.includes('key=')) {
              if (content.includes('query') || content.includes('req.query')) {
                hasKeyInUrl = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-003',
      name: 'API Key in URL',
      description: 'API keys may be passed in URL query parameters',
      category: 'api',
      severity: 'high',
      passed: !hasKeyInUrl,
      message: hasKeyInUrl
        ? 'API key in URL pattern detected - use headers instead'
        : 'No obvious API key in URL patterns found',
      fixable: false,
      guidance: 'API keys in URLs are logged by browsers, proxies, and web servers. They appear in referrer headers and browser history, making them easy to steal.',
    });

    // API-004: Check for response headers security
    let hasSecurityHeaders = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('X-Content-Type-Options') || content.includes('X-Frame-Options') || content.includes('Content-Security-Policy')) {
              hasSecurityHeaders = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'API-004',
      name: 'API Security Headers',
      description: 'Security headers not explicitly set',
      category: 'api',
      severity: 'medium',
      passed: hasSecurityHeaders,
      message: hasSecurityHeaders
        ? 'Security headers detected in responses'
        : 'Add security headers (X-Content-Type-Options, X-Frame-Options, CSP)',
      fixable: false,
      guidance: 'Missing security headers like X-Frame-Options and CSP leave your API responses vulnerable to clickjacking, MIME-sniffing, and cross-site scripting attacks.',
    });

    return findings;
  }

  private async checkSecretManagement(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // SEC-001: Check for secret management tools
    let hasSecretManager = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasSecretManager = pkgJson.includes('vault') || pkgJson.includes('aws-sdk') || pkgJson.includes('dotenv-vault') || pkgJson.includes('1password');
    } catch {}

    findings.push({
      checkId: 'SEC-001',
      name: 'Secret Management',
      description: 'No secret management tool detected',
      category: 'secrets',
      severity: 'medium',
      passed: hasSecretManager,
      message: hasSecretManager
        ? 'Secret management capability detected'
        : 'Consider using a secret manager (Vault, AWS Secrets Manager, doppler)',
      fixable: false,
      guidance: 'Without a secret manager, credentials end up in .env files, config files, or source code where they can be leaked through version control or log files.',
    });

    // SEC-002: Check for encryption library
    let hasEncryption = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasEncryption = pkgJson.includes('crypto') || pkgJson.includes('bcrypt') || pkgJson.includes('argon2') || pkgJson.includes('sodium');
    } catch {}

    findings.push({
      checkId: 'SEC-002',
      name: 'Encryption Library',
      description: 'No encryption library detected',
      category: 'secrets',
      severity: 'medium',
      passed: hasEncryption,
      message: hasEncryption
        ? 'Encryption library detected'
        : 'Consider using encryption for sensitive data (bcrypt, argon2)',
      fixable: false,
      guidance: 'Without encryption, sensitive data like passwords and tokens are stored in plaintext. A database breach or file leak exposes everything immediately.',
    });

    // SEC-003: Check for key rotation support
    let hasKeyRotation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        try {
          const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
          if (content.includes('rotation') || content.includes('rotate') || content.includes('KEY_VERSION')) {
            hasKeyRotation = true;
            break;
          }
        } catch {}
      }
    } catch {}

    findings.push({
      checkId: 'SEC-003',
      name: 'Key Rotation Support',
      description: 'No key rotation mechanism detected',
      category: 'secrets',
      severity: 'low',
      passed: hasKeyRotation,
      message: hasKeyRotation
        ? 'Key rotation support detected'
        : 'Consider implementing key rotation for long-lived secrets',
      fixable: false,
      guidance: 'Without key rotation, a single compromised key grants permanent access. Regular rotation limits the window of exposure when a key is leaked.',
    });

    // SEC-004: Check for hardcoded connection strings
    let hasHardcodedConnStr = false;
    const connPatterns = ['mongodb://', 'postgres://', 'mysql://', 'redis://', 'amqp://'];

    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            for (const pattern of connPatterns) {
              if (content.includes(pattern) && !content.includes('${') && !content.includes('process.env')) {
                hasHardcodedConnStr = true;
                break;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SEC-004',
      name: 'Hardcoded Connection Strings',
      description: 'Connection strings may be hardcoded',
      category: 'secrets',
      severity: 'critical',
      passed: !hasHardcodedConnStr,
      message: hasHardcodedConnStr
        ? 'Hardcoded connection strings detected'
        : 'No hardcoded connection strings found',
      fixable: false,
      fix: hasHardcodedConnStr ? 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.' : undefined,
      guidance: 'Hardcoded connection strings contain database hostnames, ports, and credentials. Anyone with code access can connect directly to your database.',
    });

    return findings;
  }

  private async checkIOSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // IO-001: Check for file upload handling
    let hasFileUpload = false;
    let hasUploadSecurity = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasFileUpload = pkgJson.includes('multer') || pkgJson.includes('formidable') || pkgJson.includes('busboy');

      if (hasFileUpload) {
        const files = await fs.readdir(targetDir);
        for (const file of files) {
          if (file.endsWith('.ts') || file.endsWith('.js')) {
            try {
              const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
              if (content.includes('fileFilter') || content.includes('limits') || content.includes('mimetype')) {
                hasUploadSecurity = true;
                break;
              }
            } catch {}
          }
        }
      }
    } catch {}

    findings.push({
      checkId: 'IO-001',
      name: 'File Upload Security',
      description: 'File upload without proper validation',
      category: 'io',
      severity: 'high',
      passed: !hasFileUpload || hasUploadSecurity,
      message: !hasFileUpload
        ? 'No file upload handling detected'
        : hasUploadSecurity
          ? 'File upload validation detected'
          : 'File upload without obvious validation - add file type/size limits',
      fixable: false,
      guidance: 'Unrestricted file uploads let attackers send malicious executables, web shells, or oversized files that can compromise the server or exhaust disk space.',
    });

    // IO-002: Check for SQL/NoSQL injection protection
    let hasDbLibrary = false;
    let hasParameterization = false;

    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasDbLibrary = pkgJson.includes('pg') || pkgJson.includes('mysql') || pkgJson.includes('mongodb') || pkgJson.includes('prisma') || pkgJson.includes('sequelize');

      if (hasDbLibrary) {
        // ORMs and query builders generally handle parameterization
        hasParameterization = pkgJson.includes('prisma') || pkgJson.includes('sequelize') || pkgJson.includes('typeorm') || pkgJson.includes('knex');
      }
    } catch {}

    findings.push({
      checkId: 'IO-002',
      name: 'Query Parameterization',
      description: 'Database queries may be vulnerable to injection',
      category: 'io',
      severity: 'critical',
      passed: !hasDbLibrary || hasParameterization,
      message: !hasDbLibrary
        ? 'No database library detected'
        : hasParameterization
          ? 'ORM/query builder detected - provides parameterization'
          : 'Raw database driver detected - ensure parameterized queries are used',
      fixable: false,
      guidance: 'Raw database queries built with string concatenation let attackers inject SQL or NoSQL commands that can read, modify, or delete all data in the database.',
    });

    // IO-003: Check for XSS protection
    let hasXssProtection = false;
    try {
      const pkgJson = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      hasXssProtection = pkgJson.includes('xss') || pkgJson.includes('sanitize') || pkgJson.includes('DOMPurify') || pkgJson.includes('helmet');
    } catch {}

    findings.push({
      checkId: 'IO-003',
      name: 'XSS Protection',
      description: 'No XSS protection library detected',
      category: 'io',
      severity: 'high',
      passed: hasXssProtection,
      message: hasXssProtection
        ? 'XSS protection library detected'
        : 'No XSS protection library found - sanitize user input before rendering',
      fixable: false,
      guidance: 'Without XSS protection, user-supplied content rendered in the browser can execute arbitrary JavaScript, stealing session tokens and user data.',
    });

    // IO-004: Check for path traversal protection
    let hasPathTraversal = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            // Check for dangerous patterns
            if (content.includes('req.params') && content.includes('readFile')) {
              if (!content.includes('path.normalize') && !content.includes('path.resolve')) {
                hasPathTraversal = true;
              }
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'IO-004',
      name: 'Path Traversal Protection',
      description: 'Potential path traversal vulnerability',
      category: 'io',
      severity: 'high',
      passed: !hasPathTraversal,
      message: hasPathTraversal
        ? 'Potential path traversal detected - use path.resolve/normalize'
        : 'No obvious path traversal vulnerabilities found',
      fixable: false,
      guidance: 'Path traversal (../) in file paths lets attackers read sensitive files like /etc/passwd or .env by escaping the intended directory.',
    });

    return findings;
  }

  /**
   * Prompt injection defense checks
   */
  private async checkPromptSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // PROMPT-001: Check for system prompt boundary markers
    let hasPromptBoundaries = false;
    const claudeMdPath = path.join(targetDir, 'CLAUDE.md');
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasPromptBoundaries =
        content.includes('SYSTEM:') ||
        content.includes('USER:') ||
        content.includes('---') ||
        content.includes('###') ||
        content.toLowerCase().includes('do not follow instructions') ||
        content.toLowerCase().includes('ignore attempts to');
    } catch {}

    findings.push({
      checkId: 'PROMPT-001',
      name: 'Prompt Boundary Markers',
      description: 'System prompts should have clear boundary markers to prevent injection',
      category: 'prompt-security',
      severity: 'high',
      passed: hasPromptBoundaries,
      message: hasPromptBoundaries
        ? 'Prompt boundaries detected in CLAUDE.md'
        : 'Consider adding prompt boundary markers to prevent injection attacks',
      fixable: false,
      guidance: 'Without clear boundary markers, attackers can inject instructions that blend with the system prompt, making it impossible for the model to distinguish trusted from untrusted content.',
    });

    // PROMPT-002: Check for injection defense instructions
    let hasInjectionDefense = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasInjectionDefense =
        content.toLowerCase().includes('injection') ||
        content.toLowerCase().includes('malicious') ||
        content.toLowerCase().includes('untrusted') ||
        content.toLowerCase().includes('sanitize') ||
        content.toLowerCase().includes('validate input');
    } catch {}

    findings.push({
      checkId: 'PROMPT-002',
      name: 'Injection Defense Instructions',
      description: 'System prompts should include injection defense guidance',
      category: 'prompt-security',
      severity: 'medium',
      passed: hasInjectionDefense,
      message: hasInjectionDefense
        ? 'Injection defense instructions found'
        : 'Consider adding injection defense instructions to system prompts',
      fixable: false,
      guidance: 'System prompts without injection defenses can be overridden by user inputs that say "ignore previous instructions", bypassing all safety rules.',
    });

    // PROMPT-003: Check for output constraints
    let hasOutputConstraints = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasOutputConstraints =
        content.toLowerCase().includes('never output') ||
        content.toLowerCase().includes('do not reveal') ||
        content.toLowerCase().includes('do not disclose') ||
        content.toLowerCase().includes('keep confidential') ||
        content.toLowerCase().includes('do not share');
    } catch {}

    findings.push({
      checkId: 'PROMPT-003',
      name: 'Output Confidentiality Rules',
      description: 'System prompts should define output confidentiality constraints',
      category: 'prompt-security',
      severity: 'medium',
      passed: hasOutputConstraints,
      message: hasOutputConstraints
        ? 'Output confidentiality rules defined'
        : 'Consider defining what information should not be disclosed',
      fixable: false,
      guidance: 'Without output confidentiality rules, the agent may freely reveal system prompts, internal tool names, API keys, or other sensitive context when asked.',
    });

    // PROMPT-004: Check for role confusion protection
    let hasRoleProtection = false;
    try {
      const content = await fs.readFile(claudeMdPath, 'utf-8');
      hasRoleProtection =
        content.toLowerCase().includes('you are') ||
        content.toLowerCase().includes('your role') ||
        content.toLowerCase().includes('as an assistant') ||
        content.toLowerCase().includes('maintain your role');
    } catch {}

    findings.push({
      checkId: 'PROMPT-004',
      name: 'Role Definition Protection',
      description: 'System prompts should clearly define the AI role to prevent confusion attacks',
      category: 'prompt-security',
      severity: 'low',
      passed: hasRoleProtection,
      message: hasRoleProtection
        ? 'Role definition found in prompts'
        : 'Consider clearly defining the AI role to prevent role confusion attacks',
      fixable: false,
      guidance: 'Without a clear role definition, attackers can use "you are now a hacker assistant" style prompts to override the agent identity and bypass safety constraints.',
    });

    return findings;
  }

  /**
   * Input validation and sanitization checks
   */
  private async checkInputValidation(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // INJ-001: Check for input validation in MCP handlers
    let hasInputValidation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('zod') ||
              content.includes('joi') ||
              content.includes('yup') ||
              content.includes('validate(') ||
              content.includes('sanitize(') ||
              content.includes('schema.')
            ) {
              hasInputValidation = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-001',
      name: 'Input Validation Library',
      description: 'Applications should use schema validation for inputs',
      category: 'input-validation',
      severity: 'high',
      passed: hasInputValidation,
      message: hasInputValidation
        ? 'Input validation library detected'
        : 'Consider using zod, joi, or similar for input validation',
      fixable: false,
      guidance: 'Without schema validation, any malformed or malicious input reaches your application logic. This is the root cause of injection, overflow, and type confusion attacks.',
    });

    // INJ-002: Check for XSS protection patterns
    let hasXssProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('escapeHtml') ||
              content.includes('sanitizeHtml') ||
              content.includes('DOMPurify') ||
              content.includes('xss(') ||
              content.includes('encode(')
            ) {
              hasXssProtection = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-002',
      name: 'XSS Protection',
      description: 'Output should be properly escaped to prevent XSS',
      category: 'input-validation',
      severity: 'high',
      passed: hasXssProtection,
      message: hasXssProtection
        ? 'XSS protection patterns detected'
        : 'Consider implementing output escaping for user-facing content',
      fixable: false,
      guidance: 'Unescaped user content rendered in HTML lets attackers inject scripts that steal cookies, hijack sessions, and impersonate users.',
    });

    // INJ-003: Check for SQL injection protection
    let hasSqlProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('parameterized') ||
              content.includes('prepared') ||
              content.includes('$1') ||
              content.includes('?') && content.includes('query(') ||
              content.includes('prisma') ||
              content.includes('knex') ||
              content.includes('sequelize')
            ) {
              hasSqlProtection = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'INJ-003',
      name: 'SQL Injection Protection',
      description: 'Database queries should use parameterized statements',
      category: 'input-validation',
      severity: 'critical',
      passed: hasSqlProtection,
      message: hasSqlProtection
        ? 'Parameterized queries or ORM detected'
        : 'Ensure all database queries use parameterized statements',
      fixable: false,
      guidance: 'SQL injection via string concatenation lets attackers read, modify, or delete any data in your database. Parameterized queries prevent this entirely.',
    });

    // INJ-004: Check for command injection protection
    let hasCmdProtection = false;
    try {
      const files = await fs.readdir(targetDir);
      let hasExec = false;
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (content.includes('exec(') || content.includes('spawn(')) {
              hasExec = true;
              if (
                content.includes('execFile') ||
                content.includes('shell: false') ||
                content.includes('shellEscape') ||
                !content.includes('${')
              ) {
                hasCmdProtection = true;
              }
            }
          } catch {}
        }
      }
      if (!hasExec) hasCmdProtection = true; // No exec calls found
    } catch {
      hasCmdProtection = true;
    }

    findings.push({
      checkId: 'INJ-004',
      name: 'Command Injection Protection',
      description: 'Shell commands should use safe execution patterns',
      category: 'input-validation',
      severity: 'critical',
      passed: hasCmdProtection,
      message: hasCmdProtection
        ? 'Safe command execution patterns detected or no shell commands found'
        : 'Use execFile instead of exec, or disable shell interpolation',
      fixable: false,
      guidance: 'Using exec() with user-controlled input lets attackers inject shell metacharacters (;, |, $()) to run arbitrary commands on the host system.',
    });

    return findings;
  }

  /**
   * Rate limiting and throttling checks
   */
  private async checkRateLimiting(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // RATE-001: Check for rate limiting configuration
    let hasRateLimiting = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasRateLimiting =
        'express-rate-limit' in deps ||
        'rate-limiter-flexible' in deps ||
        'bottleneck' in deps ||
        '@upstash/ratelimit' in deps;
    } catch {}

    findings.push({
      checkId: 'RATE-001',
      name: 'Rate Limiting Configuration',
      description: 'API endpoints should have rate limiting',
      category: 'rate-limiting',
      severity: 'medium',
      passed: hasRateLimiting,
      message: hasRateLimiting
        ? 'Rate limiting library detected'
        : 'Consider implementing rate limiting to prevent abuse',
      fixable: false,
      guidance: 'Without rate limiting, attackers can make unlimited API calls, exhausting your quota and running up costs. It also enables brute-force and credential stuffing attacks.',
    });

    // RATE-002: Check for retry/backoff patterns
    let hasBackoff = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('retry') ||
              content.includes('backoff') ||
              content.includes('exponential') ||
              content.includes('p-retry')
            ) {
              hasBackoff = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-002',
      name: 'Retry with Backoff',
      description: 'External calls should implement exponential backoff',
      category: 'rate-limiting',
      severity: 'low',
      passed: hasBackoff,
      message: hasBackoff
        ? 'Retry/backoff patterns detected'
        : 'Consider implementing exponential backoff for external calls',
      fixable: false,
      guidance: 'Without exponential backoff, retries hammer external services at full speed during outages, worsening the problem and potentially getting your API key banned.',
    });

    // RATE-003: Check for timeout configurations
    let hasTimeouts = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('timeout') ||
              content.includes('Timeout') ||
              content.includes('TIMEOUT')
            ) {
              hasTimeouts = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-003',
      name: 'Timeout Configuration',
      description: 'Operations should have appropriate timeouts',
      category: 'rate-limiting',
      severity: 'medium',
      passed: hasTimeouts,
      message: hasTimeouts
        ? 'Timeout configurations detected'
        : 'Consider setting timeouts for external calls and long-running operations',
      fixable: false,
      guidance: 'Without timeouts, a slow or unresponsive external service can cause your application to hang indefinitely, tying up connections and eventually crashing.',
    });

    // RATE-004: Check for concurrent request limiting
    let hasConcurrencyLimit = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('p-limit') ||
              content.includes('semaphore') ||
              content.includes('concurrency') ||
              content.includes('maxConcurrent')
            ) {
              hasConcurrencyLimit = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'RATE-004',
      name: 'Concurrency Limits',
      description: 'Concurrent operations should be limited',
      category: 'rate-limiting',
      severity: 'low',
      passed: hasConcurrencyLimit,
      message: hasConcurrencyLimit
        ? 'Concurrency limiting detected'
        : 'Consider limiting concurrent operations to prevent resource exhaustion',
      fixable: false,
      guidance: 'Without concurrency limits, a burst of requests can spawn unbounded parallel operations that exhaust memory, file descriptors, and CPU, crashing the service.',
    });

    return findings;
  }

  /**
   * Session and timeout security checks
   */
  private async checkSessionSecurity(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // SESSION-001: Check for secure session configuration
    let hasSecureSessions = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('httpOnly') ||
              content.includes('secure: true') ||
              content.includes('sameSite')
            ) {
              hasSecureSessions = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-001',
      name: 'Secure Cookie Settings',
      description: 'Session cookies should have secure flags',
      category: 'session-security',
      severity: 'high',
      passed: hasSecureSessions,
      message: hasSecureSessions
        ? 'Secure cookie flags detected'
        : 'Set httpOnly, secure, and sameSite on session cookies',
      fixable: false,
      guidance: 'Session cookies without secure flags can be stolen via XSS (missing httpOnly), sent over plain HTTP (missing secure), or exploited in cross-site attacks (missing sameSite).',
    });

    // SESSION-002: Check for session expiry
    let hasSessionExpiry = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('maxAge') ||
              content.includes('expiresIn') ||
              content.includes('ttl') ||
              content.includes('sessionTimeout')
            ) {
              hasSessionExpiry = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-002',
      name: 'Session Expiry',
      description: 'Sessions should have appropriate expiry times',
      category: 'session-security',
      severity: 'medium',
      passed: hasSessionExpiry,
      message: hasSessionExpiry
        ? 'Session expiry configuration detected'
        : 'Configure appropriate session expiry times',
      fixable: false,
      guidance: 'Sessions without expiry remain valid indefinitely. A stolen session token grants permanent access until the server is restarted or the token is manually revoked.',
    });

    // SESSION-003: Check for CSRF protection
    let hasCsrfProtection = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasCsrfProtection = 'csurf' in deps || 'csrf' in deps || '@fastify/csrf-protection' in deps;
    } catch {}

    findings.push({
      checkId: 'SESSION-003',
      name: 'CSRF Protection',
      description: 'Forms should have CSRF protection',
      category: 'session-security',
      severity: 'high',
      passed: hasCsrfProtection,
      message: hasCsrfProtection
        ? 'CSRF protection library detected'
        : 'Consider implementing CSRF protection for state-changing operations',
      fixable: false,
      guidance: 'Without CSRF protection, a malicious website can trick authenticated users into performing unwanted actions (transfers, password changes, data deletion) by forging requests from their browser.',
    });

    // SESSION-004: Check for secure token storage
    let hasSecureStorage = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('keytar') ||
              content.includes('secure-store') ||
              content.includes('keychain') ||
              content.includes('credential-store')
            ) {
              hasSecureStorage = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'SESSION-004',
      name: 'Secure Token Storage',
      description: 'Tokens should be stored securely',
      category: 'session-security',
      severity: 'medium',
      passed: hasSecureStorage,
      message: hasSecureStorage
        ? 'Secure token storage detected'
        : 'Consider using secure storage for sensitive tokens',
      fixable: false,
      guidance: 'Tokens stored in plaintext files or localStorage can be stolen by any process with file access or XSS attack, allowing full account takeover without credentials.',
    });

    return findings;
  }

  /**
   * Data encryption checks
   */
  private async checkEncryption(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // ENCRYPT-001: Check for encryption at rest
    let hasEncryption = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('crypto') ||
              content.includes('encrypt') ||
              content.includes('aes-') ||
              content.includes('sodium')
            ) {
              hasEncryption = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-001',
      name: 'Encryption Implementation',
      description: 'Sensitive data should be encrypted at rest',
      category: 'encryption',
      severity: 'high',
      passed: hasEncryption,
      message: hasEncryption
        ? 'Encryption implementation detected'
        : 'Consider encrypting sensitive data at rest',
      fixable: false,
      guidance: 'Without encryption at rest, anyone with disk access (stolen laptop, compromised server, backup leak) can read sensitive data including credentials and user information.',
    });

    // ENCRYPT-002: Check for secure hashing
    let hasSecureHashing = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('bcrypt') ||
              content.includes('argon2') ||
              content.includes('scrypt') ||
              content.includes('pbkdf2')
            ) {
              hasSecureHashing = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-002',
      name: 'Secure Password Hashing',
      description: 'Passwords should use secure hashing algorithms',
      category: 'encryption',
      severity: 'critical',
      passed: hasSecureHashing,
      message: hasSecureHashing
        ? 'Secure hashing algorithm detected (bcrypt/argon2/scrypt)'
        : 'Use bcrypt, argon2, or scrypt for password hashing',
      fixable: false,
      guidance: 'Passwords hashed with fast algorithms (MD5, SHA1) can be cracked in bulk using rainbow tables or GPU brute-force. Bcrypt, argon2, and scrypt are deliberately slow to resist this.',
    });

    // ENCRYPT-003: Check for weak algorithms
    let hasWeakAlgorithms = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('md5') ||
              content.includes('sha1') ||
              content.includes("'des'") ||
              content.includes('"des"')
            ) {
              hasWeakAlgorithms = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-003',
      name: 'Weak Cryptographic Algorithms',
      description: 'Avoid using weak cryptographic algorithms',
      category: 'encryption',
      severity: 'high',
      passed: !hasWeakAlgorithms,
      message: hasWeakAlgorithms
        ? 'Weak algorithms detected (MD5/SHA1/DES) - use SHA-256+ and AES'
        : 'No weak cryptographic algorithms detected',
      fixable: false,
      guidance: 'MD5 and SHA1 have known collision attacks, and DES has a 56-bit key easily brute-forced with modern hardware. Data protected by these algorithms should be considered unprotected.',
    });

    // ENCRYPT-004: Check for TLS configuration
    let hasTlsConfig = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('https') ||
              content.includes('tls') ||
              content.includes('ssl') ||
              content.includes('rejectUnauthorized')
            ) {
              hasTlsConfig = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'ENCRYPT-004',
      name: 'TLS Configuration',
      description: 'Communications should use TLS',
      category: 'encryption',
      severity: 'high',
      passed: hasTlsConfig,
      message: hasTlsConfig
        ? 'TLS/HTTPS configuration detected'
        : 'Ensure all communications use TLS',
      fixable: false,
      guidance: 'Without TLS, all network traffic including credentials, tokens, and sensitive data is transmitted in plaintext and can be intercepted by anyone on the network path.',
    });

    return findings;
  }

  /**
   * Audit trail and logging security checks
   */
  private async checkAuditTrail(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // AUDIT-001: Check for audit logging
    let hasAuditLogging = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('audit') ||
              content.includes('winston') ||
              content.includes('pino') ||
              content.includes('bunyan')
            ) {
              hasAuditLogging = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-001',
      name: 'Audit Logging',
      description: 'Security-relevant events should be logged',
      category: 'audit',
      severity: 'medium',
      passed: hasAuditLogging,
      message: hasAuditLogging
        ? 'Audit logging implementation detected'
        : 'Consider implementing audit logging for security events',
      fixable: false,
      guidance: 'Missing audit logs mean you cannot detect or investigate security incidents after they occur. Attackers operate undetected and forensic analysis becomes impossible.',
    });

    // AUDIT-002: Check for log rotation
    let hasLogRotation = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js') || file.endsWith('.json')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('rotate') ||
              content.includes('maxFiles') ||
              content.includes('maxSize')
            ) {
              hasLogRotation = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-002',
      name: 'Log Rotation',
      description: 'Logs should have rotation configured',
      category: 'audit',
      severity: 'low',
      passed: hasLogRotation,
      message: hasLogRotation
        ? 'Log rotation configuration detected'
        : 'Consider configuring log rotation to manage disk space',
      fixable: false,
      guidance: 'Without log rotation, logs grow until they fill the disk, causing service outages. Attackers can also exploit this to trigger denial-of-service by generating excessive log entries.',
    });

    // AUDIT-003: Check for error tracking
    let hasErrorTracking = false;
    try {
      const pkgPath = path.join(targetDir, 'package.json');
      const content = await fs.readFile(pkgPath, 'utf-8');
      const pkg = JSON.parse(content);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      hasErrorTracking = '@sentry/node' in deps || 'bugsnag' in deps || 'rollbar' in deps;
    } catch {}

    findings.push({
      checkId: 'AUDIT-003',
      name: 'Error Tracking',
      description: 'Errors should be tracked for monitoring',
      category: 'audit',
      severity: 'low',
      passed: hasErrorTracking,
      message: hasErrorTracking
        ? 'Error tracking service detected'
        : 'Consider using an error tracking service for production',
      fixable: false,
      guidance: 'Without error tracking, security-related failures (auth errors, injection attempts, rate limit hits) go unnoticed in production, giving attackers time to refine their approach.',
    });

    // AUDIT-004: Check for no sensitive data in logs
    let hasLogSanitization = false;
    try {
      const files = await fs.readdir(targetDir);
      for (const file of files) {
        if (file.endsWith('.ts') || file.endsWith('.js')) {
          try {
            const content = await fs.readFile(path.join(targetDir, file), 'utf-8');
            if (
              content.includes('redact') ||
              content.includes('mask') ||
              content.includes('sanitize')
            ) {
              hasLogSanitization = true;
              break;
            }
          } catch {}
        }
      }
    } catch {}

    findings.push({
      checkId: 'AUDIT-004',
      name: 'Log Sanitization',
      description: 'Sensitive data should be redacted from logs',
      category: 'audit',
      severity: 'high',
      passed: hasLogSanitization,
      message: hasLogSanitization
        ? 'Log sanitization patterns detected'
        : 'Consider redacting sensitive data (passwords, tokens) from logs',
      fixable: false,
      guidance: 'Unsanitized logs containing passwords, tokens, or PII become a secondary breach vector. Log aggregation services, backups, and support teams all gain access to sensitive data.',
    });

    return findings;
  }

  /**
   * Process isolation and sandboxing checks
   */
  private async checkSandboxing(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // SANDBOX-001: Check for Docker/container usage
    let hasContainerization = false;
    try {
      await fs.access(path.join(targetDir, 'Dockerfile'));
      hasContainerization = true;
    } catch {}
    try {
      await fs.access(path.join(targetDir, 'docker-compose.yml'));
      hasContainerization = true;
    } catch {}
    try {
      await fs.access(path.join(targetDir, 'docker-compose.yaml'));
      hasContainerization = true;
    } catch {}

    findings.push({
      checkId: 'SANDBOX-001',
      name: 'Container Isolation',
      description: 'Applications should run in isolated containers',
      category: 'sandboxing',
      severity: 'medium',
      passed: hasContainerization,
      message: hasContainerization
        ? 'Container configuration detected'
        : 'Consider running in Docker containers for isolation',
      fixable: false,
      guidance: 'Without container isolation, a compromised application has direct access to the host filesystem, network, and other processes. Containers limit the blast radius of a breach.',
    });

    // SANDBOX-002: Check for non-root execution
    let hasNonRootConfig = false;
    try {
      const dockerPath = path.join(targetDir, 'Dockerfile');
      const content = await fs.readFile(dockerPath, 'utf-8');
      hasNonRootConfig = content.includes('USER ') && !content.includes('USER root');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-002',
      name: 'Non-Root Execution',
      description: 'Containers should not run as root',
      category: 'sandboxing',
      severity: 'high',
      passed: hasNonRootConfig,
      message: hasNonRootConfig
        ? 'Non-root user configured in Dockerfile'
        : 'Configure containers to run as non-root user',
      fixable: false,
      guidance: 'Containers running as root can escape container isolation more easily. A container breakout as root grants full control of the host system.',
    });

    // SANDBOX-003: Check for resource limits
    let hasResourceLimits = false;
    try {
      const composePath = path.join(targetDir, 'docker-compose.yml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasResourceLimits = content.includes('mem_limit') || content.includes('cpus') || content.includes('deploy:');
    } catch {}
    try {
      const composePath = path.join(targetDir, 'docker-compose.yaml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasResourceLimits = content.includes('mem_limit') || content.includes('cpus') || content.includes('deploy:');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-003',
      name: 'Resource Limits',
      description: 'Containers should have resource limits',
      category: 'sandboxing',
      severity: 'medium',
      passed: hasResourceLimits,
      message: hasResourceLimits
        ? 'Resource limits configured'
        : 'Consider setting CPU and memory limits for containers',
      fixable: false,
      guidance: 'Without resource limits, a single compromised or buggy container can consume all host CPU and memory, causing denial-of-service for every other service on the machine.',
    });

    // SANDBOX-004: Check for read-only filesystem
    let hasReadOnlyFs = false;
    try {
      const composePath = path.join(targetDir, 'docker-compose.yml');
      const content = await fs.readFile(composePath, 'utf-8');
      hasReadOnlyFs = content.includes('read_only: true');
    } catch {}

    findings.push({
      checkId: 'SANDBOX-004',
      name: 'Read-Only Filesystem',
      description: 'Containers should use read-only filesystem where possible',
      category: 'sandboxing',
      severity: 'low',
      passed: hasReadOnlyFs,
      message: hasReadOnlyFs
        ? 'Read-only filesystem configured'
        : 'Consider using read-only filesystem for containers',
      fixable: false,
      guidance: 'A writable filesystem allows attackers to drop malware, modify binaries, or plant persistence mechanisms inside the container. Read-only filesystems prevent post-exploitation tampering.',
    });

    return findings;
  }

  /**
   * MCP tool permission boundary checks
   */
  private async checkToolBoundaries(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const mcpConfigPath = path.join(targetDir, 'mcp.json');

    let mcpConfig: Record<string, unknown> | null = null;
    try {
      const content = await fs.readFile(mcpConfigPath, 'utf-8');
      mcpConfig = JSON.parse(content);
    } catch {}

    // TOOL-001: Check for tool whitelisting
    let hasToolWhitelist = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { allowedTools?: string[] }>)) {
        if (server.allowedTools && server.allowedTools.length > 0) {
          hasToolWhitelist = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'TOOL-001',
      name: 'Tool Whitelisting',
      description: 'MCP servers should have explicit tool whitelists',
      category: 'tool-boundaries',
      severity: 'high',
      passed: hasToolWhitelist,
      message: hasToolWhitelist
        ? 'Tool whitelisting configured'
        : 'Configure allowedTools to restrict MCP server capabilities',
      fixable: false,
      guidance: 'Without an explicit tool whitelist, MCP servers expose all available tools to the AI agent. A prompt injection attack can invoke any tool, including destructive ones.',
    });

    // TOOL-002: Check for resource constraints
    let hasResourceConstraints = false;
    if (mcpConfig?.servers) {
      for (const [, server] of Object.entries(mcpConfig.servers as Record<string, { maxTokens?: number; timeout?: number }>)) {
        if (server.maxTokens || server.timeout) {
          hasResourceConstraints = true;
          break;
        }
      }
    }

    findings.push({
      checkId: 'TOOL-002',
      name: 'Tool Resource Constraints',
      description: 'MCP tools should have resource constraints',
      category: 'tool-boundaries',
      severity: 'medium',
      passed: hasResourceConstraints,
      message: hasResourceConstraints
        ? 'Resource constraints configured'
        : 'Consider setting maxTokens and timeout for MCP tools',
      fixable: false,
      guidance: 'Without token limits and timeouts, a runaway or malicious tool call can consume unlimited API credits and block the agent indefinitely.',
    });

    // TOOL-003: Check for dangerous tool usage
    let hasDangerousTools = false;
    if (mcpConfig?.servers) {
      const dangerousTools = ['shell', 'exec', 'system', 'eval', 'run_command'];
      for (const [name] of Object.entries(mcpConfig.servers as Record<string, unknown>)) {
        for (const dangerous of dangerousTools) {
          if (name.toLowerCase().includes(dangerous)) {
            hasDangerousTools = true;
            break;
          }
        }
      }
    }

    findings.push({
      checkId: 'TOOL-003',
      name: 'Dangerous Tool Detection',
      description: 'Identify potentially dangerous MCP tools',
      category: 'tool-boundaries',
      severity: 'high',
      passed: !hasDangerousTools,
      message: hasDangerousTools
        ? 'Potentially dangerous tools detected (shell/exec) - ensure proper restrictions'
        : 'No obvious dangerous tools detected',
      fixable: false,
      guidance: 'Shell and exec tools give the AI agent arbitrary command execution on the host. A prompt injection can leverage these to exfiltrate data, install malware, or pivot to other systems.',
    });

    // TOOL-004: Check for tool confirmation requirements
    let hasConfirmation = false;
    try {
      const claudePath = path.join(targetDir, 'CLAUDE.md');
      const content = await fs.readFile(claudePath, 'utf-8');
      hasConfirmation =
        content.toLowerCase().includes('confirm') ||
        content.toLowerCase().includes('approval') ||
        content.toLowerCase().includes('ask before');
    } catch {}

    findings.push({
      checkId: 'TOOL-004',
      name: 'Tool Confirmation Requirements',
      description: 'Dangerous operations should require confirmation',
      category: 'tool-boundaries',
      severity: 'medium',
      passed: hasConfirmation,
      message: hasConfirmation
        ? 'Tool confirmation instructions detected'
        : 'Consider requiring confirmation for destructive operations',
      fixable: false,
      guidance: 'Without confirmation gates, the AI agent can execute destructive operations (file deletion, database drops, deployments) in a single step with no human checkpoint.',
    });

    return findings;
  }

  calculateScore(findings: SecurityFindingDraft[]): {
    score: number;
    maxScore: number;
  } {
    return calculateSecurityScore(findings);
  }

  /**
   * Settle a result's score from a findings set: recompute the composite and
   * re-apply the #259 verdict-band clamp in one step.
   *
   * The CLI recalculates the score at eight points after `scan()` returns
   * (post-NanoMind merge, post-infrastructure merge, post-.hmaignore
   * re-filter, per command). Every one of those must go through here — a
   * bare `calculateScore()` assignment silently drops the clamp and leaves
   * `scoreClamped` describing a score that no longer exists. Pass the same
   * findings array the verdict is built from, so the number and the verdict
   * can never be computed off different evidence.
   */
  applyScore(
    result: {
      score: number;
      rawScore?: number;
      scoreClamped?: boolean;
      scoreExcludingOwnArchive?: number;
    },
    findings: SecurityFindingDraft[],
  ): void {
    const { score: rawScore } = this.calculateScore(findings);
    const { score, clamped } = clampScoreToVerdictBand(rawScore, findings);
    result.score = score;
    result.rawScore = rawScore;
    result.scoreClamped = clamped;
    // #374 — re-derived here, from the same array, for the same reason the clamp
    // is: a merge that adds or drops findings moves both numbers, and a stale
    // live-tree figure beside a fresh headline would advertise a delta neither
    // number supports. Assigned unconditionally so it can also go back to
    // `undefined` when a re-filter removes the last archive finding.
    result.scoreExcludingOwnArchive = scoreExcludingOwnArchive(findings);
  }

  /**
   * The directory `--fix` stores backups under, resolved to a real directory
   * inside the scanned tree. Throws otherwise, which degrades the run to
   * detect-only rather than writing somewhere unintended.
   *
   * #321 — this used to be a bare `mkdir -p <target>/.hackmyagent-backup/<stamp>`
   * followed by `copyFile`, and both follow symlinks. One
   * `ln -s /attacker/drop <target>/.hackmyagent-backup` sent every backup copy,
   * `.env` included, out of the tree. Reproduced on the base commit as well as
   * on this branch, so it is not a regression from the unpushed range — but it
   * shares its root with #317/#318/#320, and the root is trusting a path string
   * where filesystem identity is needed.
   *
   * The base directory is REFUSED outright when it is a symlink, wherever it
   * points. Resolving it and accepting an in-tree target would still mean
   * backups landing somewhere the scanned tree chose, and this is the one
   * directory whose location HMA must own.
   */
  private async prepareBackupRoot(targetDir: string): Promise<string> {
    const targetReal = await fs.realpath(targetDir);
    const base = path.join(targetReal, BACKUP_DIR_NAME);

    try {
      // Non-recursive: `targetReal` exists (realpath just proved it), so the
      // only thing this can create is the base itself.
      await fs.mkdir(base);
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
    }

    // `lstat`, not `stat`: a symlink to a directory is a directory to `stat`,
    // which is exactly how #321 stayed invisible.
    const st = await fs.lstat(base);
    if (st.isSymbolicLink()) {
      throw backupSetupError(
        'HMA-BACKUP-SYMLINK',
        `${base} is a symbolic link, and backups are not written through a link.`,
      );
    }
    if (!st.isDirectory()) {
      throw backupSetupError(
        'HMA-BACKUP-NOT-DIR',
        `${base} exists and is not a directory, so backups cannot be stored there.`,
      );
    }

    // Canonical, including the ON-DISK CASING: everything downstream compares
    // against this, and a `.HACKMYAGENT-BACKUP` adopted by name would otherwise
    // leave the run's own paths spelled one way and read back another (#317).
    //
    // #334 — that property needs `realpath.native`. Measured on macOS with the
    // directory on disk named `.HACKMYAGENT-BACKUP`:
    //
    //   fs.realpathSync(".../.hackmyagent-backup")        -> ".../.hackmyagent-backup"
    //   fs.realpathSync.native(".../.hackmyagent-backup") -> ".../.HACKMYAGENT-BACKUP"
    //
    // The JS implementation returns the CALLER's spelling for the final
    // component, so the comment above described something the code did not do
    // and the lexical fast path in `isOwnBackupDir` almost never fired — one
    // `stat` per directory of every `--fix` walk, for a compare that could not
    // match. Identity covered the gap, which is why nothing broke; correctness
    // of the stated property and the cost are both worth fixing.
    //
    // Sync because there is no promises-API `.native` (Node exposes it on the
    // callback and sync forms only), and because this runs once per run.
    const baseReal = fsSync.realpathSync.native(base);
    if (!this.isPathWithinDirectory(baseReal, targetReal)) {
      throw backupSetupError(
        'HMA-BACKUP-OUTSIDE-TREE',
        `${base} resolves to ${baseReal}, which is outside the scanned tree.`,
      );
    }
    return baseReal;
  }

  /**
   * The run's own backup directory, created and PROVEN new.
   *
   * #320 — the stamp was `YYYY-MM-DD-HHMMSS` in UTC and the `mkdir` was
   * `recursive: true`, which silently ADOPTS an existing directory. So the
   * scanned tree could name HMA's own backup by guessing a second, turning a
   * CRITICAL into a silent drop and moving the score UP. Two independent
   * reproductions, kept apart rather than blended (#334):
   *
   *   the #320 report          125 pre-seeded stamps, 126 CRED-001 detect-only
   *                            vs 125 under `--fix`
   *   this stack's own run      90 pre-seeded stamps,  91 CRED-001 detect-only
   *                            vs  90 under `--fix`, score 13 -> 14
   *
   * "Unforgeable by construction" was false either way, and 86,400 empty
   * directories cover a whole day.
   *
   * Two independent properties, either of which suffices:
   *   - a random component the tree cannot predict, and
   *   - a NON-recursive `mkdir`, which fails EEXIST instead of adopting. On a
   *     case-insensitive filesystem EEXIST also fires for a case variant, so a
   *     pre-seeded `.../2026-07-29-120000-AB12CD34` cannot become this run's
   *     backup either.
   *
   * The time-ordered prefix stays: `rollback` selects the latest backup by
   * lexical sort, so the NAME has to sort in creation order.
   *
   * #332 — adding the random suffix broke exactly that, and the comment here
   * asserting the invariant was the only thing left holding it. Two backups
   * created inside one second sorted by random hex: measured at the primitive
   * level, 5 of 6 trials selected the OLDER backup, which leaves run 2's
   * generated files in place, deletes run 1's copies, and lets a second
   * rollback restore already-redacted content — #317's shape again.
   *
   * Two changes, so the ordering component is decided by time and only by time:
   *
   *   - the stamp carries MILLISECONDS. Two `createBackup` calls were measured
   *     2-6ms apart, so seconds were not enough resolution to order them.
   *   - within one millisecond, a fixed-width SEQUENCE derived from what is
   *     already in the base orders the siblings. That is what makes sequential
   *     creation deterministic rather than merely likely.
   *
   * The random component stays (that is #320) but no longer decides anything.
   * Truly concurrent creation in the same millisecond by two processes is still
   * a tie — neither is "later" at that resolution — and the concurrency test
   * covers what matters there: neither run adopts or deletes the other's backup.
   *
   * Names written by earlier versions (`YYYY-MM-DD-HHMMSS-<rand>`) sort BELOW a
   * new name from the same second, since a digit outranks the `-` that follows
   * the seconds field. That is the correct order: the new one is later.
   */
  private async createRunBackupDir(baseReal: string): Promise<string> {
    const stamp = new Date()
      .toISOString()
      .slice(0, 23)
      .replace('T', '-')
      .replace(/[:.]/g, '');
    const seq = await this.nextStampSequence(baseReal, stamp);

    let lastErr: unknown;
    for (let attempt = 0; attempt < 8; attempt++) {
      const dir = path.join(
        baseReal,
        `${stamp}-${stampSequenceField(seq, attempt)}`
        + `-${crypto.randomBytes(4).toString('hex')}`,
      );
      try {
        await fs.mkdir(dir);
        return dir;
      } catch (err) {
        lastErr = err;
        // Anything other than "it already exists" is a real filesystem
        // failure and must degrade the run, not be retried 8 times.
        if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
      }
    }
    throw backupSetupError(
      'HMA-BACKUP-NO-NEW-DIR',
      `Could not create a new backup directory under ${baseReal} after 8 attempts`
      + `${lastErr instanceof Error ? `: ${lastErr.message}` : '.'}`,
    );
  }

  /**
   * The next ordering slot for `stamp`: one past the highest sequence already
   * recorded for that same millisecond in this base.
   *
   * Reading the base is what makes SEQUENTIAL creation deterministic rather than
   * merely probable — run 1 is on disk before run 2 asks. Two processes asking
   * at the same instant can still choose the same slot, which is the tie the
   * millisecond stamp has already declared.
   *
   * Fails to zero: an unreadable base leaves ordering to the millisecond stamp,
   * which is the behaviour without this function at all, and never blocks a
   * backup — this is an ordering aid, not a guard.
   */
  private async nextStampSequence(baseReal: string, stamp: string): Promise<number> {
    try {
      const entries = await fs.readdir(baseReal);
      let highest = -1;
      for (const entry of entries) {
        if (!entry.startsWith(`${stamp}-`)) continue;
        const seq = Number.parseInt(entry.slice(stamp.length + 1, stamp.length + 4), 10);
        if (Number.isFinite(seq) && seq > highest) highest = seq;
      }
      return Math.min(highest + 1, 998);
    } catch {
      return 0;
    }
  }

  /**
   * Create a backup of files that may be modified during auto-fix
   */
  private async createBackup(targetDir: string): Promise<string> {
    const backupDir = await this.createRunBackupDir(await this.prepareBackupRoot(targetDir));

    // The identity of the directory just created, captured once. Every later
    // "is this inside the backup?" question is answered against this rather
    // than against a path string — see `isInsideOwnBackup` (#317).
    //
    // #347.3 — this used to go through `identityOrUndefined`, which collapses
    // the three-valued probe back into two and throws away exactly the
    // distinction #333 added it for. An EACCES, ELOOP or EIO on the directory
    // `mkdir` had just returned was reported as `HMA-BACKUP-VANISHED —
    // disappeared immediately after being created`, which is a claim about the
    // filesystem that only ENOENT supports, and it sent the user looking for a
    // race that is not there.
    this.lastBackupIdent = backupIdentityOrThrow(await identityOf(backupDir), backupDir);

    // Create manifest to track what existed before.
    //
    // `absentAtBackup` is the candidate set, NOT a claim that auto-fix
    // created any of it. Pre-0.25.1 this list was written straight into
    // `createdFiles` and rollback unlinked every entry, so a `package.json`
    // or `CLAUDE.md` the user wrote between `--fix` and `rollback` was
    // deleted as if HMA had generated it (#262). `createdFiles` is now
    // filled in after the fixes run, by recordCreatedFiles(), and carries
    // the content hash of what was actually generated.
    const manifest: BackupManifest = {
      version: BACKUP_MANIFEST_VERSION,
      existingFiles: [],
      absentAtBackup: [],
      createdFiles: [],
    };

    // Backup each file that exists (static list + skill + web directory scan)
    const filesToBackup = [...HardeningScanner.BACKUP_FILES];

    // Skill files discovered recursively. The SKILL-001 auto-fix appends an
    // `opena2a-guard` signature block to every unsigned skill it finds, and
    // those files were in no backup candidate list — so `rollback` could not
    // restore them while still reporting success. Same defect class as the
    // SOUL.md leftover in #262, found while fixing it.
    try {
      for (const skillFile of await this.findSkillFiles(targetDir)) {
        const rel = path.relative(targetDir, skillFile);
        if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) filesToBackup.push(rel);
      }
    } catch { /* discovery is best-effort; never block a fix run */ }

    // Also discover files in web-served directories that --fix may modify
    const webDirs = ['public', 'static', 'dist', 'build', 'out', 'www', '_site'];
    const webExts = ['.html', '.htm', '.js', '.jsx', '.tsx', '.css', '.py', '.md'];
    for (const webDir of webDirs) {
      const webDirPath = path.join(targetDir, webDir);
      try {
        const entries = await fs.readdir(webDirPath, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isFile() && webExts.some(ext => entry.name.endsWith(ext))) {
            filesToBackup.push(path.join(webDir, entry.name));
          }
        }
      } catch { /* dir doesn't exist */ }
    }

    for (const file of filesToBackup) {
      const sourcePath = path.join(targetDir, file);
      try {
        await fs.access(sourcePath);
        // NOTE: `access` and `copyFile` both follow symlinks, so a symlinked
        // candidate is backed up by CONTENT. That is deliberate for now.
        //
        // It has a real downside — a repo shipping `SOUL.md -> ~/.ssh/id_rsa`
        // gets that key's bytes copied into `.hackmyagent-backup/`, inside
        // the scanned tree. But simply skipping symlinked candidates is
        // WORSE, and was tried and reverted: roughly 18 fix sites here plus
        // `hardenSoul`'s `appendFileSync` still write through the link, so
        // skipping the backup leaves the out-of-tree file mutated with no
        // copy to restore from, and `rollback` reports success having
        // reverted nothing. Following the link at least keeps the write
        // recoverable.
        //
        // The root fix is to stop writing through symlinks at every fix
        // site, not to drop the backup that compensates for it. Tracked
        // separately; do not re-apply the skip on its own.
        const destPath = path.join(backupDir, file);
        await fs.mkdir(path.dirname(destPath), { recursive: true });
        await fs.copyFile(sourcePath, destPath);
        manifest.existingFiles.push(file);
      } catch {
        // #313 — absence is PROVEN here, never inferred from the fact that
        // something went wrong. This catch-all collapsed ENOENT-of-target,
        // EACCES, ELOOP, EISDIR, ENOSPC and EMFILE into "the file isn't
        // there", and `absentAtBackup` is the candidate list `recordCreatedFiles`
        // draws from — so anything that merely FAILED to copy became eligible
        // to be reported as HMA-generated and deleted by `rollback`.
        //
        // Measured, on the exact case `isGenuinelyAbsent`'s own docstring
        // describes: a user's `.gitignore -> ./nowhere` dangling symlink landed
        // in `absentAtBackup`, was recorded in `createdFiles`, and `rollback`
        // DELETED it while printing "Rollback complete / removed 1 generated
        // file" — leaving behind the file HMA had actually created through the
        // link. A pre-existing `.gitignore` at mode 0222 took the same route:
        // `access(F_OK)` passes, `copyFile` raises EACCES, and the original was
        // overwritten with no copy anywhere.
        //
        // #304 replaced this inference with an lstat proof in
        // `ensureBackupCovers`, but the identical inference survived here, and
        // because `ctx.covered` is pre-seeded from `absentAtBackup` the proof
        // was never consulted for any of the static candidates.
        //
        // Three outcomes, not two. A path that exists but could not be copied
        // belongs in NEITHER list: it is not restorable, so `existingFiles`
        // would lie, and it is not a creation, so `absentAtBackup` would let
        // rollback delete it. Landing in neither leaves it uncovered, which
        // makes `ensureBackupCovers` refuse the write — the safe direction.
        if (await this.isGenuinelyAbsent(sourcePath)) {
          // Candidate only — a fix stage may create it, and
          // recordCreatedFiles() decides afterwards whether it did.
          manifest.absentAtBackup.push(file);
        }
      }
    }

    // Save manifest
    await fs.writeFile(
      path.join(backupDir, '.manifest.json'),
      JSON.stringify(manifest, null, 2)
    );

    // Normalized so `ensureBackupCovers` compares like with like: the entries
    // above are joined with `path.join`, and `toTargetRelativePath` is what
    // the write path produces (#300).
    this.lastBackupCovered = [...manifest.existingFiles, ...manifest.absentAtBackup]
      .map((f) => this.toTargetRelativePath(f, targetDir))
      .filter((f): f is string => f !== null);

    return backupDir;
  }

  /**
   * Record what a fix stage actually created, with content hashes, so
   * rollback can remove generated files without guessing (#262).
   *
   * Additive and idempotent: `secure --fix` calls this at the end of scan()
   * for the static fixes, and the CLI calls it again after the governance
   * auto-fix (harden-soul runs after scan() returns and is what generates
   * SOUL.md). Re-recording a path already present is a no-op, so the hash
   * always reflects the first write — the one the user was told about.
   *
   * A candidate is recorded only when it did NOT exist at backup time (a
   * file that existed was copied into the backup and must be restored, never
   * deleted) and exists now. Silent on every failure: this is bookkeeping for
   * a convenience feature and must never break a scan that already succeeded.
   */
  async recordCreatedFiles(
    targetDir: string,
    backupPath: string | undefined,
    candidatePaths: readonly string[],
  ): Promise<void> {
    if (!backupPath || candidatePaths.length === 0) return;

    const manifestPath = path.join(backupPath, '.manifest.json');
    let manifest: BackupManifest;
    try {
      manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
    } catch {
      return;
    }

    // Only a file HMA affirmatively observed to be MISSING — either when the
    // backup was taken, or immediately before a fix wrote it — can be recorded
    // as created. A fixed finding on a file in neither list (not a backup
    // candidate) proves the fix touched it, not that the fix made it, and
    // recording it would let rollback delete a file the user wrote. Fail-safe
    // direction: never delete what we cannot prove we generated, even at the
    // cost of leaving a file behind (which the rollback report then names).
    //
    // Both lists are OBSERVATIONS, never inferences. #304 was an errno being
    // read as an observation: a failed copy meant "absent", so a file that
    // existed could be classified as generated and unlinked at rollback. See
    // `isGenuinelyAbsent`.
    //
    // #313 — that claim was FALSE for `absentAtBackup` when it was written.
    // #304 proved absence in `ensureBackupCovers` but left the identical errno
    // inference in `createBackup`, and since `ctx.covered` is pre-seeded from
    // `absentAtBackup` the new proof was never reached for any of the 25 static
    // candidates. Both producers of both lists now prove it, so the sentence
    // above is true of the whole path rather than of one branch of it.
    const provenAbsent = new Set([
      ...manifest.absentAtBackup,
      ...(manifest.absentAtFixWrite ?? []),
    ]);
    const alreadyRecorded = new Set(manifest.createdFiles.map(c => c.path));
    let changed = false;

    for (const candidate of candidatePaths) {
      const rel = this.toTargetRelativePath(candidate, targetDir);
      if (!rel || !provenAbsent.has(rel) || alreadyRecorded.has(rel)) continue;

      const absolute = path.join(targetDir, rel);
      // Defense in depth: a finding's `file` is data, and this path feeds an
      // unlink at rollback time.
      if (!this.isPathWithinDirectory(absolute, targetDir)) continue;

      try {
        const content = await fs.readFile(absolute);
        manifest.createdFiles.push({
          path: rel,
          sha256: crypto.createHash('sha256').update(content).digest('hex'),
        });
        alreadyRecorded.add(rel);
        changed = true;
      } catch {
        // Not created (or unreadable) — nothing to record.
      }
    }

    if (!changed) return;
    try {
      await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    } catch {
      // Bookkeeping only.
    }
  }

  /**
   * Normalize a candidate path (absolute or target-relative, either
   * separator) to a target-relative path. Returns null when it escapes the
   * target directory.
   */
  private toTargetRelativePath(candidate: string, targetDir: string): string | null {
    // No manual separator rewriting (#304). `\` was folded to `/` here to
    // "handle Windows paths", but `path.join`/`path.relative`/`path.isAbsolute`
    // are already platform-correct — on Windows both separators are separators,
    // and on POSIX `\` is an ordinary filename byte. Rewriting it turned a
    // legal name into a different path: the value became a description of
    // itself that no longer round-trips to the file it names. Everything
    // downstream (the backup copy, the manifest key, the rollback restore, the
    // created-file proof) then operated on that description, so a component
    // containing a `\` was rewritten with no recoverable copy while rollback
    // reported success. Two distinct files could also collide onto one key.
    const cleaned = candidate.replace(/^\.\//, '');
    if (!cleaned) return null;
    const absolute = path.isAbsolute(cleaned) ? cleaned : path.join(targetDir, cleaned);
    const rel = path.relative(targetDir, absolute);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return rel;
  }

  /**
   * Parse a backup manifest, tolerating the v1 shape. In v1 `createdFiles`
   * was a string array of every absent backup candidate — an unverifiable
   * claim, so those entries are quarantined into `legacyCreatedFiles` and
   * never deleted. See BACKUP_MANIFEST_VERSION.
   */
  private parseManifest(raw: string): BackupManifest {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const existingFiles = Array.isArray(parsed.existingFiles)
      ? (parsed.existingFiles as unknown[]).filter((f): f is string => typeof f === 'string')
      : [];
    const rawCreated = Array.isArray(parsed.createdFiles) ? (parsed.createdFiles as unknown[]) : [];

    const createdFiles: CreatedFileRecord[] = [];
    const legacyCreatedFiles: string[] = [];
    for (const entry of rawCreated) {
      if (typeof entry === 'string') {
        legacyCreatedFiles.push(entry);
      } else if (
        entry && typeof entry === 'object' &&
        typeof (entry as CreatedFileRecord).path === 'string' &&
        typeof (entry as CreatedFileRecord).sha256 === 'string'
      ) {
        createdFiles.push(entry as CreatedFileRecord);
      }
    }

    return {
      version: typeof parsed.version === 'number' ? parsed.version : 1,
      existingFiles,
      absentAtBackup: Array.isArray(parsed.absentAtBackup)
        ? (parsed.absentAtBackup as unknown[]).filter((f): f is string => typeof f === 'string')
        : [],
      absentAtFixWrite: Array.isArray(parsed.absentAtFixWrite)
        ? (parsed.absentAtFixWrite as unknown[]).filter((f): f is string => typeof f === 'string')
        : [],
      createdFiles,
      legacyCreatedFiles: legacyCreatedFiles.length > 0 ? legacyCreatedFiles : undefined,
    };
  }

  /**
   * Resolve a relative path to a real location inside the tree, or say why it
   * does not stay there. See `./contain` for the whole argument.
   *
   * Delegates rather than implements: the fix-write side needs this exact
   * property (#270) and `SoulScanner.hardenSoul` needs it too, and a second
   * copy of "is this path inside the tree" is what let the write side and the
   * restore side disagree for four rounds.
   */
  private async resolveInsideTree(
    targetReal: string,
    rel: string,
    opts: { followLeafLink: boolean },
  ): Promise<ResolveOutcome> {
    return containResolveInsideTree(targetReal, rel, opts);
  }

  /**
   * Copy one manifest entry out of the backup and back into the tree.
   *
   * Both ends are resolved (#318). The source must be a regular file that
   * resolves back inside the backup directory — a symlink there copies
   * out-of-tree CONTENT IN, which is the same defect mirrored and was verified
   * with a link to a file outside the tree landing in it.
   *
   * #327 — returns WHY it did not land, never a bare false. Every one of these
   * refusals leaves a manifest entry unrestored, and an unrestored entry that
   * nothing reports is the harm the containment guards exist to prevent, arrived
   * at from the other side: the user is told the revert is complete while their
   * bytes are only in the backup that is about to be deleted.
   *
   * #338 — and it reports whether the BACKUP still holds a copy of this entry,
   * because that is the fact the retention decision and the report header both
   * depend on and neither was checking it. So the SOURCE is probed first, even
   * for an entry whose destination is refused: "is the copy in there" has an
   * answer in every case, and deciding what to keep on disk from a fact nobody
   * established is what #326 was about.
   */
  private async restoreOneBackupFile(
    backupReal: string,
    targetReal: string,
    rel: string,
  ): Promise<{ ok: true } | { ok: false; cause: RestoreRefusal; detail?: string; backupHoldsCopy: boolean }> {
    // ---- Does the backup hold a copy of this entry? ----
    //
    // What the backup HOLDS for this entry, decided by this run's own probe.
    //
    // This started as "nothing there is PROVEN, everything else counts as a
    // copy", on the reasoning that refusing to delete is the fail-safe
    // direction. That was wrong in a way the adversarial pass caught: three of
    // the five refusals are decided by bytes the scanned tree wrote INSIDE the
    // forged backup, so `mkdir X` beside a manifest naming `X` made
    // `backupHoldsCopy` true, the directory was retained, and #338's wedge came
    // straight back — three runs, nothing restored, the real backup never
    // reached. A symlink pointing out of the backup did it too.
    //
    // So the question is the one the retention decision actually needs: is there
    // a REGULAR FILE at the resolved source inside the backup — the thing
    // `restoreOneBackupFile` could have copied out? A directory, a link pointing
    // outside, and an entry the filesystem would not describe are all "no":
    // deleting the backup around them destroys nothing this run could have
    // restored, and keeping it hands the scanned tree a permanent lock on the
    // recovery path. The cost is that an EACCES on a real copy goes with the
    // directory; it was unreadable to the user too, and the alternative is an
    // attacker-controlled denial of recovery.
    let sourceReal: string | null = null;
    let sourceRefusal: RestoreRefusal | null = null;
    const sourcePath = path.join(backupReal, rel);
    if (!this.isPathWithinDirectory(sourcePath, backupReal)) {
      sourceRefusal = 'source-outside-backup';
    } else {
      try {
        const candidate = await fs.realpath(sourcePath);
        if (!this.isPathWithinDirectory(candidate, backupReal)) {
          sourceRefusal = 'source-resolves-outside-backup';
        } else {
          try {
            sourceRefusal = (await fs.lstat(candidate)).isFile() ? null : 'source-not-regular-file';
          } catch {
            sourceRefusal = 'source-unexaminable';
          }
          if (!sourceRefusal) sourceReal = candidate;
        }
      } catch {
        sourceRefusal = 'source-unreadable';
      }
    }
    // `sourceReal` is set only when realpath succeeded, the result is inside the
    // backup, and it is a regular file. That is the whole definition.
    const backupHoldsCopy = sourceReal !== null;

    // ---- Where would it go? ----
    const dest = await this.resolveInsideTree(targetReal, rel, { followLeafLink: true });
    if (!dest.ok) return { ok: false, cause: dest.cause, backupHoldsCopy };
    if (sourceRefusal || !sourceReal) {
      return { ok: false, cause: sourceRefusal ?? 'source-unreadable', backupHoldsCopy };
    }

    try {
      await fs.copyFile(sourceReal, dest.path);
      return { ok: true };
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      return { ok: false, cause: 'write-failed', detail: code, backupHoldsCopy };
    }
  }

  /**
   * Rollback to the most recent backup.
   *
   * Returns what it actually did. A generated file is deleted only when its
   * content hash still matches what HMA wrote, so a SOUL.md the user has
   * since edited is kept, not silently discarded (#262). The caller is
   * expected to report the kept files rather than claim a clean revert.
   */
  async rollback(targetDir: string): Promise<RollbackReport> {
    // Resolved once, and every containment decision below is made against this
    // rather than against the caller's spelling. On macOS `os.tmpdir()` alone
    // makes the two differ (`/var` -> `/private/var`), so a resolved-vs-lexical
    // mismatch is the normal case, not an exotic one.
    let targetReal: string;
    try {
      targetReal = await fs.realpath(targetDir);
    } catch {
      throw new Error('No backup found. Run hackmyagent secure --fix <dir> first to create a backup.');
    }
    // Check if backup directory exists — and that it is a real directory in the
    // tree, not a link out of it (#321). `access` follows symlinks, so a
    // `.hackmyagent-backup -> /attacker/drop` passed this gate and rollback then
    // read its manifest and restored from its contents.
    //
    // `backupBaseDir` is the RESOLVED base from here on, and every path below is
    // built from it. Comparing a resolved path against a lexically-joined one is
    // the #317 mistake in miniature: a compare against the name we joined would
    // refuse a legitimate rollback on a `.HACKMYAGENT-BACKUP`.
    //
    // #334 — this comment used to say `realpath` returns the on-disk casing. It
    // does not: the JS implementation returns the caller's spelling for the
    // final component, and only `realpath.native` canonicalizes case. The code
    // is correct either way — everything below is built from whatever this
    // returns, so the two spellings cannot diverge — but the reason stated for
    // it was wrong.
    let backupBaseDir: string;
    try {
      const joinedBase = path.join(targetReal, BACKUP_DIR_NAME);
      const baseSt = await fs.lstat(joinedBase);
      if (baseSt.isSymbolicLink() || !baseSt.isDirectory()) {
        throw new Error('not a real backup directory');
      }
      backupBaseDir = await fs.realpath(joinedBase);
      if (!this.isPathWithinDirectory(backupBaseDir, targetReal)) {
        throw new Error('backup directory resolves outside the tree');
      }
    } catch {
      throw new Error('No backup found. Run hackmyagent secure --fix <dir> first to create a backup.');
    }

    // Find the most recent backup.
    //
    // #334 — DIRECTORIES only. This filtered dotfiles and nothing else, so an
    // ordinary file dropped in the backup base — `zzz` sorts above every stamp —
    // was selected as "the latest backup", and every legitimate rollback in that
    // tree failed on it. `withFileTypes` decides by what the entry IS rather
    // than by what it is called.
    const backups = await fs.readdir(backupBaseDir, { withFileTypes: true });
    const sortedBackups = backups
      .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
      .map((e) => e.name)
      .sort()
      .reverse();

    if (sortedBackups.length === 0) {
      throw new Error('No backup found. Run hackmyagent secure --fix <dir> first to create a backup.');
    }

    // Select a backup that can actually be USED, trying the next candidate when
    // one cannot (#338).
    //
    // The highest-sorting name is a GUESS, and it is a guess at a name the
    // scanned tree can write: a cloned repo shipping
    // `.hackmyagent-backup/9999-99-99-999999/` sorts above every real stamp and
    // is therefore always selected. Treating that guess as final meant one
    // unusable directory disabled the recovery path of a tool that had just
    // rewritten the user's files — permanently, since nothing consumed it and
    // the next run selected it again.
    //
    // Advancing is not a suppression channel: every candidate passed over is
    // reported by name and reason, and NONE is deleted. HMA could not read them,
    // so it cannot know they hold nothing.
    //
    // "Usable" means only that a plausible manifest could be parsed out of it. A
    // candidate that parses is the backup for this run whatever its entries
    // then do — advancing on a RESTORE failure would silently reach past a real
    // backup into an older one and put stale content back, which is #332's harm.
    const skippedBackups: Array<{ name: string; reason: string }> = [];
    /** Candidates that listed files and restored none of them. Kept, never used. */
    const barren: Array<{
      name: string; at: string; dir: string;
      manifest: BackupManifest; unrestored: RollbackReport['unrestored'];
    }> = [];
    let restored: string[] = [];
    let unrestored: RollbackReport['unrestored'] = [];
    let backupReal: string | undefined;
    let backupDir: string | undefined;
    let latestBackup: string | undefined;
    let manifest: BackupManifest | undefined;

    for (const candidate of sortedBackups) {
      const candidateDir = path.join(backupBaseDir, candidate);
      // The selected backup gets the same treatment as its parent: the tree
      // chose which entry sorts highest, so it can offer a symlink here too
      // (#318/#321). Resolved once, and everything read out of it is required to
      // resolve back inside this directory.
      //
      // #334 — and it says which of those it was. These refusals used to report
      // "Backup manifest is unreadable", naming a `.manifest.json` that was
      // never opened, so the user was sent to look at the wrong file for a cause
      // that was the directory itself.
      // Every reason below is a FIXED sentence. The candidate's name is already
      // tree-derived and the report escapes it; the reason must not become a
      // second channel for tree bytes, which is what an errno message or a
      // resolved link target would be.
      let candidateReal = '';
      let dirRefusal: string | undefined;
      try {
        const st = await fs.lstat(candidateDir);
        if (st.isSymbolicLink()) dirRefusal = 'it is a symbolic link, and rollback does not read through one';
        else if (!st.isDirectory()) dirRefusal = 'it is not a directory';
        else {
          candidateReal = await fs.realpath(candidateDir);
          if (!this.isPathWithinDirectory(candidateReal, backupBaseDir)) {
            dirRefusal = 'it resolves to somewhere outside the backup directory';
          }
        }
      } catch {
        dirRefusal = 'the filesystem would not say what it is';
      }
      if (dirRefusal) {
        skippedBackups.push({ name: candidate, reason: dirRefusal });
        continue;
      }

      // Size-guarded. #305's follow-up bounded the manifest read on the SCAN
      // path and explicitly exempted this one, on the grounds that "rollback
      // only ever reads a manifest HMA itself just wrote". #312 disproved that.
      //
      // Fails closed: an implausible manifest makes the candidate unusable, and
      // refusing to parse one cannot lose a real rollback — `createBackup`
      // writes a list of paths, not payloads.
      let manifestRefusal: string | undefined;
      try {
        const manifestPath = path.join(candidateReal, '.manifest.json');
        const stat = await fs.stat(manifestPath);
        // Per candidate, not cumulative. A shared allowance across the loop was
        // a wedge of exactly the shape this change exists to remove: eleven
        // directories carrying 1MB of invalid JSON each exhausted it before the
        // real backup was reached, and nothing is deleted, so re-running never
        // helped. Dropping it costs reads bounded by bytes the tree has already
        // written to disk — sequential, no amplification — and each candidate is
        // still capped at a size no real manifest reaches.
        if (!stat.isFile()) manifestRefusal = 'its .manifest.json is not a regular file';
        else if (stat.size > MAX_FILE_SIZE) manifestRefusal = 'its .manifest.json is implausibly large';
        if (!manifestRefusal) {
          manifest = this.parseManifest(await fs.readFile(manifestPath, 'utf-8'));
        }
      } catch {
        // Never the thrown message: a JSON parse error quotes the file, and that
        // file is in the scanned tree. Whatever went wrong, the user's next step
        // is the same, and it does not depend on the parser's phrasing.
        manifestRefusal = 'its .manifest.json could not be read as a backup manifest';
      }
      if (manifestRefusal) {
        skippedBackups.push({ name: candidate, reason: manifestRefusal });
        continue;
      }

      // Try this candidate's restores HERE, because the decision to use it
      // depends on what they do.
      //
      // Refining `backupHoldsCopy` was not enough and could never have been: the
      // scanned tree controls BOTH ends. It plants a real regular file in the
      // forged backup — so the copy genuinely is there — and plants a directory,
      // or a link pointing out of the tree, at the DESTINATION. The restore then
      // fails for a reason that has nothing to do with the copy, retention is
      // correct to keep the directory, and the wedge is back: measured three
      // runs each on `destdir`, `destlink-out` and `destlink-dangling`, nothing
      // restored, the real backup never reached. Any predicate over the tree's
      // own bytes loses this game.
      //
      // So the LOOP is what changes. A candidate that promised entries and
      // delivered none of them is not this run's backup, whatever the reason: it
      // is kept (it may hold bytes nobody can read yet) and REPORTED, and the run
      // moves to the next one. A candidate that restored something, or that
      // promised nothing, is the backup — advancing past either of those is what
      // would reach into an older run and restore stale content.
      const attempt: RollbackReport['unrestored'] = [];
      const put: string[] = [];
      for (const file of manifest?.existingFiles ?? []) {
        const outcome = await this.restoreOneBackupFile(candidateReal, targetReal, file);
        if (outcome.ok) {
          put.push(file);
        } else {
          const base = RESTORE_REFUSAL_REASONS[outcome.cause];
          attempt.push({
            path: file,
            reason: outcome.detail ? `${base} (${outcome.detail})` : base,
            backupHoldsCopy: outcome.backupHoldsCopy,
          });
        }
      }
      // A candidate that promises NOTHING contributes nothing either, and the
      // cheapest forgery there is — 49 bytes of empty manifest — used to be
      // selected, restore nothing, print "[+] Rollback complete", consume
      // itself, and say nothing about the backup behind it. Three of them cost
      // a user three runs of reading success before recovery. Advancing past it
      // cannot write anything stale, because it would have written nothing.
      const promisesNothing = (manifest?.existingFiles.length ?? 0) === 0
        && (manifest?.createdFiles.length ?? 0) === 0
        && (manifest?.legacyCreatedFiles?.length ?? 0) === 0;
      if (promisesNothing && sortedBackups.indexOf(candidate) < sortedBackups.length - 1) {
        barren.push({
          name: candidate, at: candidateReal, dir: candidateDir,
          manifest: manifest as BackupManifest, unrestored: [],
        });
        continue;
      }
      if (put.length === 0 && attempt.length > 0) {
        barren.push({
          name: candidate, at: candidateReal, dir: candidateDir,
          manifest: manifest as BackupManifest, unrestored: attempt,
        });
        continue;
      }

      restored = put;
      unrestored = attempt;
      backupReal = candidateReal;
      backupDir = candidateDir;
      latestBackup = candidate;
      break;
    }

    // Every candidate was barren. There is nothing behind them to be wedged out
    // of, so the newest one becomes this run's backup after all: the user gets
    // the full per-entry report and the retention decision, instead of a
    // one-line refusal that names no reason. The no-wedge property is unaffected
    // — passing over only matters when there IS something behind.
    if (!backupReal && barren.length > 0) {
      const first = barren.shift()!;
      backupReal = first.at;
      backupDir = first.dir;
      latestBackup = first.name;
      manifest = first.manifest;
      restored = [];
      unrestored = first.unrestored;
    }

    if (!backupReal || !backupDir || !latestBackup || !manifest) {
      const tried = skippedBackups.length;
      throw new Error(
        `None of the ${tried} backup director${tried === 1 ? 'y' : 'ies'} under ${backupBaseDir} `
        + `can be used. ${skippedBackups.map((s) => `${s.name}: ${s.reason}`).join('; ')}. `
        + 'Restore files by hand from whichever of them holds them, then delete it.',
      );
    }

    // How many candidates the tree is holding in front of the ones behind this
    // run's choice. Reported when the rollback does not complete, so a user
    // looking at a retained directory is told there is something behind it.
    const remainingBehind = sortedBackups.length - sortedBackups.indexOf(latestBackup) - 1;

    const report: RollbackReport = {
      restored,
      removed: [],
      keptModified: [],
      keptUnverifiable: [],
      unrestored,
      unremoved: [],
      skippedBackups,
      barrenBackups: barren.map((b) => ({ name: b.name, listed: b.unrestored.length })),
      backupsBehind: remainingBehind,
      backupUsed: latestBackup,
    };

    // Restore existing files from backup.
    //
    // #312 — the manifest is read from the SCANNED tree, which is attacker-
    // controlled, and this loop had no containment check while the
    // `createdFiles` loop below did. A cloned repo carrying its own
    // `.hackmyagent-backup/9999-99-99-999999/` (which sorts above any real
    // stamp, so it is always selected as the latest) turned `rollback` into an
    // arbitrary file write:
    //
    //   existingFiles: ["../<stamp>/authorized_keys"]
    //   -> copies the attacker's bytes OUTSIDE the scanned tree
    //   -> "[+] Rollback complete / Restored 1 modified file"
    //
    // #318 — and that guard closed only the `..` half. It reasoned that
    // "guarding the destination is sufficient for both ends: if the joined
    // destination stays inside targetDir, the normalized relative path has no
    // leading `..`, so the source cannot climb out of backupDir either" — a
    // statement about path arithmetic, not about the filesystem, and false in
    // both directions. `evil/sshlink -> /home/victim/.ssh` plus
    // `existingFiles: ["sshlink/authorized_keys"]` wrote the attacker's bytes to
    // `/home/victim/.ssh/authorized_keys` and printed
    // `restored sshlink/authorized_keys`; a symlink INSIDE the backup pulled
    // out-of-tree content the other way. Both ends are now resolved, and the
    // `..` case is still refused before any syscall is spent on it.

    // Remove files a fix stage created — but only when the bytes on disk are
    // still the bytes HMA wrote. Any edit since means the file is the user's
    // now, and a rollback of our changes is not a licence to delete it.
    //
    // Resolved, for the same reason as the restore loop: the manifest names both
    // the path AND the hash it must match, so a forged entry pointing through a
    // symlink at a file whose contents the attacker knows is a DELETE primitive
    // aimed outside the tree. #318 named the write; this is the same defect with
    // the arrow reversed.
    for (const created of manifest.createdFiles) {
      // Not followed: a symlink where a generated file should be is not the file
      // HMA generated, and unlinking through it would delete the target instead.
      const resolved = await this.resolveInsideTree(targetReal, created.path, { followLeafLink: false });
      // #342 — this used to be a bare `continue`. HackMyAgent said it would
      // remove the file, could not, and reported "Rollback complete / removed 0
      // generated files" with exit 0 while the file was still on disk. The
      // symlinked-`SOUL.md` fixture the #327 test builds hits it exactly, and
      // that test asserted only that the link's target survived — never that the
      // user is told — which is why the gap survived the change named for it.
      if (!resolved.ok) {
        report.unremoved.push({
          path: created.path,
          reason: RESTORE_REFUSAL_REASONS[resolved.cause],
        });
        continue;
      }
      const filePath = resolved.path;
      let current: Buffer;
      try {
        current = await fs.readFile(filePath);
      } catch (err) {
        // Only ENOENT proves it is already gone. Any other errno proves nothing,
        // and "I could not read it" must not become "there was nothing to
        // revert" — #313's inference, in the one loop that had no channel to
        // report it through.
        if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
          report.unremoved.push({
            path: created.path,
            reason: 'it could not be read, so HackMyAgent cannot tell whether it generated it',
          });
        }
        continue;
      }
      const currentHash = crypto.createHash('sha256').update(current).digest('hex');
      if (currentHash !== created.sha256) {
        report.keptModified.push(created.path);
        continue;
      }
      try {
        await fs.unlink(filePath);
        report.removed.push(created.path);
      } catch {
        report.keptModified.push(created.path);
      }
    }

    // v1 manifests listed every absent backup candidate as "created" with no
    // hash. Deleting on that basis is what could remove a user's own file, so
    // these are reported instead of acted on.
    for (const file of manifest.legacyCreatedFiles ?? []) {
      // #312 — no write here, but an unguarded path still lets a forged
      // manifest probe for files outside the tree and have their existence
      // reported back. #318 — and a lexical guard does not stop that probe,
      // only a `..` in it. All three manifest loops resolve.
      const resolved = await this.resolveInsideTree(targetReal, file, { followLeafLink: false });
      // #342 — same gap, same silence. This loop only ever REPORTS, so a path it
      // cannot resolve produced no line at all and the entry vanished from the
      // report entirely.
      if (!resolved.ok) {
        report.unremoved.push({
          path: file,
          reason: RESTORE_REFUSAL_REASONS[resolved.cause],
        });
        continue;
      }
      try {
        await fs.access(resolved.path);
        report.keptUnverifiable.push(file);
      } catch {
        // Never created — nothing to report.
      }
    }

    // Remove the used backup — but only when it has been fully used.
    //
    // #327 — an entry this run could not restore may have its only remaining
    // copy inside this directory, so deleting it would destroy the bytes the
    // rollback was asked to bring back. Measured on an ordinary symlinked config
    // with no attacker: `[+] Rollback complete`, exit 0, and no copy of the
    // original left anywhere in the tree.
    //
    // #338 — but "may" is not "does", and retaining on the weaker claim turned
    // this fix into a permanent denial of recovery. A directory the tree ships
    // as `9999-99-99-999999/` holding a manifest that names a file it does not
    // contain is selected every run, restores nothing, and was then KEPT — so
    // the next run selected it again, and the real backup behind it was never
    // reachable. Before this fix a failing selection consumed itself and the
    // second run recovered; after it, three runs recovered nothing.
    //
    // So retention is decided on the fact rather than on the possibility: keep
    // the directory when it still holds a copy of something that did not go
    // back. A backup that restored nothing and holds nothing is protecting
    // nothing, and deleting it is what lets the run behind it be reached.
    //
    // "Holds nothing" is PROVEN per entry (see `restoreOneBackupFile`): a
    // lexical escape or an ENOENT. Anything the filesystem would not answer
    // counts as holding a copy, because the cost of being wrong in that
    // direction is the user's last bytes.
    const retaining = report.unrestored.some((u) => u.backupHoldsCopy);
    if (retaining) {
      report.backupRetainedAt = backupReal;
    } else {
      // GUARDED, and this is the whole of the fix.
      //
      // `force: true` ignores one thing — the path not existing. Everything
      // else throws, and it throws HERE, after every file has been restored and
      // the entire report assembled. A `0500` subdirectory inside a forged
      // backup is enough: `fs.rm` cannot unlink through a directory it may not
      // write, and the exception replaced the whole report — restored list,
      // unrestored list, `backup kept at`, "copy those files back by hand" —
      // with a bare EACCES. That is #344's harm reached through a different
      // door, and the barren-candidate change fires this `rm` in more cases
      // than before, so the door is wider than it was.
      //
      // The removal is housekeeping. The rollback already happened, and a
      // failure to tidy up must not throw away the account of it.
      try {
        await fs.rm(backupReal, { recursive: true, force: true });
      } catch (err) {
        const code = (err as NodeJS.ErrnoException)?.code;
        report.backupRemovalFailed = {
          path: backupReal,
          reason: code
            ? `${code} — the directory or something inside it could not be removed`
            : 'it could not be removed',
        };
      }
    }

    return report;
  }

  /**
   * Recursively find SKILL.md and *.skill.md files
   * Skips node_modules and limits depth to 5
   */
  private async findSkillFiles(dir: string, depth: number = 0, rootDir?: string): Promise<string[]> {
    if (depth > 5) {
      return [];
    }

    // Single-FILE target: the readdir() below throws on a file path and
    // silently returns nothing, so `secure SKILL.md` skipped every SKILL-*
    // check and reported a false-clean verdict on a malicious lone skill
    // (e.g. a reverse-shell SKILL.md scored ~98/100 "Usable"; audit 2026-06-01).
    // When the caller points us straight at a skill file, scan it.
    if (depth === 0 && !rootDir) {
      try {
        const st = await fs.stat(dir);
        if (st.isFile()) {
          const base = path.basename(dir);
          return base === 'SKILL.md' || base.endsWith('.skill.md') ? [dir] : [];
        }
      } catch {
        return [];
      }
    }

    const baseDir = rootDir || dir;
    const skillFiles: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const fullPath = path.join(dir, entry.name);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, baseDir)) {
          continue;
        }

        if (entry.isDirectory()) {
          // Skip node_modules and hidden directories (except .openclaw, .moltbot, .clawdbot)
          if (entry.name === 'node_modules') continue;
          if (entry.name.startsWith('.') &&
              !['openclaw', 'moltbot', 'clawdbot'].includes(entry.name.slice(1))) {
            continue;
          }

          const subFiles = await this.findSkillFiles(fullPath, depth + 1, baseDir);
          skillFiles.push(...subFiles);
        } else if (entry.isFile()) {
          // Match SKILL.md or *.skill.md
          if (entry.name === 'SKILL.md' || entry.name.endsWith('.skill.md')) {
            skillFiles.push(fullPath);
          }
        }
      }
    } catch {
      // Directory not accessible, skip
    }

    return skillFiles;
  }

  /**
   * OpenClaw skill security checks (SKILL-001 to SKILL-024)
   */
  private async checkOpenclawSkills(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const skillFiles = await this.findSkillFiles(targetDir);

    for (const skillFile of skillFiles) {
      // When secure targets the skill file directly, path.relative is '' —
      // fall back to the basename so findings keep a file path (the CLI filters
      // out file-less findings) and remain CISO-actionable.
      const relativePath = path.relative(targetDir, skillFile) || path.basename(skillFile);

      let content: string;
      try {
        const stats = await fs.stat(skillFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(skillFile, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n').map(line =>
        line.length > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) : line
      );

      // SKILL-001: Unsigned Skill
      const hasSignature =
        content.includes('opena2a_signature:') ||
        content.includes('-----BEGIN SIGNATURE-----') ||
        content.includes('<!-- opena2a-guard hash=');

      let skill001Fixed = false;
      if (!hasSignature && autoFix) {
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        const signedDate = new Date().toISOString();
        const signatureBlock = `\n<!-- opena2a-guard hash="sha256:${hash}" signed="${signedDate}" -->`;
        const skill001Content = content + signatureBlock;
        skill001Fixed = await this.applyFixWrite(skillFile, skill001Content);
        if (skill001Fixed) content = skill001Content;
      }

      findings.push({
        checkId: 'SKILL-001',
        name: 'Unsigned Skill',
        description: 'Skill file lacks cryptographic signature for authenticity verification',
        category: 'skill',
        severity: 'medium',
        passed: hasSignature || skill001Fixed,
        message: hasSignature
          ? 'Skill has cryptographic signature'
          : skill001Fixed
            ? 'Skill was unsigned - signature added'
            : 'Skill is unsigned - cannot verify authenticity or integrity',
        file: relativePath,
        fixable: true,
        fixed: skill001Fixed,
        fixMessage: skill001Fixed ? 'Added SHA-256 signature block to skill file' : undefined,
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Unsigned skills cannot be verified for authenticity or integrity. Sign with a cryptographic identity to enable tamper detection.',
      });

      // SKILL-002: Remote Fetch Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_REMOTE_FETCH_PATTERNS) {
          // Reset regex lastIndex for global patterns
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            const section = classifySkillSection(content, i);
            if (isLikelyFalsePositive('SKILL-002', line, section, content)) {
              continue;
            }
            findings.push({
              checkId: 'SKILL-002',
              name: 'Remote Fetch Pattern',
              description: 'Skill contains pattern that fetches and executes remote code',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Remote fetch pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove the curl|sh or wget|sh pattern from this file',
              guidance: 'Remote code execution patterns download and execute arbitrary code. Replace with a pinned dependency or vendored script with checksum verification.',
            });
            break; // One finding per line
          }
        }
      }

      // SKILL-003: Heartbeat Installation
      const heartbeatPattern = /heartbeat|cron|schedule|every\s+\d+\s*(min|hour|sec)/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        heartbeatPattern.lastIndex = 0;
        if (heartbeatPattern.test(line)) {
          findings.push({
            checkId: 'SKILL-003',
            name: 'Heartbeat Installation',
            description: 'Skill attempts to install periodic/scheduled tasks',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `Heartbeat/scheduled task pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Move scheduled task configuration to a separate heartbeat config file',
            guidance: 'Skills that install heartbeats or cron jobs gain persistent execution beyond the user session. Heartbeats should be configured separately with restricted permissions.',
          });
        }
      }

      // SKILL-004: Filesystem Write Outside Sandbox
      const filesystemWildcardPattern = /filesystem:\s*\*|filesystem:\s*~\/|filesystem:\s*\//gi;
      let skill004FileModified = false;
      // Line indices this fix rewrote. The write below re-derives its content
      // from `content` rather than reusing `lines`, so it needs to know which
      // lines to redo. See the write for why.
      const skill004Indices: number[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        filesystemWildcardPattern.lastIndex = 0;
        if (filesystemWildcardPattern.test(line)) {
          let fixApplied = false;
          if (autoFix) {
            const originalLine = lines[i];
            lines[i] = lines[i].replace(/filesystem:\s*\*/gi, 'filesystem:./');
            lines[i] = lines[i].replace(/filesystem:\s*~\//gi, 'filesystem:./data/');
            if (lines[i] !== originalLine) {
              fixApplied = true;
              skill004FileModified = true;
              skill004Indices.push(i);
            }
          }

          findings.push({
            checkId: 'SKILL-004',
            name: 'Filesystem Write Outside Sandbox',
            description: 'Skill requests broad filesystem access outside sandbox',
            category: 'skill',
            severity: 'critical',
            passed: fixApplied,
            message: fixApplied
              ? `Broad filesystem access restricted: "${lines[i].trim()}"`
              : `Broad filesystem access requested: "${line.trim()}"`,
            file: relativePath,
            line: i + 1,
            fixable: true,
            fixed: fixApplied,
            fixMessage: fixApplied ? 'Restricted filesystem access to sandbox scope' : undefined,
            fix: 'hackmyagent secure --fix',
            guidance: 'Broad filesystem access (filesystem:* or filesystem:~/) lets skills read/write anywhere. Restrict to specific directories (e.g., filesystem:./data/*).',
          });
        }
      }
      if (skill004FileModified) {
        // Rebuilt from `content`, NOT from `lines`. Two reasons, both data loss:
        //
        //  1. `lines` is a SCAN buffer — every line over MAX_LINE_LENGTH was
        //     truncated for regex safety. Writing it back silently discarded
        //     the tail: a 12072-byte SKILL.md came back 10059 bytes, 2013
        //     bytes gone, with no finding and no warning. A safety buffer must
        //     never be a write source.
        //  2. `lines` was split BEFORE SKILL-001 appended its signature block,
        //     so writing it also erased a signature this same run had just
        //     successfully written.
        const skill004Current = content.split('\n');
        for (const i of skill004Indices) {
          if (skill004Current[i] === undefined) continue;
          skill004Current[i] = skill004Current[i]
            .replace(/filesystem:\s*\*/gi, 'filesystem:./')
            .replace(/filesystem:\s*~\//gi, 'filesystem:./data/');
        }
        const skill004Content = skill004Current.join('\n');
        skill004FileModified = await this.applyFixWrite(skillFile, skill004Content);
        if (skill004FileModified) {
          content = skill004Content;
        } else {
          // SKILL-004 findings were pushed above with `passed: fixApplied`,
          // set from the in-memory line rewrite, before this write. Revoking
          // the write flag alone leaves them claiming `passed: true` for a
          // CRITICAL still on disk — and `cli.ts` re-filters on `!f.passed`,
          // so they vanish from the report entirely. Scoped to this file.
          for (const f of findings) {
            if (f.checkId === 'SKILL-004' && f.file === relativePath && f.fixed) {
              f.passed = false;
              f.fixed = false;
              f.fixMessage = undefined;
              // Same: the message quoted the REWRITTEN line, which is not what
              // is on disk.
              f.message = 'Broad filesystem access requested (auto-fix could not be written)';
            }
          }
        }
      }

      // SKILL-005: Credential File Access
      // Only flag as CRITICAL inside frontmatter (capabilities section).
      // Body text often describes credential handling in documentation,
      // which is informational, not an actual access pattern.
      let inSkill005Frontmatter = false;
      let skill005FrontmatterDelimiters = 0;
      for (let i = 0; i < lines.length; i++) {
        const trimmed = lines[i].trim();
        if (trimmed === '---') {
          skill005FrontmatterDelimiters++;
          inSkill005Frontmatter = skill005FrontmatterDelimiters === 1;
          if (skill005FrontmatterDelimiters >= 2) inSkill005Frontmatter = false;
          continue;
        }
        const line = lines[i];
        for (const pattern of SKILL_CREDENTIAL_ACCESS_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            // Frontmatter = actual capability declaration (CRITICAL)
            // Body = still suspicious but lower severity (MEDIUM)
            const severity = inSkill005Frontmatter ? 'critical' : 'medium';
            findings.push({
              checkId: 'SKILL-005',
              name: 'Credential File Access',
              description: inSkill005Frontmatter
                ? 'Skill declares access to credential or sensitive configuration files'
                : 'Skill body mentions credential file patterns',
              category: 'skill',
              severity,
              passed: false,
              message: `Credential file access pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove credential file access patterns from this skill',
              guidance: 'Skills accessing ~/.ssh, ~/.aws, wallets, or .env files can exfiltrate credentials. Use npx secretless-ai init to protect credentials from AI tool context.',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-006: Data Exfiltration Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_EXFILTRATION_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-006',
              name: 'Data Exfiltration Pattern',
              description: 'Skill contains patterns commonly used for data exfiltration',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Data exfiltration pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove the exfiltration endpoint from this skill',
              guidance: 'Data exfiltration patterns (webhook.site, requestbin, ngrok, suspicious POST) send local data to external servers. Remove or replace with audited, allow-listed endpoints.',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-007: ClickFix Social Engineering
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_CLICKFIX_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            const section = classifySkillSection(content, i);
            if (isLikelyFalsePositive('SKILL-007', line, section, content)) {
              continue;
            }
            findings.push({
              checkId: 'SKILL-007',
              name: 'ClickFix Social Engineering',
              description: 'Skill uses social engineering tactics to trick users into running commands',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `ClickFix social engineering pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove the copy/paste instruction block from this skill',
              guidance: 'ClickFix social engineering tricks users into copying and pasting malicious commands. This technique was used extensively in the ClawHavoc campaign.',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-008: Reverse Shell Pattern
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const pattern of SKILL_REVERSE_SHELL_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(line)) {
            findings.push({
              checkId: 'SKILL-008',
              name: 'Reverse Shell Pattern',
              description: 'Skill contains patterns commonly used to establish reverse shells',
              category: 'skill',
              severity: 'critical',
              passed: false,
              message: `Reverse shell pattern detected: "${line.trim().substring(0, 80)}..."`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Remove the reverse shell pattern from this skill',
              guidance: 'Reverse shell patterns (netcat, bash -i, /dev/tcp) establish remote command execution. This is a strong indicator of malicious intent.',
            });
            break; // One finding per line per check
          }
        }
      }

      // SKILL-009: Typosquatting Name
      const popularSkills = [
        'filesystem',
        'github',
        'slack',
        'discord',
        'postgres',
        'sqlite',
        'fetch',
        'browser',
        'puppeteer',
        'playwright',
      ];
      const skillBasename = path.basename(skillFile, path.extname(skillFile)).toLowerCase();
      for (const popular of popularSkills) {
        if (skillBasename !== popular && this.levenshteinDistance(skillBasename, popular) <= 2) {
          findings.push({
            checkId: 'SKILL-009',
            name: 'Typosquatting Name',
            description: 'Skill name is suspiciously similar to a popular skill (potential typosquatting)',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `Skill name "${skillBasename}" is similar to popular skill "${popular}" (potential typosquatting)`,
            file: relativePath,
            fixable: false,
            fix: commandNaming(relativePath, (q) => `hackmyagent check ${q}`)
              ?? 'Inspect the file named in this finding by hand — its name cannot be shown truthfully in a shell command.',
            guidance: 'Typosquatting uses names similar to popular skills to trick users into installing malicious versions. Verify the skill source and rename if unintentional.',
          });
          break; // One typosquatting finding per skill file
        }
      }

      // SKILL-010: Env File Exfiltration (context-aware)
      //
      // Must match an ACTUAL env-access action, not just the substring ".env"
      // or "environment". A documentation section that lists patterns like
      // ".env, .pem, .key" is not env exfiltration. Real signals:
      //   - Direct env-var access syntax (process.env, os.environ[, getenv())
      //   - Destructuring from process.env (covers `const {KEY} = process.env`)
      //   - Runtime-specific env APIs (Deno.env.get, Bun.env.KEY)
      //   - dotenv loaders (dotenv.config(), load_dotenv())
      //   - Shell dumps of the whole env (`env | curl ...`, `printenv | nc`)
      //   - Shell exfil over an .env file (cat/curl/scp/... .env)
      //   - File-read API with an .env argument (readFile('.env'), Read('.env'))
      //   - curl --data-binary @.env (send .env contents as POST body)
      const envFilePattern = /process\.env\b|\bos\.environb?\b|\bgetenv\s*\(|\bDeno\.env\b|\bBun\.env\b|\bdotenv(?:\.config|_values|\.parse)\s*\(|\bload_dotenv\s*\(|\brequire\s*\(\s*['"`]dotenv(?:\/config)?['"`]\s*\)|\bimport\s+[^;]*['"`]dotenv(?:\/config)?['"`]|\b(?:cat|head|tail|curl|wget|scp|rsync|tar|zip|xxd|base64)\s+[^|\n]*\.env\b|\b(?:env|printenv)\s*[|>]|(?:read|readFile|readFileSync|open)\s*\(\s*['"`][^'"`]*\.env|\bRead\s*\(\s*['"`][^'"`]*\.env|@\.env\b|\bsource\s+\.?env\b/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        envFilePattern.lastIndex = 0;
        if (envFilePattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-010', line, section, content)) {
            continue;
          }
          findings.push({
            checkId: 'SKILL-010',
            name: 'Env File Exfiltration',
            description: 'Skill attempts to access environment files or variables',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Environment file/variable access detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'npx secretless-ai init',
            guidance: 'Skills accessing .env files or process.env can exfiltrate API keys and secrets. Use Secretless AI to block credential access from AI tool context.',
          });
        }
      }

      // SKILL-011: Browser Data Access (context-aware)
      const browserDataPattern = /chrome|firefox|cookies|localStorage|sessionStorage|browser.*data|chromium|safari.*cookies/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        browserDataPattern.lastIndex = 0;
        if (browserDataPattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-011', line, section, content)) {
            continue;
          }
          findings.push({
            checkId: 'SKILL-011',
            name: 'Browser Data Access',
            description: 'Skill attempts to access browser data, cookies, or local storage',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Browser data access pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Remove browser data access patterns from this skill',
            guidance: 'Skills accessing browser data (cookies, localStorage, sessionStorage) can steal session tokens and authentication state.',
          });
        }
      }

      // SKILL-012: Crypto Wallet Access (context-aware)
      const cryptoWalletPattern = /wallet|solana|phantom|metamask|ledger|seed\s*phrase|mnemonic|\.sol\b|\.eth\b|private\s*key/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        cryptoWalletPattern.lastIndex = 0;
        if (cryptoWalletPattern.test(line)) {
          const section = classifySkillSection(content, i);
          if (isLikelyFalsePositive('SKILL-012', line, section, content)) {
            continue;
          }
          findings.push({
            checkId: 'SKILL-012',
            name: 'Crypto Wallet Access',
            description: 'Skill attempts to access cryptocurrency wallets or seed phrases',
            category: 'skill',
            severity: 'critical',
            passed: false,
            message: `Crypto wallet access pattern detected: "${line.trim().substring(0, 80)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Remove crypto wallet access patterns from this skill',
            guidance: 'Skills accessing wallets, seed phrases, or private keys can drain cryptocurrency funds. No legitimate skill needs this access.',
          });
        }
      }

      // SKILL-018: Undeclared Capability Validation
      const declaredCaps = parseSkillDeclaredCaps(content);
      const inferredCaps = inferActualCapabilities(content);
      const capFindings = validateCapabilities(declaredCaps, inferredCaps, relativePath);
      findings.push(...capFindings);

      // SKILL-019: Stale Skill Signature
      const signatureMatch = content.match(
        /<!-- opena2a-guard hash="sha256:([a-f0-9]+)" signed="([^"]+)"(?: expires_at="([^"]+)")? -->/
      );
      if (signatureMatch) {
        const storedHash = signatureMatch[1];
        const signatureBlock = signatureMatch[0];
        // Compute hash of content excluding the signature block
        const contentWithoutSig = content.replace(signatureBlock, '').replace(/\n$/, '');
        const computedHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');

        if (storedHash !== computedHash) {
          let skill019Fixed = false;
          if (autoFix) {
            const newHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');
            const newDate = new Date().toISOString();
            const expiresAt = signatureMatch[3]
              ? ` expires_at="${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()}"`
              : '';
            const newSigBlock = `<!-- opena2a-guard hash="sha256:${newHash}" signed="${newDate}"${expiresAt} -->`;
            const skill019Content = content.replace(signatureBlock, newSigBlock);
            skill019Fixed = await this.applyFixWrite(skillFile, skill019Content);
            if (skill019Fixed) content = skill019Content;
          }

          findings.push({
            checkId: 'SKILL-019',
            name: 'Stale Skill Signature',
            description: 'Skill content has changed since it was signed - signature hash mismatch',
            category: 'skill',
            severity: 'medium',
            passed: skill019Fixed,
            message: skill019Fixed
              ? 'Stale signature detected and re-signed'
              : 'Signature hash does not match current content - skill may have been tampered with',
            file: relativePath,
            fixable: true,
            fixed: skill019Fixed,
            fixMessage: skill019Fixed ? 'Re-computed hash and updated signature block' : undefined,
            fix: 'hackmyagent secure --fix',
            guidance: 'The signature hash no longer matches the file content. This could indicate tampering or a legitimate edit that was not re-signed.',
          });
        }

        // HEARTBEAT-007: Expired Heartbeat (check expires_at in signature block)
        if (signatureMatch[3]) {
          const expiresAt = new Date(signatureMatch[3]);
          const now = new Date();
          if (expiresAt < now) {
            let hb007Fixed = false;
            if (autoFix) {
              const contentWithoutSig = content.replace(signatureMatch[0], '').replace(/\n$/, '');
              const newHash = crypto.createHash('sha256').update(contentWithoutSig).digest('hex');
              const newDate = new Date().toISOString();
              const newExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
              const newSigBlock = `<!-- opena2a-guard hash="sha256:${newHash}" signed="${newDate}" expires_at="${newExpiry}" -->`;
              const hb007Content = content.replace(signatureMatch[0], newSigBlock);
              hb007Fixed = await this.applyFixWrite(skillFile, hb007Content);
              if (hb007Fixed) content = hb007Content;
            }

            findings.push({
              checkId: 'HEARTBEAT-007',
              name: 'Expired Heartbeat',
              description: 'Skill signature has expired and needs renewal',
              category: 'skill',
              severity: 'high',
              passed: hb007Fixed,
              message: hb007Fixed
                ? 'Expired signature renewed with 7-day validity'
                : `Skill signature expired at ${signatureMatch[3]}`,
              file: relativePath,
              fixable: true,
              fixed: hb007Fixed,
              fixMessage: hb007Fixed ? 'Updated expiry to 7 days from now and re-signed' : undefined,
              fix: 'hackmyagent secure --fix',
              guidance: 'Expired signatures mean the skill has not been re-verified since its expiry date. Re-signing renews the validity period and re-verifies content integrity.',
            });
          }
        }
      }

      // SKILL-020: Missing/invalid frontmatter
      // Issue #135: hygiene gaps default MEDIUM; HIGH only when paired with
      // a malice signal (wildcard tools, credential env, outbound postRunHook,
      // persistence patterns). Reserved HIGH means HIGH actually means something.
      const skill020MaliceUpgrade = hasSkillMaliceSignals(content);
      const skill020Severity: 'high' | 'medium' = skill020MaliceUpgrade ? 'high' : 'medium';
      const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
      if (!fmMatch) {
        findings.push({
          checkId: 'SKILL-020',
          name: 'Missing YAML Frontmatter',
          description: 'Skill file lacks required YAML frontmatter for capability declaration',
          category: 'skill',
          severity: skill020Severity,
          passed: false,
          message: `${relativePath}: Skill file lacks required YAML frontmatter (---). Add frontmatter with name, version, and capabilities fields.`,
          file: relativePath,
          fixable: true,
          fix: 'Add YAML frontmatter block with name, version, and capabilities fields',
          guidance: 'Skills without frontmatter cannot declare their capabilities, making permission validation impossible. Add a --- delimited YAML block at the top of the file.',
        });
      } else {
        const fmRaw = fmMatch[1];
        const requiredFields = ['name', 'version', 'capabilities'];
        const missingFields = requiredFields.filter(f => !new RegExp(`^${f}:`, 'm').test(fmRaw));
        if (missingFields.length > 0) {
          findings.push({
            checkId: 'SKILL-020',
            name: 'Incomplete Frontmatter',
            description: 'Skill frontmatter is missing required fields',
            category: 'skill',
            severity: skill020Severity,
            passed: false,
            message: `${relativePath}: Missing required frontmatter fields: ${missingFields.join(', ')}. These are needed for capability declaration and version tracking.`,
            file: relativePath,
            fixable: true,
            fix: `Add missing fields to frontmatter: ${missingFields.join(', ')}`,
            guidance: 'Incomplete frontmatter prevents proper capability validation. Every skill should declare name, version, and capabilities.',
          });
        } else {
          findings.push({
            checkId: 'SKILL-020',
            name: 'Valid Frontmatter',
            description: 'Skill file has valid YAML frontmatter with required fields',
            category: 'skill',
            severity: skill020Severity,
            passed: true,
            message: 'Skill has valid frontmatter with name, version, and capabilities',
            file: relativePath,
            fixable: false,
            fix: 'No action needed',
            guidance: 'Skill frontmatter is properly configured.',
          });
        }
      }

      // SKILL-021: Overprivileged permissions (dangerous capability combinations)
      const dangerousCombos: Array<{ combo: [string, string]; reason: string }> = [
        {
          combo: ['filesystem:*', 'network:outbound'],
          reason: 'filesystem:* + network:outbound enables data exfiltration',
        },
        {
          combo: ['credential:read', 'network:outbound'],
          reason: 'credential:read + network:outbound enables credential exfiltration',
        },
      ];
      const capPatterns = content.match(/(?:filesystem|network|credential|tool):[a-z*]+/g) || [];
      const allCaps = [...new Set(capPatterns)];
      // Also include capabilities from frontmatter if parsed
      const declaredCapsForPriv = parseSkillDeclaredCaps(content);
      for (const dc of declaredCapsForPriv.capabilities) {
        if (!allCaps.includes(dc)) allCaps.push(dc);
      }

      for (const { combo, reason } of dangerousCombos) {
        const matchCap = (actual: string, pattern: string): boolean => {
          if (actual === pattern) return true;
          if (pattern.endsWith(':*')) return actual.startsWith(pattern.slice(0, -1));
          if (actual.endsWith(':*')) return pattern.startsWith(actual.slice(0, -1));
          return false;
        };
        const hasFirst = allCaps.some(c => matchCap(c, combo[0]));
        const hasSecond = allCaps.some(c => matchCap(c, combo[1]));

        if (hasFirst && hasSecond) {
          findings.push({
            checkId: 'SKILL-021',
            name: 'Overprivileged Permissions',
            description: 'Skill has dangerous capability combination that enables exfiltration',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `${relativePath}: ${reason}. Restrict filesystem access to specific paths or remove outbound network access.`,
            file: relativePath,
            fixable: false,
            fix: 'Restrict capabilities to minimum required permissions',
            guidance: 'Dangerous capability combinations can enable data or credential exfiltration. Follow the principle of least privilege.',
          });
        }
      }

      // SKILL-022: Environment variable exfiltration
      const envAccessPatterns = [
        /process\.env/,
        /os\.environ/,
        /\$ENV\{/,
        /System\.getenv/,
        /printenv/,
        /\$\(env\)/,
        /\$\(printenv/,
        /\$HOME\b/,
        /\$\{[A-Z_]+\}/,
      ];
      const outboundPatterns = [
        /network:outbound/,
        /fetch\s*\(/,
        /https?:\/\//,
        /XMLHttpRequest/,
        /\.send\s*\(/,
        /curl\s/,
        /wget\s/,
      ];
      const hasEnvAccess = envAccessPatterns.some(p => p.test(content));
      const hasOutbound = outboundPatterns.some(p => p.test(content));

      if (hasEnvAccess && hasOutbound) {
        findings.push({
          checkId: 'SKILL-022',
          name: 'Environment Variable Exfiltration Risk',
          description: 'Skill accesses environment variables and has outbound network capability',
          category: 'skill',
          severity: 'critical',
          passed: false,
          message: `${relativePath}: Skill accesses environment variables AND has outbound network capability. This combination can exfiltrate secrets via network requests.`,
          file: relativePath,
          fixable: false,
          fix: 'Remove outbound network access or environment variable reads',
          guidance: 'Skills that read environment variables and send data externally can exfiltrate API keys, tokens, and other secrets stored in environment variables.',
        });
      }

      // SKILL-023: Obfuscated code patterns
      const obfuscationPatterns = [
        { pattern: /atob\s*\(/, label: 'atob() base64 decode' },
        { pattern: /Buffer\.from\s*\(/, label: 'Buffer.from() decode' },
        { pattern: /eval\s*\(/, label: 'eval() dynamic execution' },
        { pattern: /String\.fromCharCode/, label: 'String.fromCharCode obfuscation' },
        { pattern: /\\x[0-9a-fA-F]{2}/, label: 'hex-encoded string' },
        { pattern: /(?:atob|Buffer\.from)\s*\([^)]+\)[\s\S]*?eval\s*\(/, label: 'base64+eval combo' },
        { pattern: /base64\s+-d/, label: 'shell base64 decode' },
        { pattern: /eval\s+\$\(/, label: 'shell eval $(...)' },
        { pattern: /\becho\s+['"][A-Za-z0-9+/=]{20,}['"]\s*\|\s*base64/, label: 'echo+base64 pipe' },
        { pattern: /new\s+Function\s*\(/, label: 'new Function() dynamic execution' },
      ];

      for (const { pattern, label } of obfuscationPatterns) {
        if (pattern.test(content)) {
          findings.push({
            checkId: 'SKILL-023',
            name: 'Obfuscated Code Pattern',
            description: 'Skill contains obfuscated code that may hide malicious behavior',
            category: 'skill',
            severity: 'high',
            passed: false,
            message: `${relativePath}: Detected ${label}. Obfuscated code in skills can hide malicious behavior and should be reviewed.`,
            file: relativePath,
            fixable: false,
            fix: 'Replace obfuscated code with readable equivalent',
            guidance: 'Obfuscated code (base64 decode, eval, hex-encoded strings) in skills is a strong indicator of hidden malicious behavior. Review and replace with transparent code.',
          });
          break; // One finding per file for obfuscation
        }
      }

      // SKILL-024: Unbounded tool chaining
      const hasToolChain = allCaps.some(c => c.includes('tool:chain'));
      if (hasToolChain) {
        const hasFm = !!fmMatch;
        const fmContent = hasFm ? fmMatch[1] : '';
        const hasMaxIterations = hasFm && (
          /maxIterations/i.test(fmContent) ||
          /iterationLimit/i.test(fmContent)
        );

        if (!hasMaxIterations) {
          findings.push({
            checkId: 'SKILL-024',
            name: 'Unbounded Tool Chaining',
            description: 'Skill declares tool:chain capability without iteration limits',
            category: 'skill',
            severity: 'medium',
            passed: false,
            message: `${relativePath}: Skill declares tool:chain capability without maxIterations or iterationLimit. Unbounded chaining can lead to infinite loops or resource exhaustion.`,
            file: relativePath,
            fixable: true,
            fix: 'Add maxIterations or iterationLimit to skill frontmatter',
            guidance: 'Tool chaining without iteration limits can cause infinite loops, resource exhaustion, or runaway costs. Set a reasonable maxIterations value in frontmatter.',
          });
        }
      }
    }

    return findings;
  }

  /**
   * Recursively find HEARTBEAT.md and *.heartbeat.md files
   * Skips node_modules and limits depth to 5
   */
  private async findHeartbeatFiles(dir: string, depth: number = 0, rootDir?: string): Promise<string[]> {
    if (depth > 5) {
      return [];
    }

    const baseDir = rootDir || dir;
    const heartbeatFiles: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const fullPath = path.join(dir, entry.name);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, baseDir)) {
          continue;
        }

        if (entry.isDirectory()) {
          // Skip node_modules and hidden directories (except .openclaw, .moltbot, .clawdbot)
          if (entry.name === 'node_modules') continue;
          if (entry.name.startsWith('.') &&
              !['openclaw', 'moltbot', 'clawdbot'].includes(entry.name.slice(1))) {
            continue;
          }

          const subFiles = await this.findHeartbeatFiles(fullPath, depth + 1, baseDir);
          heartbeatFiles.push(...subFiles);
        } else if (entry.isFile()) {
          // Match HEARTBEAT.md or *.heartbeat.md
          if (entry.name === 'HEARTBEAT.md' || entry.name.endsWith('.heartbeat.md')) {
            heartbeatFiles.push(fullPath);
          }
        }
      }
    } catch {
      // Directory not accessible, skip
    }

    return heartbeatFiles;
  }

  /**
   * OpenClaw heartbeat security checks (HEARTBEAT-001 to HEARTBEAT-006)
   */
  private async checkOpenclawHeartbeat(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const heartbeatFiles = await this.findHeartbeatFiles(targetDir);

    for (const heartbeatFile of heartbeatFiles) {
      const relativePath = path.relative(targetDir, heartbeatFile);

      let content: string;
      try {
        const stats = await fs.stat(heartbeatFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(heartbeatFile, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n').map(line =>
        line.length > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) : line
      );

      // HEARTBEAT-001: Unverified Heartbeat URL
      const urlPattern = /https?:\/\/[^\s]+/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        urlPattern.lastIndex = 0;
        const match = urlPattern.exec(line);
        if (match) {
          findings.push({
            checkId: 'HEARTBEAT-001',
            name: 'Unverified Heartbeat URL',
            description: 'Heartbeat contacts external URL without verification',
            category: 'heartbeat',
            severity: 'critical',
            passed: false,
            message: `External URL detected in heartbeat: "${match[0].substring(0, 60)}..."`,
            file: relativePath,
            line: i + 1,
            fixable: false,
            fix: 'Verify the URL is from a trusted source and add hash pinning for integrity',
            guidance: 'Heartbeats that contact external URLs without verification can be redirected to malicious endpoints. Pin the expected hash to detect tampering.',
          });
        }
      }

      // HEARTBEAT-002: No Hash Pinning
      const hasHashPinning =
        content.includes('pinned_hash:') ||
        content.includes('sha256:') ||
        content.includes('hash:');

      findings.push({
        checkId: 'HEARTBEAT-002',
        name: 'No Hash Pinning',
        description: 'Heartbeat lacks hash pinning for content integrity verification',
        category: 'heartbeat',
        severity: 'high',
        passed: hasHashPinning,
        message: hasHashPinning
          ? 'Heartbeat has hash pinning for integrity verification'
          : 'Heartbeat lacks hash pinning - content integrity cannot be verified',
        file: relativePath,
        fixable: false,
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Without hash pinning, heartbeat content can be modified without detection. Pinning creates a cryptographic fingerprint to verify integrity on each execution.',
      });

      // HEARTBEAT-003: Unsigned Heartbeat
      const hasSignature =
        content.includes('opena2a_signature:') ||
        content.includes('signature:') ||
        content.includes('-----BEGIN SIGNATURE-----');

      findings.push({
        checkId: 'HEARTBEAT-003',
        name: 'Unsigned Heartbeat',
        description: 'Heartbeat file lacks cryptographic signature',
        category: 'heartbeat',
        severity: 'high',
        passed: hasSignature,
        message: hasSignature
          ? 'Heartbeat has cryptographic signature'
          : 'Heartbeat is unsigned - cannot verify authenticity or integrity',
        file: relativePath,
        fixable: false,
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Unsigned heartbeats cannot prove who created them or whether they have been modified. Cryptographic signatures enable authenticity and integrity verification.',
      });

      // HEARTBEAT-004: Dangerous Capabilities
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].toLowerCase();
        for (const cap of HEARTBEAT_DANGEROUS_CAPS) {
          if (line.includes(cap.toLowerCase())) {
            findings.push({
              checkId: 'HEARTBEAT-004',
              name: 'Dangerous Capabilities',
              description: 'Heartbeat requests dangerous capabilities',
              category: 'heartbeat',
              severity: 'critical',
              passed: false,
              message: `Dangerous capability "${cap}" detected in heartbeat`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Heartbeats should use minimal capabilities - avoid shell:*, filesystem:*, network:*',
              guidance: 'Wildcard capabilities (shell:*, filesystem:*, network:*) give heartbeats unrestricted access. A compromised heartbeat with these permissions can execute arbitrary commands, read any file, or exfiltrate data.',
            });
          }
        }
      }

      // HEARTBEAT-005: Excessive Frequency
      // Match both "every: 30s" and "Every 30 minutes:" formats
      const frequencyPattern = /every[:\s]+(\d+)\s*(s|sec|seconds?|m|min|minutes?|h|hours?)/gi;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        frequencyPattern.lastIndex = 0;
        const match = frequencyPattern.exec(line);
        if (match) {
          const value = parseInt(match[1], 10);
          const unit = match[2].toLowerCase();

          // Calculate interval in minutes
          let intervalMinutes = value;
          if (unit.startsWith('s')) {
            intervalMinutes = value / 60;
          } else if (unit.startsWith('h')) {
            intervalMinutes = value * 60;
          }

          if (intervalMinutes < 5) {
            findings.push({
              checkId: 'HEARTBEAT-005',
              name: 'Excessive Frequency',
              description: 'Heartbeat runs too frequently (< 5 minutes)',
              category: 'heartbeat',
              severity: 'medium',
              passed: false,
              message: `Heartbeat interval of ${value}${unit} is less than 5 minutes`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Increase heartbeat interval to at least 5 minutes to prevent resource exhaustion',
              guidance: 'High-frequency heartbeats consume CPU, memory, and network bandwidth. Intervals under 5 minutes can cause resource exhaustion and may mask malicious polling behavior.',
            });
          }
        }
      }

      // HEARTBEAT-006: No Active Hours Limit
      const hasActiveHours =
        /activeHours:/i.test(content) ||
        /schedule:/i.test(content) ||
        /time_window:/i.test(content) ||
        /run_between:/i.test(content);

      findings.push({
        checkId: 'HEARTBEAT-006',
        name: 'No Active Hours Limit',
        description: 'Heartbeat lacks time-of-day restrictions',
        category: 'heartbeat',
        severity: 'medium',
        passed: hasActiveHours,
        message: hasActiveHours
          ? 'Heartbeat has active hours restriction'
          : 'Heartbeat can run 24/7 without time restrictions',
        file: relativePath,
        fixable: false,
        fix: 'Add activeHours: or schedule: to limit when the heartbeat can run',
        guidance: 'Unrestricted heartbeats run 24/7 including off-hours when no one monitors them. Time-of-day limits reduce the window for undetected malicious activity.',
      });
    }

    return findings;
  }

  /**
   * Find OpenClaw gateway configuration files
   */
  private async findGatewayConfigFiles(dir: string): Promise<string[]> {
    const configFiles: string[] = [];
    const candidates = [
      'openclaw.json',
      '.openclaw/config.json',
      'moltbot.json',
      '.moltbot/config.json',
    ];

    for (const candidate of candidates) {
      const fullPath = path.join(dir, candidate);
      try {
        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, dir)) {
          continue;
        }
        // Check if it's a symlink
        const stats = await fs.lstat(fullPath);
        if (stats.isSymbolicLink()) {
          continue; // Skip symlinks to prevent path traversal
        }
        await fs.access(fullPath);
        configFiles.push(fullPath);
      } catch {
        // File doesn't exist
      }
    }

    return configFiles;
  }

  /**
   * OpenClaw gateway security checks (GATEWAY-001 to GATEWAY-006)
   */
  private async checkOpenclawGateway(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const configFiles = await this.findGatewayConfigFiles(targetDir);

    for (const configFile of configFiles) {
      const relativePath = path.relative(targetDir, configFile);

      let content: string;
      let config: Record<string, unknown>;
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(configFile, 'utf-8');
        config = JSON.parse(content);
      } catch {
        continue;
      }

      // Track what fixes we apply
      let configModified = false;
      const fixesApplied: string[] = [];

      // GATEWAY-001: Bound to 0.0.0.0
      const gateway = config.gateway as Record<string, unknown> | undefined;
      const boundToAllInterfaces = gateway && gateway.host === '0.0.0.0';
      let gateway001Fixed = false;

      if (boundToAllInterfaces && autoFix) {
        // Fix: Change 0.0.0.0 to 127.0.0.1
        (config.gateway as Record<string, unknown>).host = '127.0.0.1';
        gateway001Fixed = true;
        configModified = true;
        fixesApplied.push('Changed gateway.host from 0.0.0.0 to 127.0.0.1 (local-only access)');
      }

      if (boundToAllInterfaces) {
        findings.push({
          checkId: 'GATEWAY-001',
          name: 'Bound to 0.0.0.0',
          description: 'Gateway is bound to all interfaces (0.0.0.0)',
          category: 'gateway',
          severity: 'critical',
          passed: gateway001Fixed,
          message: gateway001Fixed
            ? 'Fixed: Gateway now bound to 127.0.0.1 (local-only)'
            : 'Gateway host is 0.0.0.0 - accessible from any network interface',
          file: relativePath,
          fixable: true,
          fixed: gateway001Fixed,
          fixMessage: gateway001Fixed ? 'Changed gateway.host from 0.0.0.0 to 127.0.0.1' : undefined,
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Binding to 0.0.0.0 exposes the gateway to all network interfaces. Use 127.0.0.1 for local-only access unless remote access is explicitly needed with proper authentication.',
        });
      }

      // GATEWAY-002: Missing WebSocket Origin Validation (not auto-fixable - requires user to specify allowed origins)
      const security = config.security as Record<string, unknown> | undefined;
      const hasWebSocketOrigins = security && security.websocketOrigins;
      findings.push({
        checkId: 'GATEWAY-002',
        name: 'Missing WebSocket Origin Validation',
        description: 'Gateway lacks WebSocket origin validation (GHSA-g8p2)',
        category: 'gateway',
        severity: 'critical',
        passed: Boolean(hasWebSocketOrigins),
        message: hasWebSocketOrigins
          ? 'WebSocket origin validation is configured'
          : 'Missing security.websocketOrigins - vulnerable to GHSA-g8p2 cross-origin attacks',
        file: relativePath,
        fixable: false,
        fix: 'Add security.websocketOrigins: ["http://localhost:3000"] to the gateway config',
        guidance: 'Without origin validation, any website can connect to the gateway via WebSocket (GHSA-g8p2). This enables cross-origin command execution attacks.',
      });

      // GATEWAY-003: Token Exposed in Config
      const gatewayAuth = gateway?.auth as Record<string, unknown> | undefined;
      // An environment-variable reference is not a plaintext token. Without
      // this the check re-fired on its OWN remedy — the auto-fix writes
      // `${OPENCLAW_AUTH_TOKEN}`, a non-empty string — so a successfully
      // fixed config stayed failing forever and `fixVerified` was
      // permanently false. Same idiom MCP-003 already uses.
      //
      // `${[^}]+}` accepted ANY braced content, so `${sk-ant-api03-<key>}`
      // read as a reference and the check went quiet on a file with a real
      // key sitting in it. A `${...}` wrapper does not un-leak a secret:
      // whether or not the gateway expands it at runtime, the bytes are on
      // disk for anyone who can read the config. The braced form is now the
      // same shell-identifier grammar as the bare form, which rejects the
      // hyphens and dots every vendor key carries.
      //
      // The identifier grammar alone still admits `$ghp_<36>` — a reference
      // to a variable *named* after a token — so a value whose name opens
      // with a known secret prefix is treated as plaintext rather than as a
      // reference. Prefixes only, deliberately: this decides "is this a
      // reference", not "is this a credential", and the credential detectors
      // own the latter.
      const isEnvRef = (v: unknown): boolean => {
        if (typeof v !== 'string') return false;
        const trimmed = v.trim();
        // Matched braces or none — `${FOO` is malformed, not a reference.
        if (!/^(\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*)$/.test(trimmed)) return false;
        // Only prefixes that can actually survive the grammar above: the
        // hyphen- and dot-bearing vendor formats (`sk-ant-`, `xoxb-`, `SG.`)
        // are already rejected by it.
        return !/^\$\{?(gh[pousr]_|github_pat_|sk_live_|sk_test_|AKIA|AIza)/i.test(trimmed);
      };
      const hasPlaintextTokenInAuth = gatewayAuth && typeof gatewayAuth.token === 'string'
        && gatewayAuth.token.length > 0 && !isEnvRef(gatewayAuth.token);
      const hasPlaintextTokenAtRoot = typeof config.token === 'string'
        && (config.token as string).length > 0 && !isEnvRef(config.token);
      const hasPlaintextToken = hasPlaintextTokenInAuth || hasPlaintextTokenAtRoot;
      let gateway003Fixed = false;

      if (hasPlaintextToken && autoFix) {
        // Fix: Replace plaintext token with environment variable reference
        if (hasPlaintextTokenInAuth && gatewayAuth) {
          gatewayAuth.token = '${OPENCLAW_AUTH_TOKEN}';
          gateway003Fixed = true;
          configModified = true;
          fixesApplied.push('Replaced gateway.auth.token with ${OPENCLAW_AUTH_TOKEN} env var reference');
        }
        if (hasPlaintextTokenAtRoot) {
          config.token = '${OPENCLAW_AUTH_TOKEN}';
          gateway003Fixed = true;
          configModified = true;
          fixesApplied.push('Replaced token with ${OPENCLAW_AUTH_TOKEN} env var reference');
        }
      }

      if (hasPlaintextToken) {
        findings.push({
          checkId: 'GATEWAY-003',
          name: 'Token Exposed in Config',
          description: 'Plaintext authentication token stored in configuration file',
          category: 'gateway',
          severity: 'critical',
          passed: gateway003Fixed,
          message: gateway003Fixed
            ? 'Fixed: Token replaced with ${OPENCLAW_AUTH_TOKEN} - set this env var with your actual token'
            : 'Plaintext token found in configuration - use environment variables instead',
          file: relativePath,
          fixable: true,
          fixed: gateway003Fixed,
          fixMessage: gateway003Fixed ? 'Replaced plaintext token with ${OPENCLAW_AUTH_TOKEN} env var reference. Set OPENCLAW_AUTH_TOKEN in your environment.' : undefined,
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Plaintext tokens in config files are exposed to anyone with repo access. Use environment variable references so credentials stay outside version control.',
        });
      }

      // GATEWAY-004: Approval Confirmations Disabled
      const exec = config.exec as Record<string, unknown> | undefined;
      const approvals = exec?.approvals as Record<string, unknown> | undefined;
      const configApprovals = config.approvals as Record<string, unknown> | undefined;
      const approvalsDisabled =
        approvals?.set === 'off' ||
        approvals?.enabled === false ||
        configApprovals?.enabled === false;
      let gateway004Fixed = false;

      if (approvalsDisabled && autoFix) {
        // Fix: Enable approvals
        if (approvals?.set === 'off') {
          approvals.set = 'on';
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed exec.approvals.set from "off" to "on"');
        }
        if (approvals?.enabled === false) {
          approvals.enabled = true;
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed exec.approvals.enabled to true');
        }
        if (configApprovals?.enabled === false) {
          configApprovals.enabled = true;
          gateway004Fixed = true;
          configModified = true;
          fixesApplied.push('Changed approvals.enabled to true');
        }
      }

      if (approvalsDisabled) {
        findings.push({
          checkId: 'GATEWAY-004',
          name: 'Approval Confirmations Disabled',
          description: 'Execution approval confirmations are disabled',
          category: 'gateway',
          severity: 'critical',
          passed: gateway004Fixed,
          message: gateway004Fixed
            ? 'Fixed: Approval confirmations are now enabled - commands will require user confirmation'
            : 'Approval confirmations disabled - commands execute without user confirmation',
          file: relativePath,
          fixable: true,
          fixed: gateway004Fixed,
          fixMessage: gateway004Fixed ? 'Enabled approval confirmations for command execution' : undefined,
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Without approval confirmations, commands execute immediately without user review. This removes the last line of defense against malicious or accidental destructive operations.',
        });
      }

      // GATEWAY-005: Sandbox Disabled
      const sandbox = config.sandbox as Record<string, unknown> | undefined;
      const sandboxDisabled = sandbox && sandbox.enabled === false;
      let gateway005Fixed = false;

      if (sandboxDisabled && autoFix) {
        // Fix: Enable sandbox
        sandbox.enabled = true;
        gateway005Fixed = true;
        configModified = true;
        fixesApplied.push('Changed sandbox.enabled to true');
      }

      if (sandboxDisabled) {
        findings.push({
          checkId: 'GATEWAY-005',
          name: 'Sandbox Disabled',
          description: 'Sandbox execution environment is disabled',
          category: 'gateway',
          severity: 'critical',
          passed: gateway005Fixed,
          message: gateway005Fixed
            ? 'Fixed: Sandbox is now enabled - code executes in isolated environment'
            : 'Sandbox is disabled - code executes with full system access',
          file: relativePath,
          fixable: true,
          fixed: gateway005Fixed,
          fixMessage: gateway005Fixed ? 'Enabled sandbox mode for isolated code execution' : undefined,
          fix: `${this.cliName} secure-openclaw --fix`,
          guidance: 'Without sandbox isolation, executed code has full system access including filesystem, network, and process control. Sandbox mode limits the blast radius of malicious or buggy code.',
        });
      }

      // GATEWAY-006: Container Escape Risk (not auto-fixable - requires manual review of mount points)
      const docker = config.docker as Record<string, unknown> | undefined;
      const isPrivileged = docker?.privileged === true;
      const mounts = docker?.mounts as string[] | undefined;
      const hasDangerousMounts = mounts?.some(
        (mount: string) =>
          mount.includes('/var/run/docker.sock') ||
          mount.includes('/etc/passwd') ||
          mount.includes('/etc/shadow') ||
          mount.startsWith('/:/') ||
          mount.includes(':/host')
      );

      if (isPrivileged || hasDangerousMounts) {
        const issues: string[] = [];
        if (isPrivileged) issues.push('privileged mode');
        if (hasDangerousMounts) issues.push('sensitive host mounts');
        findings.push({
          checkId: 'GATEWAY-006',
          name: 'Container Escape Risk',
          description: 'Docker configuration allows container escape',
          category: 'gateway',
          severity: 'critical',
          passed: false,
          message: `Container escape risk: ${issues.join(', ')}`,
          file: relativePath,
          fixable: false,
          fix: 'Disable docker.privileged and remove sensitive mounts (/var/run/docker.sock, /etc/passwd, /:/) from the config',
          guidance: 'Privileged mode and sensitive host mounts allow container escape -- the agent can access the host system, other containers, and all their data.',
        });
      }

      // GATEWAY-007: Open DM Policy with Wildcard
      const channels = config.channels as Record<string, Record<string, unknown>> | undefined;
      const dm = config.dm as Record<string, unknown> | undefined;
      let hasOpenDmWildcard = false;

      if (channels) {
        for (const [, channelConfig] of Object.entries(channels)) {
          if (
            channelConfig.dmPolicy === 'open' &&
            Array.isArray(channelConfig.allowFrom) &&
            channelConfig.allowFrom.includes('*')
          ) {
            hasOpenDmWildcard = true;
            break;
          }
        }
      }
      if (!hasOpenDmWildcard && dm?.policy === 'open') {
        const allowList = dm.allowFrom as string[] | undefined;
        if (Array.isArray(allowList) && allowList.includes('*')) {
          hasOpenDmWildcard = true;
        }
      }

      if (hasOpenDmWildcard) {
        findings.push({
          checkId: 'GATEWAY-007',
          name: 'Open DM Policy with Wildcard',
          description: 'Direct message policy allows messages from any source',
          category: 'gateway',
          severity: 'critical',
          passed: false,
          message: 'DM policy is open with wildcard allowFrom - anyone can message the agent',
          file: relativePath,
          fixable: false,
          fix: 'Replace wildcard "*" in allowFrom with specific allowed sender IDs or domains',
          guidance: 'An open DM policy with wildcard allows any entity to send messages to the agent. Attackers can use this to inject commands or exfiltrate data via conversation.',
        });
      }

      // GATEWAY-008: Tailscale Funnel Exposure
      const tailscale = gateway?.tailscale as Record<string, unknown> | undefined;
      const tailscaleRoot = config.tailscale as Record<string, unknown> | undefined;
      const funnelEnabled = tailscale?.funnel === true || tailscaleRoot?.funnel === true;

      if (funnelEnabled) {
        findings.push({
          checkId: 'GATEWAY-008',
          name: 'Tailscale Funnel Exposure',
          description: 'Tailscale Funnel is enabled, exposing the agent to the public internet',
          category: 'gateway',
          severity: 'high',
          passed: false,
          message: 'Tailscale Funnel enabled - agent is publicly accessible from the internet',
          file: relativePath,
          fixable: false,
          fix: 'Disable Tailscale Funnel unless public access is intentional. Use Tailscale ACLs to restrict access.',
          guidance: 'Tailscale Funnel exposes the agent to the public internet, bypassing Tailscale\'s private network protection. Only enable if you explicitly need public access.',
        });
      }

      // Write modified config back to file if any fixes were applied
      if (configModified) {
        // #300 — the one fix write that still bypassed `applyFixWrite`, and
        // so the one still able to rewrite a file the backup cannot restore.
        // Gateway configs are discovered by a recursive walk, exactly like
        // the #292 config files: `openclaw.json` at the root is a backup
        // candidate, the same file one directory down was not. Routed
        // through the choke point; the failure branch is unchanged, since a
        // refused write and a failed write have the same consequence for the
        // findings already pushed against this file.
        const gatewayWritten = await this.applyFixWrite(
          configFile,
          JSON.stringify(config, null, 2) + '\n',
        );
        if (gatewayWritten) {
          // Add a summary finding about what was fixed
          findings.push({
            checkId: 'FIX-SUMMARY',
            name: 'Auto-Fix Applied',
            description: 'Configuration was automatically remediated',
            category: 'gateway',
            severity: 'low',
            passed: true,
            message: `Applied ${fixesApplied.length} fix(es): ${fixesApplied.join('; ')}`,
            file: relativePath,
            fixable: false,
            fix: 'hackmyagent rollback',
            guidance: 'Auto-fixes were applied to this configuration. Use rollback to revert if any fix caused unexpected behavior.',
          });
        } else {
          // The GATEWAY-00x findings above were pushed with
          // `passed: <check>Fixed`, set from an in-memory mutation, before
          // this write ran. The write is what makes them true, so a failure
          // has to take them back — otherwise the report shows `passed: true`
          // for a config sitting unchanged on disk. Unlike the other checks
          // these are already in the array, so revoke in place.
          // Scoped to THIS config file. `findings` accumulates across every
          // entry of the enclosing `for (const configFile of configFiles)`
          // loop — up to four gateway configs — so an unscoped revoke let a
          // failed write on a later file take back the landed fixes of an
          // earlier one, reporting a CRITICAL on a file the tool had just
          // correctly repaired.
          for (const f of findings) {
            if (f.category === 'gateway' && f.fixed && f.file === relativePath) {
              f.passed = false;
              f.fixed = false;
              f.fixMessage = undefined;
              // These read "Fixed: Gateway now bound to 127.0.0.1" while the
              // config on disk is untouched.
              f.message = `${f.name} (auto-fix could not be written)`;
            }
          }
          // No local FIX-ERROR push. `applyFixWrite` has already recorded the
          // path and errno, and `scan()` renders one FIX-WRITE-FAILED finding
          // covering every failed write in the run. Pushing here as well
          // would report a single event twice, and the local finding was the
          // weaker of the two: `fix: 'Check file permissions and try again'`
          // is advice, while FIX-WRITE-FAILED carries a runnable re-run
          // command. Closes #284, which asked for exactly this unification.
        }
      }
    }

    return findings;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[b.length][a.length];
  }

  /**
   * Find files matching a pattern recursively (max depth 3, skips node_modules/.git)
   */
  private async findFilesMatching(
    targetDir: string,
    patterns: string[],
    maxDepth: number = 3
  ): Promise<string[]> {
    const matchedFiles: string[] = [];

    const scanDir = async (dir: string, currentDepth: number): Promise<void> => {
      if (currentDepth > maxDepth) return;

      let entries;
      try {
        entries = await fs.readdir(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        // Skip symlinks to prevent path traversal
        if (entry.isSymbolicLink()) {
          continue;
        }

        const entryName = entry.name;
        const fullPath = path.join(dir, entryName);

        // Validate path is within directory (no path traversal)
        if (!this.isPathWithinDirectory(fullPath, targetDir)) {
          continue;
        }

        // Skip node_modules and .git unconditionally. The only backup
        // directory skipped is the one THIS RUN created (#309) — a name, or a
        // name plus a forgeable manifest, was a suppression token any scanned
        // tree could type, and this walk feeds seven checks.
        if (entryName === 'node_modules' || entryName === '.git') {
          continue;
        }

        let stat;
        try {
          stat = await fs.stat(fullPath);
        } catch {
          continue;
        }

        if (stat.isDirectory()) {
          // #317 — by identity, and against the `stat` this walk already
          // takes, so recognising the run's own backup costs no extra syscall
          // and cannot be defeated by respelling the path. The lexical
          // compare it replaces missed a case variant of the directory name.
          const ctx = this.backupContext;
          if (ctx && sameIdentity({ dev: stat.dev, ino: stat.ino }, ctx.backupIdent)) {
            continue;
          }
          await scanDir(fullPath, currentDepth + 1);
        } else if (stat.isFile()) {
          // Check if filename matches any pattern
          const lowerName = entryName.toLowerCase();
          for (const pattern of patterns) {
            if (lowerName.includes(pattern.toLowerCase())) {
              matchedFiles.push(fullPath);
              break;
            }
          }
        }
      }
    };

    await scanDir(targetDir, 0);
    return matchedFiles;
  }

  /**
   * OpenClaw config security checks (CONFIG-001 to CONFIG-006)
   */
  private async checkOpenclawConfig(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // CONFIG-001: Session File Exposure
    const sessionPatterns = [
      'whatsapp-session',
      'discord-token',
      'telegram-session',
      'slack-token',
      'session.json',
    ];
    const sessionFiles = await this.findFilesMatching(targetDir, sessionPatterns);
    for (const sessionFile of sessionFiles) {
      const relativePath = path.relative(targetDir, sessionFile);
      findings.push({
        checkId: 'CONFIG-001',
        name: 'Session File Exposure',
        description: 'Session/token file found that may contain sensitive credentials',
        category: 'config',
        severity: 'critical',
        passed: false,
        message: `Session/token file exposed: ${path.basename(sessionFile)}`,
        file: relativePath,
        fixable: false,
        fix: 'Move session files outside the project directory or add to .gitignore',
        guidance: 'Session and token files contain credentials that grant access to messaging platforms. If committed to git, anyone with repo access can hijack these sessions.',
      });
    }

    // CONFIG-002: SOUL.md Injection Vectors
    const soulFiles = await this.findFilesMatching(targetDir, ['SOUL.md']);
    for (const soulFile of soulFiles) {
      const relativePath = path.relative(targetDir, soulFile);
      let content: string;
      try {
        const stats = await fs.stat(soulFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(soulFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of PROMPT_INJECTION_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          // Exclude matches inside defensive/governance context
          // SOUL.md templates quote attack phrases to teach defense against them
          const matchIdx = content.indexOf(match[0]);
          const surroundingStart = Math.max(0, matchIdx - 200);
          const surroundingEnd = Math.min(content.length, matchIdx + match[0].length + 100);
          const surrounding = content.slice(surroundingStart, surroundingEnd).toLowerCase();
          const isDefensive = /must never|forbidden|should not|must not|never comply|resist|reject|refuse|do not|defense|hardening|such as|attempt|detect/i.test(surrounding);
          // Also check if the document is a governance doc (3+ constraint phrases)
          const constraintCount = (content.match(/must never|must not|must always|should not|forbidden|prohibited|restricted to|shall not/gi) || []).length;
          if (isDefensive || constraintCount >= 3) continue;

          findings.push({
            checkId: 'CONFIG-002',
            name: 'SOUL.md Injection Vectors',
            description: 'SOUL.md contains potential prompt injection patterns',
            category: 'config',
            severity: 'high',
            passed: false,
            message: `Prompt injection pattern detected: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Review and remove suspicious patterns from SOUL.md',
            guidance: 'SOUL.md defines agent behavior. Prompt injection patterns embedded here can override safety instructions and make the agent act maliciously.',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-003: Daemon Running as Root
    const daemonPatterns = ['daemon.sh', 'start.sh', 'run.sh'];
    const daemonFiles = await this.findFilesMatching(targetDir, daemonPatterns);
    const rootPatterns = [/\bsudo\b/gi, /User=root/gi, /uid=0/gi];
    for (const daemonFile of daemonFiles) {
      const relativePath = path.relative(targetDir, daemonFile);
      let content: string;
      try {
        const stats = await fs.stat(daemonFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(daemonFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of rootPatterns) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-003',
            name: 'Daemon Running as Root',
            description: 'Daemon script runs with root privileges',
            category: 'config',
            severity: 'critical',
            passed: false,
            message: `Root privilege pattern found: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Run daemon as non-root user with minimal privileges',
            guidance: 'Daemons running as root have unrestricted system access. A compromised root-level daemon can modify any file, install backdoors, or pivot to other systems.',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-004: Plaintext API Keys
    const envFiles = await this.findFilesMatching(targetDir, ['.env']);
    for (const envFile of envFiles) {
      const relativePath = path.relative(targetDir, envFile);
      let content: string;
      try {
        const stats = await fs.stat(envFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(envFile, 'utf-8');
      } catch {
        continue;
      }

      for (const { name, pattern } of CREDENTIAL_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-004',
            name: 'Plaintext API Keys',
            description: 'Plaintext API key found in environment file',
            category: 'config',
            severity: 'critical',
            passed: false,
            message: `${name} found in plaintext`,
            file: relativePath,
            fixable: false,
            fix: 'opena2a protect .  — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only.',
            guidance: 'Plaintext API keys in .env files can be accidentally committed to version control and extracted by any process that reads the file.',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-005: Memory Poisoning Patterns
    const memoryFiles = await this.findFilesMatching(targetDir, ['memory.json']);
    const memoryPoisonPatterns = [
      ...PROMPT_INJECTION_PATTERNS,
      /\bbase64\b/gi,
      /\beval\s*\(/gi,
      /\bexec\s*\(/gi,
    ];
    for (const memoryFile of memoryFiles) {
      const relativePath = path.relative(targetDir, memoryFile);
      let content: string;
      try {
        const stats = await fs.stat(memoryFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(memoryFile, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of memoryPoisonPatterns) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'CONFIG-005',
            name: 'Memory Poisoning Patterns',
            description: 'memory.json contains suspicious patterns that could poison agent memory',
            category: 'config',
            severity: 'high',
            passed: false,
            message: `Suspicious pattern in memory: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Review and sanitize memory.json contents',
            guidance: 'Agent memory files can be poisoned with prompt injections, eval calls, or base64-encoded payloads that execute when the agent loads its context.',
          });
          break; // Only report first match per file
        }
      }
    }

    // CONFIG-006: Moltbook Integration Risk
    const openclawConfigFiles = await this.findFilesMatching(targetDir, ['openclaw.json']);
    for (const configFile of openclawConfigFiles) {
      const relativePath = path.relative(targetDir, configFile);
      let config: Record<string, unknown>;
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        const content = await fs.readFile(configFile, 'utf-8');
        config = JSON.parse(content);
      } catch {
        continue;
      }

      const moltbook = config.moltbook as Record<string, unknown> | undefined;
      if (moltbook && moltbook.enabled === true && moltbook.autoFollow === true) {
        findings.push({
          checkId: 'CONFIG-006',
          name: 'Moltbook Integration Risk',
          description: 'Moltbook auto-follow enabled, allowing automatic following of untrusted agents',
          category: 'config',
          severity: 'high',
          passed: false,
          message: 'Moltbook enabled with autoFollow - may auto-follow untrusted agents',
          file: relativePath,
          fixable: false,
          fix: 'Disable autoFollow or review moltbook security settings',
          guidance: 'Auto-following untrusted agents can expose your agent to malicious instructions, data exfiltration, or prompt injection from compromised peers.',
        });
      }

      // CONFIG-007: Unrestricted Elevated Execution
      const tools = config.tools as Record<string, unknown> | undefined;
      const elevated = tools?.elevated as Record<string, unknown> | undefined;
      const exec = config.exec as Record<string, unknown> | undefined;
      const execApprovals = exec?.approvals as Record<string, unknown> | undefined;
      const hasUnrestrictedExec =
        elevated?.defaultLevel === 'full' ||
        execApprovals?.set === 'off';

      if (hasUnrestrictedExec) {
        findings.push({
          checkId: 'CONFIG-007',
          name: 'Unrestricted Elevated Execution',
          description: 'Elevated execution is set to full access without restrictions or approvals are bypassed',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: elevated?.defaultLevel === 'full'
            ? 'tools.elevated.defaultLevel is "full" - all tools run with maximum privileges'
            : 'exec.approvals.set is "off" - execution approval is bypassed',
          file: relativePath,
          fixable: false,
          fix: 'Set tools.elevated.defaultLevel to "restricted" and enable exec.approvals',
          guidance: 'Unrestricted elevated execution gives tools maximum system privileges without approval gates. This bypasses all safety checks for destructive operations.',
        });
      }

      // CONFIG-008: Sandbox Disabled
      const sandbox = config.sandbox as Record<string, unknown> | undefined;
      const toolExec = tools?.exec as Record<string, unknown> | undefined;
      const sandboxDisabled =
        sandbox?.enabled === false ||
        toolExec?.sandbox === false;

      if (sandboxDisabled) {
        findings.push({
          checkId: 'CONFIG-008',
          name: 'Sandbox Disabled',
          description: 'Sandbox execution environment is explicitly disabled in config',
          category: 'config',
          severity: 'high',
          passed: false,
          message: sandbox?.enabled === false
            ? 'sandbox.enabled is false - code runs without isolation'
            : 'tools.exec.sandbox is false - tool execution is not sandboxed',
          file: relativePath,
          fixable: false,
          fix: 'Enable sandbox: set sandbox.enabled to true or tools.exec.sandbox to true',
          guidance: 'Without sandbox isolation, tool execution has direct access to the host filesystem, network, and processes. Enable sandboxing to contain potential damage.',
        });
      }

      // CONFIG-009: Weak Gateway Token
      const gatewayConfig = config.gateway as Record<string, unknown> | undefined;
      const gatewayAuth = gatewayConfig?.auth as Record<string, unknown> | undefined;
      const tokenValue = (gatewayAuth?.token as string) || (config.token as string);
      if (
        typeof tokenValue === 'string' &&
        tokenValue.length > 0 &&
        tokenValue.length < 24 &&
        !tokenValue.startsWith('${')
      ) {
        findings.push({
          checkId: 'CONFIG-009',
          name: 'Weak Gateway Token',
          description: 'Gateway authentication token is too short (< 24 characters)',
          category: 'config',
          severity: 'high',
          passed: false,
          message: `Token is only ${tokenValue.length} characters - minimum 24 recommended`,
          file: relativePath,
          fixable: false,
          fix: 'openssl rand -base64 32',
          guidance: 'Short tokens are vulnerable to brute-force attacks. Use at least 24 characters of cryptographically random data for authentication tokens.',
        });
      }
    }

    return findings;
  }

  /**
   * OpenClaw supply chain security checks (SUPPLY-001 to SUPPLY-004)
   */
  private async checkOpenclawSupplyChain(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const skillFiles = await this.findSkillFiles(targetDir);

    // Known malicious skill patterns from ClawHavoc campaign
    const clawHavocPatterns = [
      'polymarket',
      'better-polymarket',
      'crypto-tracker',
      'solana-tracker',
      'phantom-wallet',
      'youtube-downloader',
      'clawhub',
      'clawhub1',
      'clawhubb',
      'cllawhub',
      'clawhub-official',
      'openclaw-official',
      'openclaw1',
      'opennclaw',
      'insiderwallet',
      'wallet-finder',
      'crypto-insider',
    ];

    for (const skillFile of skillFiles) {
      // When secure targets the skill file directly, path.relative is '' —
      // fall back to the basename so findings keep a file path (the CLI filters
      // out file-less findings) and remain CISO-actionable.
      const relativePath = path.relative(targetDir, skillFile) || path.basename(skillFile);

      let content: string;
      try {
        const stats = await fs.stat(skillFile);
        if (stats.size > MAX_FILE_SIZE) {
          findings.push({
            checkId: 'SCAN-001',
            name: 'Oversized File',
            description: 'File exceeds maximum scan size',
            category: 'scan',
            severity: 'medium',
            passed: false,
            message: `File ${relativePath} is ${Math.round(stats.size / 1024 / 1024)}MB - skipped (max ${MAX_FILE_SIZE / 1024 / 1024}MB)`,
            file: relativePath,
            fixable: false,
            fix: 'Reduce file size or exclude from scan',
            guidance: 'Oversized files can be used to evade security scanning. Attackers hide malicious content in large files knowing scanners will skip them.',
          });
          continue;
        }
        content = await fs.readFile(skillFile, 'utf-8');
      } catch {
        continue;
      }

      // Parse YAML frontmatter
      const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
      const frontmatter = frontmatterMatch ? frontmatterMatch[1] : '';

      // Extract skill name from filename or frontmatter
      const skillNameMatch = frontmatter.match(/^name:\s*(.+)$/m);
      const skillName = skillNameMatch
        ? skillNameMatch[1].trim().replace(/["']/g, '').toLowerCase()
        : path.basename(path.dirname(skillFile)).toLowerCase();

      // SUPPLY-001: Unverified Publisher
      // Issue #135: hygiene default MEDIUM; HIGH on malice co-occurrence.
      const supplyMaliceUpgrade = hasSkillMaliceSignals(content);
      const supplySeverity: 'high' | 'medium' = supplyMaliceUpgrade ? 'high' : 'medium';
      const hasPublisher = /^publisher:\s*.+$/m.test(frontmatter);
      const hasPublisherVerified = /^publisher_verified:\s*true$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-001',
        name: 'Unverified Publisher',
        description: 'Skill publisher identity has not been verified',
        category: 'supply',
        severity: supplySeverity,
        passed: hasPublisher && hasPublisherVerified,
        message: hasPublisher && hasPublisherVerified
          ? 'Skill publisher is verified'
          : hasPublisher
            ? 'Skill has publisher but publisher_verified is not true'
            : 'Skill lacks publisher metadata - cannot verify source',
        file: relativePath,
        fixable: false,
        fix: commandNaming(relativePath, (q) => `hackmyagent check ${q}`)
              ?? 'Inspect the file named in this finding by hand — its name cannot be shown truthfully in a shell command.',
        guidance: 'Unverified publishers cannot be trusted. Add publisher: and publisher_verified: true to skill frontmatter after DNS TXT record verification.',
      });

      // SUPPLY-002: Skill Not in Registry
      const hasRegistryAttestation = /^registry_attestation:\s*.+$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-002',
        name: 'Skill Not in Registry',
        description: 'Skill has not been registered with a trusted skill registry',
        category: 'supply',
        severity: 'medium',
        passed: hasRegistryAttestation,
        message: hasRegistryAttestation
          ? 'Skill has registry attestation'
          : 'Skill lacks registry_attestation - not listed in trusted registry',
        file: relativePath,
        fixable: false,
        fix: 'Add registry_attestation: to skill frontmatter after registry submission',
        guidance: 'Unregistered skills have no community trust signal. Register with a trusted registry to enable trust scoring and vulnerability alerts.',
      });

      // SUPPLY-003: Known Malicious Skill Pattern (ClawHavoc campaign)
      let isMaliciousMatch = false;
      let matchedPattern = '';

      for (const pattern of clawHavocPatterns) {
        // Check for exact match or substring
        if (skillName.includes(pattern)) {
          isMaliciousMatch = true;
          matchedPattern = pattern;
          break;
        }

        // Check for typosquatting (Levenshtein distance <= 1)
        const distance = this.levenshteinDistance(skillName, pattern);
        if (distance <= 1 && distance > 0) {
          isMaliciousMatch = true;
          matchedPattern = `${skillName} (similar to ${pattern})`;
          break;
        }
      }

      if (isMaliciousMatch) {
        findings.push({
          checkId: 'SUPPLY-003',
          name: 'Known Malicious Skill Pattern',
          description: 'Skill matches known malicious patterns from ClawHavoc campaign',
          category: 'supply',
          severity: 'critical',
          passed: false,
          message: `Skill matches known malicious pattern: "${matchedPattern}"`,
          file: relativePath,
          fixable: false,
          fix: removeFileFix(relativePath, 'This skill matches a known ClawHavoc pattern.'),
          guidance: 'This skill matches known malicious patterns from the ClawHavoc campaign. Remove immediately and audit any systems it had access to.',
        });
      }

      // SUPPLY-004: Version Drift Detection
      // Issue #135: shares the same malice-upgrade gate as SUPPLY-001.
      const hasInstalledHash = /^installed_hash:\s*.+$/m.test(frontmatter);

      findings.push({
        checkId: 'SUPPLY-004',
        name: 'Version Drift Detection',
        description: 'Skill lacks installed_hash for detecting unauthorized modifications',
        category: 'supply',
        severity: supplySeverity,
        passed: hasInstalledHash,
        message: hasInstalledHash
          ? 'Skill has installed_hash for integrity verification'
          : 'Skill lacks installed_hash - cannot detect version drift or tampering',
        file: relativePath,
        fixable: false,
        fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
        guidance: 'Without an installed_hash, modifications to the skill cannot be detected. The hash enables tamper detection on every scan.',
      });

      // SUPPLY-005: ClawHavoc C2 IP
      for (const ip of CLAWHAVOC_C2_IPS) {
        if (content.includes(ip)) {
          findings.push({
            checkId: 'SUPPLY-005',
            name: 'ClawHavoc C2 IP Detected',
            description: 'Skill contains known ClawHavoc command-and-control IP address',
            category: 'supply',
            severity: 'critical',
            passed: false,
            message: `Known C2 IP address found: ${ip}`,
            file: relativePath,
            fixable: false,
            fix: removeFileFix(relativePath, 'This skill contains a known ClawHavoc C2 IP address.'),
            guidance: 'This skill contains a known ClawHavoc command-and-control IP address. Remove immediately and check network logs for connections to this IP.',
          });
          break;
        }
      }

      // SUPPLY-006: Malware Filenames
      for (const filename of CLAWHAVOC_MALICIOUS_FILES) {
        if (content.toLowerCase().includes(filename.toLowerCase())) {
          findings.push({
            checkId: 'SUPPLY-006',
            name: 'ClawHavoc Malware Filename',
            description: 'Skill references known ClawHavoc malware payload filename',
            category: 'supply',
            severity: 'critical',
            passed: false,
            message: `Known malware filename referenced: "${filename}"`,
            file: relativePath,
            fixable: false,
            fix: removeFileFix(relativePath, 'This skill references a known ClawHavoc malware payload filename.'),
            guidance: 'This skill references a known ClawHavoc malware payload filename. Remove and scan for other indicators of compromise.',
          });
          break;
        }
      }

      // SUPPLY-007: ClickFix Pattern
      for (const pattern of CLAWHAVOC_CLICKFIX_PATTERNS) {
        const match = content.match(pattern);
        if (match) {
          findings.push({
            checkId: 'SUPPLY-007',
            name: 'ClawHavoc ClickFix Pattern',
            description: 'Skill contains social engineering instructions to execute malware',
            category: 'supply',
            severity: 'high',
            passed: false,
            message: `ClickFix social engineering pattern detected: "${match[0]}"`,
            file: relativePath,
            fixable: false,
            fix: 'Remove the download/execute instruction from this skill',
            guidance: 'ClickFix patterns trick users into downloading and executing malware. This technique is associated with the ClawHavoc campaign.',
          });
          break;
        }
      }

      // SUPPLY-008: Suspicious Archive Password
      const archiveMatch = content.match(CLAWHAVOC_ARCHIVE_PASSWORD);
      if (archiveMatch) {
        findings.push({
          checkId: 'SUPPLY-008',
          name: 'Suspicious Archive Password',
          description: 'Skill contains password-protected archive reference typical of malware distribution',
          category: 'supply',
          severity: 'high',
          passed: false,
          message: `Suspicious archive password pattern: "${archiveMatch[0]}"`,
          file: relativePath,
          fixable: false,
          fix: 'Remove the archive password reference from this skill',
          guidance: 'Password-protected archives are a common malware distribution technique to bypass antivirus scanning. Investigate the archive source.',
        });
      }
    }

    return findings;
  }

  /**
   * OpenClaw CVE-specific checks (CVE-001, CVE-002, CVE-003, CVE-004)
   */
  private async checkOpenclawCVE(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // CVE-001: Vulnerable OpenClaw Version
    const pkgJsonPath = path.join(targetDir, 'package.json');
    try {
      const pkgContent = await fs.readFile(pkgJsonPath, 'utf-8');
      const pkg = JSON.parse(pkgContent);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      const openclawVersion = deps?.openclaw || deps?.['@openclaw/core'];

      if (openclawVersion) {
        // Extract numeric version (strip ^ ~ >= etc.)
        const versionMatch = openclawVersion.match(/(\d{4})\.(\d{1,2})\.(\d{1,2})/);
        if (versionMatch) {
          const year = parseInt(versionMatch[1], 10);
          const month = parseInt(versionMatch[2], 10);
          const day = parseInt(versionMatch[3], 10);

          // Patch release: v2026.1.29
          const isVulnerable =
            year < 2026 ||
            (year === 2026 && month < 1) ||
            (year === 2026 && month === 1 && day < 29);

          findings.push({
            checkId: 'CVE-001',
            name: 'CVE-2026-25253: WebSocket Hijacking RCE',
            description: 'OpenClaw version vulnerable to CVE-2026-25253 (CVSS 8.8) - WebSocket hijacking enables 1-click RCE',
            category: 'cve',
            severity: 'critical',
            passed: !isVulnerable,
            message: isVulnerable
              ? `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-25253 - upgrade to v2026.1.29+`
              : `OpenClaw ${openclawVersion} includes CVE-2026-25253 fix`,
            file: 'package.json',
            fixable: false,
            fix: 'npm install openclaw@latest',
            guidance: 'CVE-2026-25253 (CVSS 8.8) enables WebSocket hijacking for remote code execution. Upgrade to v2026.1.29 or later which includes the fix.',
          });
          // CVE-003: OS Command Injection via SSH Path (same fix version)
          if (isVulnerable) {
            findings.push({
              checkId: 'CVE-003',
              name: 'CVE-2026-25157: OS Command Injection via SSH Path',
              description: 'OpenClaw version vulnerable to CVE-2026-25157 (CVSS 7.8) - unescaped project path enables command injection on SSH hosts',
              category: 'cve',
              severity: 'high',
              passed: false,
              message: `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-25157 - upgrade to v2026.1.29+`,
              file: 'package.json',
              fixable: false,
              fix: 'npm install openclaw@latest',
              guidance: 'CVE-2026-25157 (CVSS 7.8) allows OS command injection via unescaped SSH project paths. Upgrade to v2026.1.29 or later which includes the fix.',
            });
          } else {
            findings.push({
              checkId: 'CVE-003',
              name: 'CVE-2026-25157: OS Command Injection via SSH Path',
              description: 'OpenClaw version includes CVE-2026-25157 fix',
              category: 'cve',
              severity: 'high',
              passed: true,
              message: `OpenClaw ${openclawVersion} includes CVE-2026-25157 fix`,
              file: 'package.json',
              fixable: false,
              fix: 'No action needed',
              guidance: 'CVE-2026-25157 (CVSS 7.8) allows OS command injection via unescaped SSH project paths. Your version includes the fix.',
            });
          }

          // CVE-004: Docker PATH Command Injection (same fix version)
          if (isVulnerable) {
            findings.push({
              checkId: 'CVE-004',
              name: 'CVE-2026-24763: Docker PATH Command Injection',
              description: 'OpenClaw version vulnerable to CVE-2026-24763 (CVSS 8.8) - unsafe PATH handling enables command injection in Docker sandbox',
              category: 'cve',
              severity: 'critical',
              passed: false,
              message: `OpenClaw ${openclawVersion} is vulnerable to CVE-2026-24763 - upgrade to v2026.1.29+`,
              file: 'package.json',
              fixable: false,
              fix: 'npm install openclaw@latest',
              guidance: 'CVE-2026-24763 (CVSS 8.8) allows command injection through unsafe PATH handling in Docker sandbox. Upgrade to v2026.1.29 or later which includes the fix.',
            });
          } else {
            findings.push({
              checkId: 'CVE-004',
              name: 'CVE-2026-24763: Docker PATH Command Injection',
              description: 'OpenClaw version includes CVE-2026-24763 fix',
              category: 'cve',
              severity: 'critical',
              passed: true,
              message: `OpenClaw ${openclawVersion} includes CVE-2026-24763 fix`,
              file: 'package.json',
              fixable: false,
              fix: 'No action needed',
              guidance: 'CVE-2026-24763 (CVSS 8.8) allows command injection through unsafe PATH handling in Docker sandbox. Your version includes the fix.',
            });
          }
        }
      }
    } catch {
      // No package.json or parse error - skip CVE checks
    }

    // CVE-002: Control UI Origin Restrictions (defense-in-depth)
    const configFiles = await this.findGatewayConfigFiles(targetDir);
    for (const configFile of configFiles) {
      const relativePath = path.relative(targetDir, configFile);
      try {
        const stats = await fs.stat(configFile);
        if (stats.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(configFile, 'utf-8');
        const config = JSON.parse(content);

        const gateway = config.gateway as Record<string, unknown> | undefined;
        const controlUi = gateway?.controlUi as Record<string, unknown> | undefined;
        const hasAllowedOrigins = controlUi?.allowedOrigins && Array.isArray(controlUi.allowedOrigins) && controlUi.allowedOrigins.length > 0;

        // Only flag if auth is configured (no auth = lower risk)
        const hasAuth = gateway?.auth || config.auth || config.token || gateway?.token;

        if (hasAuth && !hasAllowedOrigins) {
          findings.push({
            checkId: 'CVE-002',
            name: 'Control UI Origin Restrictions Not Configured',
            description: 'Auth is configured but controlUi.allowedOrigins is not set - adding explicit origin restrictions provides defense-in-depth',
            category: 'cve',
            severity: 'medium',
            passed: false,
            message: 'Auth configured without controlUi.allowedOrigins - consider adding explicit origin restrictions for defense-in-depth',
            file: relativePath,
            fixable: false,
            fix: 'Add gateway.controlUi.allowedOrigins with your allowed origins (e.g., ["http://localhost:3000"])',
            guidance: 'Without origin restrictions, the control UI can be accessed from any origin. Adding allowedOrigins provides defense-in-depth against cross-origin attacks.',
          });
        } else if (hasAuth && hasAllowedOrigins) {
          findings.push({
            checkId: 'CVE-002',
            name: 'Control UI Origin Restrictions Configured',
            description: 'Control UI origin restrictions are configured',
            category: 'cve',
            severity: 'medium',
            passed: true,
            message: 'controlUi.allowedOrigins is configured',
            file: relativePath,
            fixable: false,
            fix: 'No action needed',
            guidance: 'Origin restrictions prevent cross-origin attacks against the control UI. Your configuration is correctly limiting allowed origins.',
          });
        }
      } catch {
        continue;
      }
    }

    return findings;
  }

  /**
   * Recursively find source files (.ts, .js, .mjs, .cjs, .tsx, .jsx)
   * Skips node_modules, dist, .git, and hidden directories
   */
  private async findSourceFiles(
    dir: string,
    baseDir: string,
    depth: number = 0
  ): Promise<string[]> {
    if (depth > 10) return [];

    const sourceExtensions = new Set(['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx']);
    const skipDirs = new Set(['node_modules', 'dist', '.git']);
    const files: string[] = [];

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      // Validate path is within directory (no path traversal)
      if (!this.isPathWithinDirectory(fullPath, baseDir)) {
        continue;
      }

      if (entry.isDirectory()) {
        // Skip node_modules, dist, .git, and hidden directories
        if (skipDirs.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;

        // Skip symlinks to prevent path traversal
        try {
          const stats = await fs.lstat(fullPath);
          if (stats.isSymbolicLink()) continue;
        } catch {
          continue;
        }

        const subFiles = await this.findSourceFiles(fullPath, baseDir, depth + 1);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (sourceExtensions.has(ext)) {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  /**
   * Walk a directory recursively and return files matching the given extensions.
   * Skips node_modules, dist, .git, and hidden directories.
   */
  private async walkDirectory(
    dir: string,
    extensions: string[],
    depth: number = 0,
    maxDepth: number = 10
  ): Promise<string[]> {
    if (depth > maxDepth) return [];

    const extSet = new Set(extensions.map((e) => e.toLowerCase()));
    const skipDirs = new Set(['node_modules', 'dist', '.git', '__pycache__', '.venv']);
    const files: string[] = [];

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;
        const subFiles = await this.walkDirectory(fullPath, extensions, depth + 1, maxDepth);
        files.push(...subFiles);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extSet.has(ext)) {
          files.push(fullPath);
        }
      }
    }

    return files;
  }

  /**
   * Check for memory/context poisoning risks
   * Detects patterns that could allow attackers to poison agent memory or conversation context
   */
  private async checkMemoryPoisoning(targetDir: string, _autoFix: boolean): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // MEM-001: Unvalidated memory persistence
    // Check for memory/context files that accept external input without validation
    const memoryFiles = ['memory.json', 'context.json', '.memory', 'agent-memory.json', 'conversation-history.json'];
    for (const memFile of memoryFiles) {
      const filePath = path.join(targetDir, memFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        // Check if memory file is world-writable or contains unvalidated external refs
        if (content.includes('$ref') || content.includes('__proto__') || content.includes('constructor')) {
          findings.push({
            checkId: 'MEM-001',
            name: 'Unvalidated memory persistence',
            description: 'Memory file contains prototype pollution vectors or unvalidated external references that could be exploited to inject malicious context',
            category: 'memory-poisoning',
            severity: 'high',
            passed: false,
            message: `Memory file ${memFile} contains potentially dangerous patterns ($ref, __proto__, constructor)`,
            fixable: false,
            file: memFile,
            fix: 'Sanitize all memory entries before persistence. Remove __proto__ and constructor keys. Validate $ref URIs.',
            guidance: 'Prototype pollution via __proto__ or constructor can alter object behavior. External $ref URIs can load malicious content into agent memory at runtime.',
          });
        }
      } catch { /* file doesn't exist - skip */ }
    }

    // MEM-002: No memory integrity verification
    // Check if conversation/memory files have integrity checks
    const configFiles = ['agent-config.json', 'config.json', 'settings.json', '.agent.json'];
    for (const cfgFile of configFiles) {
      const filePath = path.join(targetDir, cfgFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.memory || config.context || config.conversationHistory) {
          const hasIntegrity = config.memoryIntegrity || config.contextVerification ||
                             config.memory?.signatureVerification || config.memory?.hashValidation;
          if (!hasIntegrity) {
            findings.push({
              checkId: 'MEM-002',
              name: 'No memory integrity verification',
              description: 'Agent configuration enables memory/context persistence without integrity verification. An attacker with file access could inject malicious context.',
              category: 'memory-poisoning',
              severity: 'medium',
              passed: false,
              message: `${cfgFile} enables memory persistence without integrity checks`,
              fixable: false,
              file: cfgFile,
              fix: 'Enable memory integrity verification: add hash validation or signature checks for persisted context.',
              guidance: 'Without integrity checks, an attacker with file access can modify persisted memory to inject malicious instructions that the agent will trust on reload.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // MEM-003: Context window overflow risk
    // Check for agents that load large context without size limits
    for (const cfgFile of configFiles) {
      const filePath = path.join(targetDir, cfgFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.contextWindow || config.maxTokens || config.memory) {
          const hasLimits = config.maxContextSize || config.contextWindow?.maxSize ||
                           config.memory?.maxEntries || config.memory?.maxSize;
          if (!hasLimits) {
            findings.push({
              checkId: 'MEM-003',
              name: 'No context size limits',
              description: 'Agent loads context/memory without size limits. An attacker could craft inputs that overflow the context window, pushing safety instructions out of scope.',
              category: 'memory-poisoning',
              severity: 'medium',
              passed: false,
              message: `${cfgFile} has no context size limits configured`,
              fixable: false,
              file: cfgFile,
              fix: 'Set explicit context size limits: maxContextSize, memory.maxEntries, or memory.maxSize.',
              guidance: 'Without size limits, an attacker can craft inputs that overflow the context window, pushing safety instructions out of scope and taking over agent behavior.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // MEM-004: Shared memory without isolation
    // Check for multi-agent setups with shared memory
    const multiAgentFiles = ['agents.json', 'orchestrator.json', 'multi-agent.json', '.agents'];
    for (const maFile of multiAgentFiles) {
      const filePath = path.join(targetDir, maFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        const agents = config.agents || config.workers || [];
        if (Array.isArray(agents) && agents.length > 1) {
          const sharedMem = config.sharedMemory || config.shared?.memory || config.commonContext;
          if (sharedMem) {
            const hasIsolation = sharedMem.isolation || sharedMem.sandboxed || sharedMem.perAgent;
            if (!hasIsolation) {
              findings.push({
                checkId: 'MEM-004',
                name: 'Shared memory without isolation',
                description: 'Multiple agents share memory without isolation boundaries. A compromised agent could poison the shared context to influence other agents.',
                category: 'memory-poisoning',
                severity: 'high',
                passed: false,
                message: `${maFile} configures shared memory for ${agents.length} agents without isolation`,
                fixable: false,
                file: maFile,
                fix: 'Enable memory isolation: set sharedMemory.isolation=true or use per-agent memory scopes.',
                guidance: 'Shared memory without isolation lets a compromised agent poison context used by all other agents. Use per-agent scopes to prevent cross-agent influence.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // MEM-005: Conversation history injection
    // Check source files for patterns that build prompts from unvalidated history
    try {
      const srcDir = path.join(targetDir, 'src');
      const srcExists = await fs.access(srcDir).then(() => true).catch(() => false);
      if (srcExists) {
        const files = await this.walkDirectory(srcDir, [...JS_FAMILY_EXTENSIONS, '.py']);
        for (const file of files.slice(0, 50)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              // Detect direct concatenation of history into system prompts
              if ((line.includes('systemPrompt') || line.includes('system_prompt') || line.includes('system_message')) &&
                  (line.includes('history') || line.includes('previousMessages') || line.includes('conversation'))) {
                if (!line.includes('sanitize') && !line.includes('validate') && !line.includes('filter')) {
                  findings.push({
                    checkId: 'MEM-005',
                    name: 'Conversation history injection',
                    description: 'System prompt includes unvalidated conversation history. An attacker could craft messages in history that inject instructions into the system prompt.',
                    category: 'memory-poisoning',
                    severity: 'high',
                    passed: false,
                    message: 'System prompt concatenates unvalidated conversation history',
                    fixable: false,
                    file: path.relative(targetDir, file),
                    line: i + 1,
                    fix: 'Sanitize conversation history before including in system prompts. Strip instruction-like patterns.',
                    guidance: 'Unvalidated conversation history concatenated into system prompts enables indirect prompt injection. Attackers can craft messages that inject instructions.',
                  });
                  break; // One finding per file
                }
              }
            }
          } catch { /* skip unreadable */ }
        }
      }
    } catch { /* skip */ }

    return findings;
  }

  /**
   * Check for RAG (Retrieval-Augmented Generation) poisoning risks
   * Detects patterns that could allow attackers to inject malicious content into RAG pipelines
   */
  private async checkRAGPoisoning(targetDir: string, _autoFix: boolean): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // RAG-001: Unvalidated retrieval sources
    const ragConfigFiles = ['rag.json', 'retrieval.json', 'vector-store.json', 'embeddings.json'];
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        const sources = config.sources || config.dataSources || config.indices || [];
        if (Array.isArray(sources)) {
          for (const source of sources) {
            const sourceUrl = source.url || source.endpoint || source.uri || '';
            if (sourceUrl && !source.verified && !source.trustedSource && !source.signatureCheck) {
              findings.push({
                checkId: 'RAG-001',
                name: 'Unvalidated RAG retrieval source',
                description: 'RAG pipeline retrieves from an unverified source. An attacker who controls the source could inject malicious content into agent responses.',
                category: 'rag-poisoning',
                severity: 'high',
                passed: false,
                message: `RAG source ${sourceUrl} has no verification or trust validation`,
                fixable: false,
                file: ragFile,
                fix: 'Add source verification: set trustedSource=true only for validated endpoints, or enable signatureCheck.',
                guidance: 'Unverified RAG sources can be compromised to inject malicious instructions into agent context. Verify sources with signatures or explicit trust markers.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }

    // RAG-002: No content sanitization in retrieval pipeline
    //
    // Context gate (hma#108, CSR-011): the original check matched keyword
    // substrings anywhere on a line, which fires on data-catalog string
    // literals like `description: "...store and retrieve context..."`. Real
    // retrieval code is shaped like a CallExpression — a retriever method
    // call or a prompt-assembly template concat. Require that shape before
    // firing. Classification: (a) preserved-detection FP-suppress.
    //
    // POSITIVE shapes (still fire):
    //   - `vectorStore.similaritySearch(q)` / `.retrieve(q)` / `.vectorSearch(q)`
    //   - `query_engine.query(...)` / `retriever.get(...)`
    //   - ``prompt = `...${retrievedDoc}` `` / `systemPrompt += context`
    //
    // NEGATIVE shapes (suppress):
    //   - `description: "store and retrieve context across conversations"`
    //   - Markdown/doc strings mentioning retrieval concepts
    const RETRIEVAL_CALL_RE = /(?:\.(?:retrieve|vectorSearch|vector_search|similaritySearch|similarity_search|get|query|invoke|ainvoke|get_relevant_documents|aget_relevant_documents)\s*\()|(?:\bquery_engine\s*\.\s*\w+\s*\()|(?:\bretriever\s*\.\s*\w+\s*\()/;
    // Accept any non-whitespace RHS: covers Python f-strings (`prompt = f"..."`),
    // bare concat (`context += retrieved`), template literals, and string
    // concat. The outer filter already requires a retrieval keyword on the
    // same line, so plain-constant assignments like `const prompt = 'hi';`
    // never reach this gate.
    const PROMPT_ASSIGN_RE = /\b(?:prompt|systemPrompt|userPrompt|context|augmented|ragContext|retrievedContext)\s*[+]?=\s*\S/;
    // Data-string shape: `identifier: "..."` or `"identifier": "..."` as the
    // entire line (trimmed). Only quoted scalars count as data — template
    // literals (backticks) are code, not data. Each quote alternative allows
    // the OPPOSITE quote character inside the value, so catalog lines like
    // `longDescription: "Use 'retrieve' to get context (see docs)."` are
    // recognized as pure data (adversarial-review lock against the #108
    // bypass where an internal single-quote broke the generic `[^"']*`).
    const DATA_STRING_LINE_RE = /^\s*["']?\w+["']?\s*:\s*(?:"[^"]*"|'[^']*'),?\s*$/;
    try {
      const srcDir = path.join(targetDir, 'src');
      const srcExists = await fs.access(srcDir).then(() => true).catch(() => false);
      if (srcExists) {
        const files = await this.walkDirectory(srcDir, [...JS_FAMILY_EXTENSIONS, '.py']);
        for (const file of files.slice(0, 50)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
              const line = lines[i];
              if ((line.includes('retrieve') || line.includes('vectorSearch') || line.includes('similarity_search') ||
                   line.includes('query_engine')) &&
                  (line.includes('context') || line.includes('prompt') || line.includes('augment'))) {
                // Context gate: suppress pure data-string property lines
                // (catalog entries, docstrings). Any line with a function call
                // or a prompt-like assignment falls through to the original
                // sanitization check — preserves detection on embedded
                // retrieval calls like `{ prompt: \`${retrieve(x)}\` }`.
                const isRetrievalCall = RETRIEVAL_CALL_RE.test(line);
                const isPromptAssembly = PROMPT_ASSIGN_RE.test(line);
                const isDataString = DATA_STRING_LINE_RE.test(line);
                const hasFunctionCall = line.includes('(');
                if (isDataString) continue;
                if (!isRetrievalCall && !isPromptAssembly && !hasFunctionCall) continue;
                // Check surrounding lines for sanitization
                const surroundingLines = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join(' ');
                if (!surroundingLines.includes('sanitize') && !surroundingLines.includes('validate') &&
                    !surroundingLines.includes('filter') && !surroundingLines.includes('escape')) {
                  findings.push({
                    checkId: 'RAG-002',
                    name: 'No RAG content sanitization',
                    description: 'Retrieved content is passed to the LLM without sanitization. Poisoned documents could inject instructions into the prompt.',
                    category: 'rag-poisoning',
                    severity: 'high',
                    passed: false,
                    message: 'Retrieved content flows to LLM without sanitization',
                    fixable: false,
                    file: path.relative(targetDir, file),
                    line: i + 1,
                    fix: 'Sanitize retrieved content before including in prompts. Strip instruction-like patterns and markup.',
                    guidance: 'Poisoned documents in a vector store can contain prompt injections that override agent behavior when retrieved. Sanitize before including in prompts.',
                  });
                  break;
                }
              }
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }

    // RAG-003: Public-writable vector store
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.writeAccess === 'public' || config.allowPublicIngestion || config.openIngestion) {
          findings.push({
            checkId: 'RAG-003',
            name: 'Public-writable vector store',
            description: 'Vector store allows public write access. An attacker could insert poisoned documents that will be retrieved and influence agent responses.',
            category: 'rag-poisoning',
            severity: 'critical',
            passed: false,
            message: `${ragFile} allows public write access to vector store`,
            fixable: false,
            file: ragFile,
            fix: 'Restrict vector store write access. Require authentication for document ingestion.',
            guidance: 'Public-writable vector stores let anyone inject poisoned documents. These documents are retrieved by the agent and can influence its responses and behavior.',
          });
        }
      } catch { /* skip */ }
    }

    // RAG-004: No provenance tracking on retrieved content
    for (const ragFile of ragConfigFiles) {
      const filePath = path.join(targetDir, ragFile);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);
        if (config.sources || config.dataSources || config.indices) {
          if (!config.provenance && !config.sourceTracking && !config.metadata?.trackSource) {
            findings.push({
              checkId: 'RAG-004',
              name: 'No provenance tracking',
              description: 'RAG pipeline does not track provenance of retrieved content. Without provenance, poisoned content cannot be traced back to its source.',
              category: 'rag-poisoning',
              severity: 'medium',
              passed: false,
              message: `${ragFile} has no content provenance tracking`,
              fixable: false,
              file: ragFile,
              fix: 'Enable provenance tracking: set sourceTracking=true to track which source each document came from.',
              guidance: 'Without provenance tracking, poisoned content cannot be traced to its source during incident response. Source tracking enables rapid identification and removal.',
            });
          }
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for agent identity spoofing risks
   * Detects missing or weak agent identity verification
   */
  private async checkAgentIdentity(targetDir: string, _autoFix: boolean): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // AIM-001: No agent identity declaration
    const identityFiles = ['agent-card.json', '.well-known/agent-card.json', 'agent.json', '.well-known/agent.json', 'aim.json', '.well-known/aim.json'];
    let hasIdentity = false;
    for (const idFile of identityFiles) {
      const filePath = path.join(targetDir, idFile);
      try {
        await fs.access(filePath);
        hasIdentity = true;

        const content = await fs.readFile(filePath, 'utf-8');
        const config = JSON.parse(content);

        // AIM-002: Identity without cryptographic binding
        // Skip if authentication is explicitly declared as "none" (local/CLI tools with no network identity).
        const hasExplicitNoAuth = config.authentication?.type === 'none';
        if ((config.agentId || config.name || config.identity) && !hasExplicitNoAuth) {
          if (!config.publicKey && !config.keyId && !config.jwk && !config.x509) {
            // Soften to MEDIUM inside examples/templates/docs/samples —
            // these are schema demonstrations, not production identities.
            // An insecure example still teaches insecure practice, so we
            // report (not skip) but lower the alarm. [CSR-002].
            // Check both the relative file path AND targetDir, because
            // the scanner only looks for agent-card.json at the scan
            // root — when the user scans `.../examples/my-agent/`,
            // idFile is just `agent-card.json` with no example marker,
            // but targetDir itself carries it.
            const isExample = isExamplePath(idFile) || isExamplePath(targetDir);
            findings.push({
              checkId: 'AIM-002',
              name: 'Identity without cryptographic binding',
              description: 'Agent declares an identity but has no cryptographic key binding. Any agent could claim this identity without proof.',
              category: 'identity-spoofing',
              severity: isExample ? 'medium' : 'high',
              passed: false,
              message: isExample
                ? `${idFile} is an example/template — identity schema shown without cryptographic key binding`
                : `${idFile} declares identity without cryptographic key binding`,
              fixable: false,
              file: idFile,
              fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
              guidance: 'Without cryptographic binding, any agent can impersonate this identity. Ed25519 key pairs provide proof of identity through digital signatures.',
            });
          }
        }

        // AIM-003: No identity verification endpoint
        if (config.agentId || config.identity) {
          if (!config.verificationEndpoint && !config.oidcIssuer && !config.wellKnown) {
            findings.push({
              checkId: 'AIM-003',
              name: 'No identity verification endpoint',
              description: 'Agent identity has no verification endpoint. Other agents cannot verify this agent\'s identity claims.',
              category: 'identity-spoofing',
              severity: 'medium',
              passed: false,
              message: `${idFile} has no identity verification endpoint (verificationEndpoint, oidcIssuer, or wellKnown)`,
              fixable: false,
              file: idFile,
              fix: 'Add a verification endpoint: verificationEndpoint URL or oidcIssuer for federated identity.',
              guidance: 'Without a verification endpoint, other agents and registries cannot verify identity claims. This enables identity spoofing in multi-agent systems.',
            });
          }
        }
      } catch { /* skip */ }
    }

    // Also check package.json or A2A agent card
    if (!hasIdentity) {
      try {
        const pkgPath = path.join(targetDir, 'package.json');
        const pkgContent = await fs.readFile(pkgPath, 'utf-8');
        const pkg = JSON.parse(pkgContent);
        if (pkg.agentCard || pkg.a2a || pkg.keywords?.some((k: string) => k.includes('agent') || k.includes('a2a'))) {
          findings.push({
            checkId: 'AIM-001',
            name: 'No agent identity declaration',
            description: 'Project appears to be an AI agent but has no formal identity declaration. Without identity, the agent cannot be verified by other agents or registries.',
            category: 'identity-spoofing',
            severity: 'medium',
            passed: false,
            message: 'Agent project has no identity declaration file (agent-card.json, agent.json, aim.json)',
            fixable: false,
            file: 'package.json',
            fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
            guidance: 'Without a formal identity declaration, the agent cannot be verified by other agents, registries, or trust frameworks. Creates an Ed25519 key pair with audit logging.',
          });
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for agent DNA/behavioral fingerprint forgery risks
   * Detects integrity issues with agent behavioral profiles
   */
  private async checkAgentDNA(targetDir: string, _autoFix: boolean): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // DNA-001: No behavioral fingerprint
    const dnaFiles = ['agent-dna.json', '.well-known/agent-dna.json', '.agent-dna', 'behavioral-profile.json'];
    const soulFileNames = ['SOUL.md', 'system-prompt.md', '.cursorrules', 'CLAUDE.md'];
    let hasDna = false;
    let hasSoul = false;
    let foundSoulFile = '';

    for (const dnaFile of dnaFiles) {
      try {
        await fs.access(path.join(targetDir, dnaFile));
        hasDna = true;

        const content = await fs.readFile(path.join(targetDir, dnaFile), 'utf-8');
        const config = JSON.parse(content);

        // DNA-002: Unsigned behavioral profile
        // Require an actual VALUE (hash bytes or signature), not a method descriptor.
        // A string like `verificationMethod: "sha256"` describes HOW to hash but
        // contains no hash value an auditor could verify — it does not count.
        const looksLikeHashValue = (v: unknown): boolean => {
          if (typeof v === 'string') {
            // SHA-256 hex = 64 chars, base64 = 43, "sha256:<hex>" = 71. Require ≥ 32.
            return v.length >= 32;
          }
          if (typeof v === 'object' && v !== null) {
            const obj = v as Record<string, unknown>;
            return looksLikeHashValue(obj.value) || looksLikeHashValue(obj.hash) ||
              looksLikeHashValue(obj.signature) || looksLikeHashValue(obj.digest);
          }
          return false;
        };
        const hasHashOrSig =
          looksLikeHashValue(config.signature) ||
          looksLikeHashValue(config.hash) ||
          looksLikeHashValue(config.contentHash) ||
          looksLikeHashValue(config.behavioralProfile?.contentHash) ||
          looksLikeHashValue(config.behavioralProfile?.signature) ||
          looksLikeHashValue(config.integrityPolicy?.contentHash) ||
          looksLikeHashValue(config.integrityPolicy?.signature);
        if (!hasHashOrSig) {
          findings.push({
            checkId: 'DNA-002',
            name: 'Unsigned behavioral profile',
            description: 'Agent DNA/behavioral profile exists but is not signed. An attacker could modify the profile to change agent behavior without detection.',
            category: 'agent-dna',
            severity: 'high',
            passed: false,
            message: `${dnaFile} has no signature or content hash`,
            fixable: false,
            file: dnaFile,
            fix: 'hackmyagent fix-all --with-aim  — signs skills, heartbeats, and agent DNA with AIM keys so tamper detection works on every scan.',
            guidance: 'Unsigned behavioral profiles can be silently modified to change agent behavior. Cryptographic signatures enable tamper detection on every load.',
          });
        }

        // DNA-003: No behavioral drift detection
        // Require a real policy value, not just `driftDetection: true`. A boolean
        // toggle without a threshold or baseline cannot actually detect drift —
        // it asserts an intention without configuring the mechanism.
        const isPolicyObject = (v: unknown): boolean =>
          typeof v === 'object' && v !== null && Object.keys(v as object).length > 0;
        const hasDriftDetection =
          (typeof config.baselineHash === 'string' && config.baselineHash.length >= 32) ||
          typeof config.driftThreshold === 'number' ||
          typeof config.integrityPolicy?.driftThreshold === 'number' ||
          isPolicyObject(config.integrityPolicy?.driftDetection) ||
          isPolicyObject(config.monitoringPolicy) ||
          (config.monitoringEnabled === true && (config.monitoringEndpoint || config.monitoringWebhook));
        if (!hasDriftDetection) {
          findings.push({
            checkId: 'DNA-003',
            name: 'No behavioral drift detection',
            description: 'Agent DNA has no drift detection configured. Gradual behavioral changes would go undetected.',
            category: 'agent-dna',
            severity: 'medium',
            passed: false,
            message: `${dnaFile} has no behavioral drift detection (baselineHash, driftThreshold, monitoring)`,
            fixable: false,
            file: dnaFile,
            fix: 'Enable behavioral drift detection: set baselineHash and driftThreshold for continuous monitoring.',
            guidance: 'Without drift detection, gradual behavioral changes (prompt drift, personality shifts) go unnoticed. A baseline hash detects any deviation from expected behavior.',
          });
        }
      } catch { /* skip */ }
    }

    for (const soulFile of soulFileNames) {
      try {
        await fs.access(path.join(targetDir, soulFile));
        hasSoul = true;
        if (!foundSoulFile) foundSoulFile = soulFile;
      } catch { /* skip */ }
    }

    // If agent has a SOUL/system prompt but no DNA fingerprint
    if (hasSoul && !hasDna) {
      // Check if this is actually an agent project
      try {
        const pkgPath = path.join(targetDir, 'package.json');
        const pkgContent = await fs.readFile(pkgPath, 'utf-8');
        const pkg = JSON.parse(pkgContent);
        if (pkg.agentCard || pkg.a2a || pkg.keywords?.some((k: string) => k.includes('agent'))) {
          findings.push({
            checkId: 'DNA-001',
            name: 'No behavioral fingerprint',
            description: 'Agent has behavioral instructions (SOUL.md/system prompt) but no behavioral fingerprint. Without a fingerprint, behavioral integrity cannot be verified.',
            category: 'agent-dna',
            severity: 'medium',
            passed: false,
            message: 'Agent has behavioral instructions but no DNA fingerprint file',
            fixable: false,
            file: foundSoulFile || 'SOUL.md',
            fix: 'Create agent-dna.json with contentHash of SOUL.md, baselineHash, and signature for integrity verification.',
            guidance: 'A behavioral fingerprint enables continuous integrity verification of agent instructions. Without it, modifications to SOUL.md cannot be detected.',
          });
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * Check for skill-based memory manipulation risks
   */
  private async checkSkillMemory(targetDir: string, _autoFix: boolean): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // SKILL-MEM-001: Skills with memory write access
    // Check SKILL.md for memory manipulation patterns
    try {
      const skillMdPath = path.join(targetDir, 'SKILL.md');
      const content = await fs.readFile(skillMdPath, 'utf-8');
      const lowerContent = content.toLowerCase();

      if ((lowerContent.includes('memory') || lowerContent.includes('context') || lowerContent.includes('state')) &&
          (lowerContent.includes('write') || lowerContent.includes('modify') || lowerContent.includes('update') || lowerContent.includes('set'))) {
        if (!lowerContent.includes('read-only') && !lowerContent.includes('readonly') && !lowerContent.includes('immutable')) {
          findings.push({
            checkId: 'SKILL-MEM-001',
            name: 'Skill with unrestricted memory access',
            description: 'A skill declares memory/context write capabilities without explicit restrictions. A malicious skill could manipulate agent memory to alter future behavior.',
            category: 'skill-memory',
            severity: 'high',
            passed: false,
            message: 'SKILL.md declares memory write access without read-only constraints',
            fixable: false,
            file: 'SKILL.md',
            fix: 'Restrict skill memory access: declare explicit read-only or scoped-write permissions in SKILL.md.',
            guidance: 'Skills with unrestricted memory write access can poison agent context, alter future responses, or plant persistent backdoors that survive restarts.',
          });
        }
      }
    } catch { /* no SKILL.md */ }

    // Check skills directory for memory manipulation patterns
    try {
      const skillsDir = path.join(targetDir, 'skills');
      const dirExists = await fs.access(skillsDir).then(() => true).catch(() => false);
      if (dirExists) {
        const files = await this.walkDirectory(skillsDir, [...JS_FAMILY_EXTENSIONS, '.py', '.md']);
        for (const file of files.slice(0, 30)) {
          try {
            const content = await fs.readFile(file, 'utf-8');
            if ((content.includes('writeMemory') || content.includes('setContext') ||
                 content.includes('updateState') || content.includes('persistMemory')) &&
                !content.includes('readOnly') && !content.includes('read_only')) {
              findings.push({
                checkId: 'SKILL-MEM-001',
                name: 'Skill with unrestricted memory access',
                description: 'Skill file contains memory write operations without read-only guards.',
                category: 'skill-memory',
                severity: 'high',
                passed: false,
                message: 'Skill writes to agent memory without restrictions',
                fixable: false,
                file: path.relative(targetDir, file),
                fix: 'Add read-only guards or scope memory writes to skill-specific namespaces.',
                guidance: 'Unrestricted memory writes from skills can alter agent state across all contexts. Scope writes to skill-specific namespaces to prevent cross-skill interference.',
              });
              break; // One per skill dir
            }
          } catch { /* skip */ }
        }
      }
    } catch { /* skip */ }

    return findings;
  }

  /**
   * Check for Unicode steganography attacks (GlassWorm detection)
   * Detects invisible codepoints, decoder patterns, eval on empty strings,
   * and tag character block presence in source files.
   */
  private async checkUnicodeSteganography(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    // Scan expanded file types beyond JS/TS (configs, docs, and Python are attack surfaces too)
    const stegoExtensions = ['.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx', '.py', '.md', '.txt', '.yaml', '.yml', '.json', '.toml'];
    const sourceFiles = await this.walkDirectory(targetDir, stegoExtensions);

    for (const filePath of sourceFiles) {
      const relativePath = path.relative(targetDir, filePath);
      let rawBuffer: Buffer;
      try {
        rawBuffer = await fs.readFile(filePath);
      } catch {
        continue;
      }

      // Skip files larger than MAX_FILE_SIZE
      if (rawBuffer.length > MAX_FILE_SIZE) continue;

      // UNICODE-STEGO-001: Invisible Codepoint Detection
      // Scan for:
      //   - Variation selectors U+FE00-FE0F (UTF-8: EF B8 80-8F)
      //   - Tag characters U+E0100-E01EF (UTF-8: F3 A0 84 80 - F3 A0 87 AF)
      //   - Zero-width chars: U+200B (E2 80 8B), U+200C (E2 80 8C), U+200D (E2 80 8D)
      //   - Mid-file BOM: U+FEFF (EF BB BF) -- skip offset 0
      //   - Bidi overrides: U+202A-202E (E2 80 AA-AE), U+2066-2069 (E2 81 A6-A9)

      // Skip ML training corpora and datasets entirely. These directories
      // intentionally contain adversarial Unicode (the model learns to
      // detect it); firing stego findings on training data teaches the
      // wrong signal and blocks legitimate ML repos. [CSR-003]+[CDS-023].
      if (isCorpusPath(relativePath)) {
        continue;
      }

      // Skip variation selector checks for documentation files where emoji are
      // decorative, not steganographic. The isEmojiVariationSelector heuristic
      // can't cover all valid emoji bases across Unicode versions, and FE0F in
      // docs is essentially always an emoji presentation selector.
      const isDocFile = /\.(md|txt)$/i.test(relativePath) ||
        /^(README|CHANGELOG|CONTRIBUTING|AGENTS|CLAUDE|LICENSE|AUTHORS|HISTORY)/i.test(path.basename(relativePath));

      let hasVariationSelectors = false;
      let variationSelectorLine = 1;
      let hasTagCharsIn001 = false;
      let tagCharLine001 = 1;
      let hasZeroWidth = false;
      let zeroWidthLine = 1;
      let hasMidFileBom = false;
      let midFileBomLine = 1;
      let hasBidiOverride = false;
      let bidiOverrideLine = 1;

      let currentLine = 1;
      for (let i = 0; i < rawBuffer.length; i++) {
        if (rawBuffer[i] === 0x0A) {
          currentLine++;
          continue;
        }
        // Variation selectors: EF B8 80-8F (U+FE00-FE0F)
        // Skip entirely for doc files (variation selectors in markdown/changelogs
        // are virtually always emoji presentation selectors, not steganography).
        // For source files, check if preceded by a known emoji base character.
        if (
          !isDocFile &&
          rawBuffer[i] === 0xEF &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xB8 &&
          rawBuffer[i + 2] >= 0x80 &&
          rawBuffer[i + 2] <= 0x8F
        ) {
          // Check if this is an emoji presentation selector (FE0F after emoji base)
          if (rawBuffer[i + 2] === 0x8F && isEmojiVariationSelector(rawBuffer, i)) {
            // Legitimate emoji — skip
          } else if (!hasVariationSelectors) {
            hasVariationSelectors = true;
            variationSelectorLine = currentLine;
          }
        }
        // Tag characters in U+E0100-E01EF: F3 A0 84 80 through F3 A0 87 AF
        if (
          rawBuffer[i] === 0xF3 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xA0 &&
          rawBuffer[i + 2] >= 0x84 &&
          rawBuffer[i + 2] <= 0x87
        ) {
          if (!hasTagCharsIn001) {
            hasTagCharsIn001 = true;
            tagCharLine001 = currentLine;
          }
        }
        // Zero-width chars: U+200B/200C/200D = E2 80 8B/8C/8D
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x80 &&
          rawBuffer[i + 2] >= 0x8B &&
          rawBuffer[i + 2] <= 0x8D
        ) {
          if (!hasZeroWidth) {
            hasZeroWidth = true;
            zeroWidthLine = currentLine;
          }
        }
        // Mid-file BOM: U+FEFF = EF BB BF (skip if at offset 0)
        if (
          i > 0 &&
          rawBuffer[i] === 0xEF &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xBB &&
          rawBuffer[i + 2] === 0xBF
        ) {
          if (!hasMidFileBom) {
            hasMidFileBom = true;
            midFileBomLine = currentLine;
          }
        }
        // Bidi overrides: U+202A-202E = E2 80 AA-AE
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x80 &&
          rawBuffer[i + 2] >= 0xAA &&
          rawBuffer[i + 2] <= 0xAE
        ) {
          if (!hasBidiOverride) {
            hasBidiOverride = true;
            bidiOverrideLine = currentLine;
          }
        }
        // Bidi isolates: U+2066-2069 = E2 81 A6-A9
        if (
          rawBuffer[i] === 0xE2 &&
          i + 2 < rawBuffer.length &&
          rawBuffer[i + 1] === 0x81 &&
          rawBuffer[i + 2] >= 0xA6 &&
          rawBuffer[i + 2] <= 0xA9
        ) {
          if (!hasBidiOverride) {
            hasBidiOverride = true;
            bidiOverrideLine = currentLine;
          }
        }
      }

      // Bidi and variation/tag chars are critical; zero-width-only is high
      const hasCriticalInvisible = hasVariationSelectors || hasTagCharsIn001 || hasBidiOverride;
      const hasAnyInvisible = hasCriticalInvisible || hasZeroWidth || hasMidFileBom;

      if (hasAnyInvisible) {
        const detectedTypes: string[] = [];
        if (hasVariationSelectors) detectedTypes.push('variation selectors (U+FE00-FE0F)');
        if (hasTagCharsIn001) detectedTypes.push('tag characters (U+E0100-E01EF)');
        if (hasZeroWidth) detectedTypes.push('zero-width characters (U+200B-200D)');
        if (hasMidFileBom) detectedTypes.push('mid-file BOM (U+FEFF)');
        if (hasBidiOverride) detectedTypes.push('bidi overrides (U+202A-202E, U+2066-2069)');

        // Determine first line hit for reporting
        const firstLine = Math.min(
          ...[
            hasVariationSelectors ? variationSelectorLine : Infinity,
            hasTagCharsIn001 ? tagCharLine001 : Infinity,
            hasZeroWidth ? zeroWidthLine : Infinity,
            hasMidFileBom ? midFileBomLine : Infinity,
            hasBidiOverride ? bidiOverrideLine : Infinity,
          ]
        );

        findings.push({
          checkId: 'UNICODE-STEGO-001',
          name: 'Invisible Unicode Codepoints Detected',
          description: 'Source file contains invisible Unicode codepoints that can hide malicious payloads (GlassWorm attack vector)',
          category: 'unicode-stego',
          severity: hasCriticalInvisible ? 'critical' : 'high',
          passed: false,
          message: `Found ${detectedTypes.join(' and ')} in ${relativePath}`,
          file: relativePath,
          line: firstLine,
          fixable: false,
          fix: 'xxd ' + shellEscape(relativePath) + ' | grep -iE "e280[8-9a-e]|efbb|efb8|f3a0"',
          guidance: 'Invisible Unicode codepoints (zero-width chars, variation selectors, tag characters, bidi overrides) can hide malicious payloads in source code. This is the GlassWorm attack vector. Inspect with a hex editor and remove all non-functional invisible characters.',
        });
      }

      // UNICODE-STEGO-002: GlassWorm Decoder Pattern
      // Detect .codePointAt( combined with hex literals in the variation selector or tag range
      const content = rawBuffer.toString('utf-8');
      const lines = content.split('\n');
      let hasCodePointAt = false;
      let hasHexLiteral = false;
      let codePointAtLine = 0;
      let hexLiteralLine = 0;

      const hexPattern = /0x(?:FE0[0-9A-Fa-f]|fe0[0-9a-f]|E010[0-9A-Fa-f]|e010[0-9a-f]|E01[0-9A-Ea-e][0-9A-Fa-f]|e01[0-9a-e][0-9a-f])/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > MAX_LINE_LENGTH) continue;
        if (!hasCodePointAt && line.includes('.codePointAt(')) {
          hasCodePointAt = true;
          codePointAtLine = i + 1;
        }
        if (!hasHexLiteral && hexPattern.test(line)) {
          hasHexLiteral = true;
          hexLiteralLine = i + 1;
        }
      }

      // This check used to consult a regex over the file PATH
      // (`/analyz|detect|scan|check|inspect|enhanc|stego/i`), which this file's own
      // comment called an attacker-controllable weak signal. Measured consequences:
      // precision 0/7 on real-world code, and our own stego analyzer was held clean
      // only by its filename, so copying it to another name self-flagged. The path is
      // no longer consulted BY THIS CHECK, so no filename can make it skip a file.
      //
      // It does NOT follow that a rename can no longer change a verdict, and an earlier
      // draft of this comment claimed exactly that. The `hasAnyInvisible` corroborator
      // below is UNICODE-STEGO-001's result, and that check is gated on `isDocFile`,
      // which DOES read the path: it skips variation selectors in `.md`/`.txt` and in
      // files whose basename begins README/CHANGELOG/CONTRIBUTING/AGENTS/CLAUDE/LICENSE/
      // AUTHORS/HISTORY. So a decoder corroborated ONLY by an embedded payload is MEDIUM
      // under one of those names and CRITICAL under another. Measured on byte-identical
      // content: `payload-carrier.js` exits 1, `README-carrier.js` exits 0. A decoder
      // corroborated by a recognised execution sink is CRITICAL under every name. That
      // asymmetry predates this change, is disclosed in the release notes, and is not
      // fixed here.
      //
      // Reconstitution — String.fromCodePoint/fromCharCode, the decoder half of
      // GlassWorm — is EVIDENCE ABOUT THE FILE, not a gate on the finding. It was a
      // required conjunct for one commit and that was wrong: a required conjunct on
      // one SPELLING is a rule about that spelling, not about the class. Measured
      // against the previous release, requiring it dropped 10 working decoder
      // spellings to no finding at all — `.map(String.fromCodePoint)`,
      // `Array.from(out, ...)`, an alias, a destructured `{ fromCharCode }`,
      // `String['fromCodePoint']`, `Reflect.apply`, `Buffer.from(out).toString()`,
      // `new TextDecoder().decode()`, a `JSON.parse('"\\uXXXX"')` round trip and an
      // indexed alphabet table — every one of which reconstituted a tag-range payload
      // and passed it to a sink. Each is pinned by a test in unicode-stego.test.ts.
      // The attacker picks the spelling, so the spelling cannot be the gate. What the
      // signal is good for is describing the file accurately, so it selects the
      // wording below and nothing else. Narrowing on semantics rather than spelling
      // needs dataflow, which is #424's AST analyzer, not another regex.
      const hasStringReconstitution = /String\.from(?:CodePoint|CharCode)\s*\(/.test(content);

      // Severity. A decoder pattern is evidence of CAPABILITY, not of malice, so on
      // its own it is a lead to follow rather than a stop-the-line finding. Critical
      // requires corroboration, and both corroborators are read from THIS file so a
      // finding's severity never depends on the order the tree is walked in:
      //   1. an execution sink here, so a decoded string can reach eval/Function;
      //   2. a variation-selector or tag-character payload here — the invisible
      //      classes this decoder shape actually reconstitutes (its hex range is
      //      FE0x / E01xx). A lone zero-width char or a mid-file BOM is NOT such a
      //      payload: a single U+200B is not a decodable string, and one common
      //      benign use is escaping a comment delimiter (a `**/` inside a JSDoc),
      //      so corroborating on it grades a legitimate escape as the attack and
      //      fires hardest on the people doing the right thing (#475). UNICODE-
      //      STEGO-001 still reports the zero-width char on its own (a HIGH lead);
      //      it just does not lift THIS decoder finding to CRITICAL.
      // Neither corroborator holds for a test that builds a payload and asserts a
      // sanitiser escapes it — a correct DEFENCE against this technique.
      const hasExecutionSink =
        /(?:^|[^\w.$])eval\s*\(/.test(content) ||
        /(?:^|[^\w.$])(?:new\s+)?Function\s*\(/.test(content);
      const hasDecodablePayload = hasVariationSelectors || hasTagCharsIn001;
      const corroborated = hasExecutionSink || hasDecodablePayload;

      if (hasCodePointAt && hasHexLiteral) {
        // Report the EARLIER of the two signals. Reporting the first `.codePointAt(`
        // sent readers to the wrong line whenever the range literal that actually
        // discriminates the finding sat above it.
        const reportedLine = Math.min(codePointAtLine, hexLiteralLine);
        const corroboration = hasExecutionSink
          ? 'an execution sink (eval/Function) in the same file'
          : hasDecodablePayload
            ? 'a variation-selector or tag-character payload in the same file (UNICODE-STEGO-001)'
            : null;
        // Say what was actually observed. A file that only READS codepoints must not
        // be described as reconstituting them; that sentence would be false about the
        // file, and a reader who checks it would find the check lying about evidence.
        const act = hasStringReconstitution
          ? 'reconstitutes strings from'
          : 'reads';

        findings.push({
          checkId: 'UNICODE-STEGO-002',
          name: 'GlassWorm Decoder Pattern Detected',
          description: corroboration
            ? `Source file ${act} Unicode variation selector or tag character codepoints AND carries corroborating evidence - this is the decoder half of a GlassWorm attack`
            : `Source file ${act} Unicode variation selector or tag character codepoints. This is the shape of a GlassWorm decoder, but neither corroborator this check recognises is present - no literal eval( or Function( call, and no variation-selector or tag-character payload`,
          category: 'unicode-stego',
          severity: corroborated ? 'critical' : 'medium',
          passed: false,
          message: corroboration
            ? `Found GlassWorm decoder pattern in ${relativePath} (codepoint range literal at line ${hexLiteralLine}, .codePointAt at line ${codePointAtLine}), corroborated by ${corroboration}`
            : `Found GlassWorm decoder shape in ${relativePath} (codepoint range literal at line ${hexLiteralLine}, .codePointAt at line ${codePointAtLine}), uncorroborated`,
          file: relativePath,
          line: reportedLine,
          fixable: false,
          fix: corroboration
            ? `sed -n '${Math.max(1, reportedLine - 5)},${reportedLine + 20}p' ${shellEscape(relativePath)}   # trace this codepoint range to whatever consumes it, then remove the decoder`
            : `sed -n '${Math.max(1, reportedLine - 5)},${reportedLine + 20}p' ${shellEscape(relativePath)}   # confirm this decodes for inspection, not for execution`,
          guidance: corroboration
            ? `The GlassWorm attack hides a payload in invisible Unicode characters and rebuilds it at runtime from their codepoints. This file ${act} those codepoints AND carries corroborating evidence, so treat it as live until traced. Follow the value from the range literal to whatever consumes it.`
            : `This file ${act} codepoints in the variation selector or tag range. Sanitisers, linters, width calculators and tests for this attack all legitimately do the same thing, which is why this is a lead rather than a verdict. What was actually checked, stated narrowly on purpose: no literal eval( or Function( call appears in this file, and no variation-selector or tag-character payload - the invisible classes this shape decodes - is present (a lone zero-width char or a mid-file BOM, which UNICODE-STEGO-001 may still report on its own, does not corroborate this finding). Neither is a statement about the class. A decoded string can reach an executor through vm, child_process, a dynamic import(), a member expression such as globalThis.eval, or the Function constructor reached through a prototype chain, and this check recognises none of those - so read the file rather than trusting this line. Reconstitution likewise has many spellings (an alias, a destructured binding, .map, Buffer.from, TextDecoder), so its absence from the message above is not proof the file does not rebuild a string.`,
        });
      }

      // UNICODE-STEGO-003: Eval on Empty String
      // Find eval() or Function() calls where the string argument has few visible chars but many bytes
      const evalPattern = /(?:eval|Function)\s*\(\s*(['"`])([\s\S]*?)\1\s*\)/g;
      let evalMatch;
      while ((evalMatch = evalPattern.exec(content)) !== null) {
        const matchedStr = evalMatch[2];
        // Count truly visible characters by excluding invisible Unicode ranges:
        // - Control characters (U+0000-001F, U+007F-009F)
        // - Variation selectors (U+FE00-FE0F)
        // - Zero-width characters (U+200B-200F, U+2060, U+FEFF)
        // - Tag characters (U+E0000-E01EF)
        // - Combining marks and other invisible codepoints
        let visibleChars = 0;
        for (const ch of matchedStr) {
          const cp = ch.codePointAt(0)!;
          if (cp <= 0x1F) continue; // C0 controls
          if (cp >= 0x7F && cp <= 0x9F) continue; // C1 controls
          if (cp >= 0x200B && cp <= 0x200F) continue; // zero-width chars
          if (cp === 0x2060 || cp === 0xFEFF) continue; // word joiner, BOM
          if (cp >= 0xFE00 && cp <= 0xFE0F) continue; // variation selectors
          if (cp >= 0xE0000 && cp <= 0xE01EF) continue; // tag characters
          if (cp >= 0xE0100 && cp <= 0xE01EF) continue; // variation selector supplement
          visibleChars++;
        }
        const byteLength = Buffer.byteLength(matchedStr, 'utf-8');

        if (visibleChars < 5 && byteLength > 100) {
          // Find the line number
          const offset = evalMatch.index;
          let evalLine = 1;
          for (let j = 0; j < offset && j < content.length; j++) {
            if (content[j] === '\n') evalLine++;
          }

          findings.push({
            checkId: 'UNICODE-STEGO-003',
            name: 'Eval on String with Hidden Payload',
            description: 'eval() or Function() is called with a string that has very few visible characters but a large byte footprint - indicates invisible Unicode payload',
            category: 'unicode-stego',
            severity: 'critical',
            passed: false,
            message: `Found eval/Function with ${visibleChars} visible chars but ${byteLength} bytes in ${relativePath}`,
            file: relativePath,
            line: evalLine,
            fixable: false,
            fix: 'node -e "const fs=require(\'fs\'); const s=fs.readFileSync(' + JSON.stringify(relativePath) + ',\'utf8\'); console.log([...s].filter(c=>c.codePointAt(0)>0x200).map(c=>c.codePointAt(0).toString(16)))"',
            guidance: 'eval() or Function() called with mostly invisible characters is a strong indicator of a GlassWorm payload. The string contains hidden Unicode characters encoding malicious code. Remove the eval/Function call and audit the file.',
          });
          break; // One finding per file
        }
      }

      // UNICODE-STEGO-004: Tag Character Block Presence
      // Scan for any U+E0000-U+E01EF characters (broader than 001, covers entire tag block)
      // UTF-8 encoding: F3 A0 80 80 through F3 A0 87 AF
      let hasTagBlock = false;
      let tagBlockLine = 1;
      currentLine = 1;

      for (let i = 0; i < rawBuffer.length; i++) {
        if (rawBuffer[i] === 0x0A) {
          currentLine++;
          continue;
        }
        if (
          rawBuffer[i] === 0xF3 &&
          i + 3 < rawBuffer.length &&
          rawBuffer[i + 1] === 0xA0 &&
          rawBuffer[i + 2] >= 0x80 &&
          rawBuffer[i + 2] <= 0x87
        ) {
          hasTagBlock = true;
          tagBlockLine = currentLine;
          break;
        }
      }

      if (hasTagBlock) {
        // Only add UNICODE-STEGO-004 if we did not already flag tag chars in 001
        // (004 is broader - covers U+E0000-U+E01EF, 001 only covers U+E0100-E01EF)
        const already001 = findings.some(
          (f) => f.checkId === 'UNICODE-STEGO-001' && f.file === relativePath
        );
        if (!already001) {
          findings.push({
            checkId: 'UNICODE-STEGO-004',
            name: 'Unicode Tag Character Block Detected',
            description: 'Source file contains characters from the Unicode Tag block (U+E0000-U+E01EF) which have no visible rendering and can be used to hide data',
            category: 'unicode-stego',
            severity: 'high',
            passed: false,
            message: `Found Unicode tag block characters in ${relativePath}`,
            file: relativePath,
            line: tagBlockLine,
            fixable: false,
            fix: 'xxd ' + shellEscape(relativePath) + ' | grep "f3a0"',
            guidance: 'Unicode Tag block characters (U+E0000-U+E01EF) are invisible and have no legitimate use in source code. They can encode hidden data or malicious payloads. Remove all tag block characters found.',
          });
        }
      }

      // UNICODE-STEGO-005: Homoglyph Confusable Detection
      // Detect Cyrillic/Greek characters that look identical to Latin but have different codepoints.
      // These can be used to bypass code review and hide malicious identifiers.
      const homoglyphCodepoints = new Set([
        // Cyrillic uppercase that look like Latin: A, B, C, E, H, K, M, O, P, T, X
        0x0410, 0x0412, 0x0421, 0x0415, 0x041D, 0x041A, 0x041C, 0x041E, 0x0420, 0x0422, 0x0425,
        // Cyrillic lowercase that look like Latin: a, e, o, p, c, x
        0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0445,
        // Fullwidth Latin (U+FF21-FF3A, U+FF41-FF5A) -- spot-check common ones
        0xFF21, 0xFF22, 0xFF41, 0xFF42,
      ]);

      let homoglyphFound = false;
      let homoglyphLine = 1;
      let homoglyphChar = '';
      const contentForHomoglyph = content || rawBuffer.toString('utf-8');
      const homoglyphLines = contentForHomoglyph.split('\n');

      // Track markdown code fences: homoglyphs inside ```...``` blocks in .md files
      // are documentation examples, not executable code — skip them.
      const isMarkdown = relativePath.endsWith('.md') || relativePath.endsWith('.txt');
      let inCodeFence = false;

      for (let lineIdx = 0; lineIdx < homoglyphLines.length; lineIdx++) {
        const line = homoglyphLines[lineIdx];
        if (line.length > MAX_LINE_LENGTH) continue;

        // Track code fence boundaries in markdown files
        if (isMarkdown && line.trimStart().startsWith('```')) {
          inCodeFence = !inCodeFence;
          continue;
        }
        // Skip lines inside markdown code fences (documentation examples)
        if (isMarkdown && inCodeFence) continue;

        // Skip comment lines
        const trimmed = line.trimStart();
        if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) continue;

        const chars = [...line];
        for (let ci = 0; ci < chars.length; ci++) {
          const cp = chars[ci].codePointAt(0)!;
          if (homoglyphCodepoints.has(cp)) {
            // Check if this Cyrillic char is in a Cyrillic text block (i18n)
            // vs mixed into a Latin word (homoglyph attack).
            // Look at neighboring characters: if surrounded by other Cyrillic
            // or non-Latin chars, it's legitimate i18n text.
            if (isCyrillicInCyrillicContext(chars, ci)) {
              continue; // Legitimate i18n — skip
            }
            homoglyphFound = true;
            homoglyphLine = lineIdx + 1;
            homoglyphChar = `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
            break;
          }
        }
        if (homoglyphFound) break;
      }

      if (homoglyphFound) {
        findings.push({
          checkId: 'UNICODE-STEGO-005',
          name: 'Homoglyph Confusable Characters Detected',
          description: 'Source file contains characters from non-Latin scripts (Cyrillic, Greek, Fullwidth) that visually resemble Latin letters. These can be used to create identifiers that look identical in code review but behave differently at runtime.',
          category: 'unicode-stego',
          severity: 'high',
          passed: false,
          message: `Found homoglyph confusable character (${homoglyphChar}) in ${relativePath} at line ${homoglyphLine}`,
          file: relativePath,
          line: homoglyphLine,
          fixable: false,
          fix: 'node -e "const fs=require(\'fs\'); [...fs.readFileSync(' + JSON.stringify(relativePath) + ',\'utf8\')].forEach((c,i)=>{const cp=c.codePointAt(0); if(cp>0x7F && cp<0xFFFF) console.log(i, cp.toString(16), c)})"',
          guidance: 'Homoglyph confusables (Cyrillic/Greek/Fullwidth characters that look like Latin letters) can create variable names that appear identical in code review but reference different values at runtime. Replace with ASCII equivalents.',
        });
      }
    }

    return findings;
  }

  /**
   * NemoClaw static analysis checks (NEMO-001 through NEMO-010)
   * Detects vulnerability patterns in any codebase: unsafe installs, missing
   * digest verification, injection vectors, secret leaks, deserialization, and
   * egress policy gaps.
   */
  private async checkNemoClawPatterns(
    targetDir: string,
    _shouldFix: boolean,
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Collect source files by extension (max depth 5, skips node_modules/.git/dist/build)
    const shFiles = await this.walkDirectory(targetDir, ['.sh'], 0, 5);
    const tsJsFiles = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 5);
    const pyFiles = await this.walkDirectory(targetDir, ['.py'], 0, 5);
    const yamlFiles = await this.walkDirectory(targetDir, ['.yaml', '.yml'], 0, 5);

    // Cap file counts to avoid scanning enormous repos
    const maxFiles = 200;
    const cappedSh = shFiles.slice(0, maxFiles);
    const cappedTsJs = tsJsFiles.slice(0, maxFiles);
    const cappedPy = pyFiles.slice(0, maxFiles);
    const cappedYaml = yamlFiles.slice(0, maxFiles);

    // A cap that fires means a clean NEMO result covers only the files that
    // were reached, not the tree. Reported so the category prints `partial`
    // rather than clear — the number was a cap, and a cap presented as a
    // measurement is what made `200 files analyzed` read as completeness.
    const nemoDropped =
      Math.max(0, shFiles.length - cappedSh.length) +
      Math.max(0, tsJsFiles.length - cappedTsJs.length) +
      Math.max(0, pyFiles.length - cappedPy.length) +
      Math.max(0, yamlFiles.length - cappedYaml.length);
    if (nemoDropped > 0) {
      this.coverage.truncate({
        layer: 'nemo-source',
        cap: maxFiles,
        prefixes: ['NEMO'],
        reason: `capped at ${maxFiles} files per extension — ${nemoDropped} source file${nemoDropped === 1 ? '' : 's'} not read`,
      });
    }

    // ---------- NEMO-001: Curl-pipe install without checksum ----------
    let nemo001Found = false;
    for (const file of cappedSh) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/curl.*\|\s*(ba)?sh/i.test(line) || /curl.*\|\s*sudo/i.test(line)) {
            // Check surrounding 20 lines for checksum verification
            const windowStart = Math.max(0, i - 10);
            const windowEnd = Math.min(lines.length, i + 11);
            const window = lines.slice(windowStart, windowEnd).join('\n').toLowerCase();
            if (!window.includes('sha256') && !window.includes('checksum') && !window.includes('gpg --verify')) {
              nemo001Found = true;
              findings.push({
                checkId: 'NEMO-001',
                name: 'Curl-pipe install without checksum',
                description: 'A shell script pipes curl output directly into a shell interpreter without verifying a checksum or GPG signature. An attacker who compromises the remote host can inject arbitrary code.',
                category: 'nemo-install',
                severity: 'critical',
                passed: false,
                message: `Curl-pipe install without integrity check at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Remove the curl-pipe pattern. Download the script to a file first, verify its SHA256 checksum, then execute. Run hackmyagent secure . to reverify after fixing.',
                guidance: 'Piping curl directly to sh executes whatever the remote server returns. A compromised or MITM-ed server can inject arbitrary code. Always download, verify, then execute.',
              });
            }
          }
        }
      } catch { /* skip unreadable */ }
    }
    if (!nemo001Found && cappedSh.length > 0) {
      findings.push({
        checkId: 'NEMO-001',
        name: 'Curl-pipe install without checksum',
        description: 'No curl-pipe-to-shell patterns found without checksum verification.',
        category: 'nemo-install',
        severity: 'critical',
        passed: true,
        message: 'No unsafe curl-pipe installs detected',
        fixable: false,
        guidance: 'Piping curl directly to sh executes whatever the remote server returns. A compromised or MITM-ed server can inject arbitrary code.',
      });
    }

    // ---------- NEMO-002: Blueprint/artifact digest verification gap ----------
    let nemo002Found = false;
    // Check YAML files for empty digest fields
    for (const file of cappedYaml) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/digest:\s*["']?\s*["']?\s*$/.test(line) || /digest:\s*["']{2}/.test(line)) {
            nemo002Found = true;
            findings.push({
              checkId: 'NEMO-002',
              name: 'Empty digest field in blueprint/artifact',
              description: 'A YAML manifest declares a digest field with an empty value. Artifacts without digests cannot be verified for integrity, enabling supply-chain injection.',
              category: 'nemo-integrity',
              severity: 'critical',
              passed: false,
              message: `Empty digest field at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'sha256sum <artifact>',
              guidance: 'Empty digest fields bypass integrity verification entirely. Require non-empty digests and fail builds when they are missing, so tampered artifacts cannot pass.',
            });
          }
        }
      } catch { /* skip */ }
    }
    // Check TS/JS files for digest skip logic
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/if\s*\(\s*!?.*digest\s*&&/.test(line) || /if\s*\(\s*!.*digest\s*\)/.test(line)) {
            nemo002Found = true;
            findings.push({
              checkId: 'NEMO-002',
              name: 'Digest verification skipped on falsy value',
              description: 'Code skips digest verification when the digest field is falsy. An attacker who removes the digest from a manifest bypasses integrity checks entirely.',
              category: 'nemo-integrity',
              severity: 'critical',
              passed: false,
              message: `Digest verification skipped when falsy at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Require non-empty digest; fail verification if digest is missing instead of skipping the check.',
              guidance: 'Skipping digest verification when the value is falsy means an attacker can remove the digest field to bypass integrity checks. Treat missing digest as a hard failure.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo002Found && (cappedYaml.length > 0 || cappedTsJs.length > 0)) {
      findings.push({
        checkId: 'NEMO-002',
        name: 'Blueprint/artifact digest verification gap',
        description: 'No empty digest fields or digest-skip logic found.',
        category: 'nemo-integrity',
        severity: 'critical',
        passed: true,
        message: 'No digest verification gaps detected',
        fixable: false,
        guidance: 'Empty or missing digest fields bypass integrity verification, allowing tampered artifacts to pass through the supply chain unchecked.',
      });
    }

    // ---------- NEMO-003: Hot-reload policy paths reachable from user input ----------
    let nemo003Found = false;
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/policy.*reload|reload.*policy|hot.*reload/i.test(line)) {
            // Check surrounding 10 lines for user input references
            const windowStart = Math.max(0, i - 5);
            const windowEnd = Math.min(lines.length, i + 6);
            const window = lines.slice(windowStart, windowEnd).join('\n');
            if (/req\.|request\.|input\.|user\./i.test(window)) {
              nemo003Found = true;
              findings.push({
                checkId: 'NEMO-003',
                name: 'Hot-reload policy path reachable from user input',
                description: 'A policy reload mechanism is within code proximity of user input handling. An attacker could trigger policy changes through crafted requests.',
                category: 'nemo-policy',
                severity: 'high',
                passed: false,
                message: `Policy reload near user input handling at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Gate policy reload behind operator authentication, not agent output or user requests.',
                guidance: 'User-reachable policy reload paths allow attackers to modify security policies via crafted requests. Only operators (authenticated admins) should trigger policy changes.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo003Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-003',
        name: 'Hot-reload policy paths reachable from user input',
        description: 'No policy reload paths reachable from user input found.',
        category: 'nemo-policy',
        severity: 'high',
        passed: true,
        message: 'No unsafe policy reload paths detected',
        fixable: false,
        guidance: 'User-reachable policy reload paths allow attackers to modify security policies via crafted requests, potentially disabling protections at runtime.',
      });
    }

    // ---------- NEMO-004: API key passed as CLI argument ----------
    let nemo004Found = false;
    const nemo004Files = [...cappedTsJs, ...cappedPy];
    for (const file of nemo004Files) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (
            /--credential.*\$\{.*key/i.test(line) ||
            /--api-key.*\$\{/i.test(line) ||
            /--token.*\$\{/i.test(line) ||
            /execSync.*--credential/i.test(line) ||
            /spawn.*--credential/i.test(line) ||
            /subprocess.*--credential/i.test(line)
          ) {
            nemo004Found = true;
            findings.push({
              checkId: 'NEMO-004',
              name: 'API key passed as CLI argument',
              description: 'Credentials are passed as command-line arguments to a subprocess. CLI arguments are visible in process listings (ps aux) and shell history.',
              category: 'nemo-secrets',
              severity: 'high',
              passed: false,
              message: `Credential passed as CLI argument at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Pass credentials via environment variables or stdin, not command-line arguments.',
              guidance: 'CLI arguments are visible in process listings (ps aux), shell history, and log files. Environment variables and stdin are not exposed to other processes.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo004Found && nemo004Files.length > 0) {
      findings.push({
        checkId: 'NEMO-004',
        name: 'API key passed as CLI argument',
        description: 'No credentials passed as CLI arguments detected.',
        category: 'nemo-secrets',
        severity: 'high',
        passed: true,
        message: 'No CLI credential exposure detected',
        fixable: false,
        guidance: 'CLI arguments are visible in process listings (ps aux), shell history, and log files. Environment variables and stdin keep credentials out of these surfaces.',
      });
    }

    // ---------- NEMO-005: exec() with user-controlled string interpolation ----------
    let nemo005Found = false;
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Match exec( or execSync( with template literal containing user-controlled vars
          // Exclude execFile (safe) patterns
          if (
            /\bexec(Sync)?\s*\(/.test(line) &&
            !/\bexecFile/.test(line) &&
            /`[^`]*\$\{[^}]*(name|Name|id|Id|input|arg|param|flag|option)/i.test(line)
          ) {
            nemo005Found = true;
            findings.push({
              checkId: 'NEMO-005',
              name: 'exec() with user-controlled string interpolation',
              description: 'exec() or execSync() is called with a template literal containing user-controlled variables. This enables command injection.',
              category: 'nemo-injection',
              severity: 'critical',
              passed: false,
              message: `exec() with user-controlled interpolation at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use execFile() or spawn() with array arguments instead of exec() with string interpolation.',
              guidance: 'exec() passes the entire string to /bin/sh, which interprets shell metacharacters. execFile() and spawn() with arrays bypass the shell entirely, preventing injection.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo005Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-005',
        name: 'exec() with user-controlled string interpolation',
        description: 'No exec() calls with user-controlled string interpolation found.',
        category: 'nemo-injection',
        severity: 'critical',
        passed: true,
        message: 'No command injection via exec() detected',
        fixable: false,
        guidance: 'exec() passes strings to /bin/sh, which interprets shell metacharacters. User-controlled interpolation in exec() enables arbitrary command execution.',
      });
    }

    // ---------- NEMO-006: Predictable /tmp paths without mktemp ----------
    let nemo006Found = false;
    for (const file of cappedSh) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Skip lines that ARE mktemp commands
          if (/mktemp/.test(line)) continue;
          // Match hardcoded /tmp/ writes
          if (
            /\/tmp\//.test(line) &&
            (/>/.test(line) || />>/.test(line) || /-o\s+\/tmp\//.test(line) || /install.*\/tmp\//.test(line))
          ) {
            nemo006Found = true;
            findings.push({
              checkId: 'NEMO-006',
              name: 'Predictable /tmp path without mktemp',
              description: 'A shell script writes to a hardcoded /tmp path instead of using mktemp. Predictable temp file names enable symlink attacks (CWE-377).',
              category: 'nemo-filesystem',
              severity: 'high',
              passed: false,
              message: `Hardcoded /tmp path at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'TMPDIR=$(mktemp -d) && trap "rm -rf $TMPDIR" EXIT',
              guidance: 'Hardcoded /tmp paths are predictable and enable symlink attacks (CWE-377). An attacker can pre-create a symlink at the expected path to redirect writes to sensitive files.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo006Found && cappedSh.length > 0) {
      findings.push({
        checkId: 'NEMO-006',
        name: 'Predictable /tmp paths without mktemp',
        description: 'No hardcoded /tmp paths found in shell scripts.',
        category: 'nemo-filesystem',
        severity: 'high',
        passed: true,
        message: 'No predictable temp file paths detected',
        fixable: false,
        guidance: 'Hardcoded /tmp paths are predictable and enable symlink attacks (CWE-377). An attacker can pre-create a symlink to redirect writes to sensitive files.',
      });
    }

    // ---------- NEMO-007: Full process.env passthrough to subprocess ----------
    let nemo007Found = false;
    for (const file of cappedTsJs) {
      const relForTest = path.relative(targetDir, file);
      // Test files deliberately spread process.env into subprocess setup to
      // mirror a real execution environment. This is fixture behavior, not
      // a leak. [CSR-004].
      if (isTestPath(relForTest)) continue;
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/env:\s*\{[^}]*\.\.\.process\.env/.test(line)) {
            nemo007Found = true;
            findings.push({
              checkId: 'NEMO-007',
              name: 'Full process.env passthrough to subprocess',
              description: 'process.env is spread into subprocess options, leaking all environment variables (including secrets) to child processes.',
              category: 'nemo-secrets',
              severity: 'high',
              passed: false,
              message: `Full process.env spread into subprocess at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'env: { PATH: process.env.PATH, NODE_ENV: process.env.NODE_ENV }',
              guidance: 'Spreading process.env leaks all environment variables (including API keys, tokens, database URLs) to child processes. Use an explicit allowlist of only the variables the child needs.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo007Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-007',
        name: 'Full process.env passthrough to subprocess',
        description: 'No full process.env passthrough to subprocesses found.',
        category: 'nemo-secrets',
        severity: 'high',
        passed: true,
        message: 'No process.env leakage to subprocesses detected',
        fixable: false,
        guidance: 'Spreading process.env leaks all environment variables (including API keys and tokens) to child processes. Use an explicit allowlist of only needed variables.',
      });
    }

    // ---------- NEMO-008: TOCTOU race between verify and apply ----------
    let nemo008Found = false;
    // Heuristic: look for verify/validate in one file AND exec/spawn in the same directory tree
    const dirVerifyMap = new Map<string, { verifyFile: string; verifyLine: number }>();
    const dirExecMap = new Map<string, { execFile: string; execLine: number }>();
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const dir = path.dirname(file);
        for (let i = 0; i < lines.length; i++) {
          if (/verify.*digest|validate.*hash|check.*integrity/i.test(lines[i])) {
            if (!dirVerifyMap.has(dir)) {
              dirVerifyMap.set(dir, { verifyFile: file, verifyLine: i + 1 });
            }
          }
          if (/\bspawn\s*\(|\bexec\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/.test(lines[i])) {
            if (!dirExecMap.has(dir)) {
              dirExecMap.set(dir, { execFile: file, execLine: i + 1 });
            }
          }
        }
      } catch { /* skip */ }
    }
    for (const [dir, verify] of dirVerifyMap) {
      const exec = dirExecMap.get(dir);
      if (exec && verify.verifyFile !== exec.execFile) {
        nemo008Found = true;
        findings.push({
          checkId: 'NEMO-008',
          name: 'TOCTOU race between verify and apply',
          description: 'Integrity verification and execution happen in separate files, creating a time-of-check-time-of-use window where the artifact can be swapped between verification and use.',
          category: 'nemo-integrity',
          severity: 'high',
          passed: false,
          message: `Verify in ${path.relative(targetDir, verify.verifyFile)}:${verify.verifyLine}, exec in ${path.relative(targetDir, exec.execFile)}:${exec.execLine}`,
          fixable: false,
          file: path.relative(targetDir, verify.verifyFile),
          line: verify.verifyLine,
          fix: 'Copy artifact to temp dir, verify the copy, execute from the copy (atomic verify-then-execute in the same function).',
          guidance: 'When verify and execute are in separate files, an attacker can swap the artifact between verification and use (TOCTOU). Atomic verify-then-execute eliminates this race window.',
        });
      }
    }
    if (!nemo008Found && cappedTsJs.length > 0) {
      findings.push({
        checkId: 'NEMO-008',
        name: 'TOCTOU race between verify and apply',
        description: 'No verify/apply TOCTOU patterns detected.',
        category: 'nemo-integrity',
        severity: 'high',
        passed: true,
        message: 'No TOCTOU race conditions detected',
        fixable: false,
        guidance: 'When verify and execute are separate steps, an attacker can swap the artifact between verification and use. Atomic verify-then-execute eliminates this race window.',
      });
    }

    // ---------- NEMO-009: Unsafe deserialization of untrusted data ----------
    let nemo009Found = false;
    // Python files: pickle.load, yaml.load without SafeLoader, eval(), exec()
    for (const file of cappedPy) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          if (/pickle\.load/i.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: pickle.load',
              description: 'pickle.load() deserializes arbitrary Python objects, enabling remote code execution if the data source is untrusted.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `pickle.load() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use json.load() or a restricted deserializer instead of pickle for untrusted data.',
              guidance: 'pickle.load() can execute arbitrary Python code during deserialization. A crafted pickle payload achieves full remote code execution.',
            });
          }
          if (/yaml\.load\s*\(/.test(line) && !/Loader\s*=\s*SafeLoader/.test(line) && !/safe_load/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: yaml.load without SafeLoader',
              description: 'yaml.load() without SafeLoader can execute arbitrary Python code embedded in YAML documents.',
              category: 'nemo-deserialization',
              severity: 'high',
              passed: false,
              message: `yaml.load() without SafeLoader at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
              guidance: 'yaml.load() without SafeLoader can construct arbitrary Python objects, including those that execute code. SafeLoader restricts to basic data types.',
            });
          }
          if (/(?<!\.)\beval\s*\(/.test(line) || /(?<!\.)\bexec\s*\(/.test(line)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: eval/exec in Python',
              description: 'eval() or exec() executes arbitrary code. If the input originates from untrusted sources, this enables code injection.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `eval()/exec() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Replace eval/exec with ast.literal_eval() for data parsing, or use a safe DSL.',
              guidance: 'eval() and exec() execute arbitrary code. If input originates from untrusted sources (user input, network, files), this is a direct code injection vector.',
            });
          }
        }
      } catch { /* skip */ }
    }
    // TS/JS files: eval(), new Function(), JSON5.parse.
    // Per-match string-literal/comment gating below is the FP guard.
    // We do NOT wholesale-skip `.test.ts` files: an attacker-planted
    // `evil.test.ts` would otherwise silence NEMO-009 across the whole
    // file. Real eval() inside test code (not inside a string literal)
    // still fires and is treated as the security smell it is.
    for (const file of cappedTsJs) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // For each pattern, locate the match index and require that the
          // match site is real code — not a string literal or comment.
          // `screenInput('eval(atob("malicious"))', 'piped')` puts the
          // eval( token inside a string passed to a screener; suppress.
          const bareEval = /(?<!\.)\beval\s*\(/.exec(line);
          if (bareEval && !isMatchInsideStringLiteral(line, bareEval.index)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: eval()',
              description: 'eval() executes arbitrary JavaScript code. If the input comes from untrusted sources, this enables code injection.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `eval() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'eval() executes arbitrary JavaScript. If the string comes from user input, network data, or files, an attacker can inject any code.',
            });
          }
          // Indirect eval: globalThis.eval(x), window.eval(x), self.eval(x), (0,eval)(x).
          // These all invoke the global eval (not a user-defined `eval` method)
          // and bypass the negative-lookbehind guard above. Detected separately
          // so the bare-eval finding above can stay narrow against method-call FPs.
          const indirectEval =
            /\b(?:globalThis|window|self|frames|top|parent)\s*\.\s*eval\s*\(/.exec(line) ??
            /\(\s*0\s*,\s*eval\s*\)\s*\(/.exec(line);
          if (indirectEval && !isMatchInsideStringLiteral(line, indirectEval.index)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: indirect eval()',
              description: 'Indirect eval invocations (globalThis.eval, (0,eval)(...), window.eval) call the global eval and execute arbitrary JavaScript.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `indirect eval() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'Indirect eval forms (globalThis.eval, (0,eval)) are commonly used to access the global scope; they execute arbitrary code with the same risks as bare eval().',
            });
          }
          const newFunction = /new\s+Function\s*\(/.exec(line);
          if (newFunction && !isMatchInsideStringLiteral(line, newFunction.index)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: new Function()',
              description: 'new Function() creates executable code from strings, equivalent to eval() for code injection risks.',
              category: 'nemo-deserialization',
              severity: 'critical',
              passed: false,
              message: `new Function() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() for data, or a sandboxed evaluator for expressions.',
              guidance: 'new Function() is equivalent to eval() -- it creates executable code from strings. If the string source is untrusted, this enables arbitrary code execution.',
            });
          }
          const json5Parse = /JSON5\.parse/.exec(line);
          if (json5Parse && !isMatchInsideStringLiteral(line, json5Parse.index)) {
            nemo009Found = true;
            findings.push({
              checkId: 'NEMO-009',
              name: 'Unsafe deserialization: JSON5.parse',
              description: 'JSON5.parse() is more lenient than JSON.parse(), accepting comments, trailing commas, and unquoted keys. This expanded surface can introduce parsing ambiguities.',
              category: 'nemo-deserialization',
              severity: 'high',
              passed: false,
              message: `JSON5.parse() at line ${i + 1}`,
              fixable: false,
              file: path.relative(targetDir, file),
              line: i + 1,
              fix: 'Use JSON.parse() instead of JSON5.parse() for untrusted data.',
              guidance: 'JSON5 accepts comments, trailing commas, and unquoted keys, expanding the parsing surface. For untrusted input, strict JSON.parse() reduces ambiguity and attack surface.',
            });
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo009Found && (cappedPy.length > 0 || cappedTsJs.length > 0)) {
      findings.push({
        checkId: 'NEMO-009',
        name: 'Unsafe deserialization of untrusted data',
        description: 'No unsafe deserialization patterns detected.',
        category: 'nemo-deserialization',
        severity: 'critical',
        passed: true,
        message: 'No unsafe deserialization detected',
        fixable: false,
        guidance: 'Unsafe deserialization (pickle, eval, yaml.load) can execute arbitrary code during data parsing. A crafted payload achieves full remote code execution.',
      });
    }

    // ---------- NEMO-010: Network egress policy allows data exfiltration ----------
    let nemo010Found = false;
    const egressEndpoints = [
      'api.telegram.org',
      'discord.com/api',
      'hooks.slack.com',
      'webhook.site',
      'requestbin',
    ];
    for (const file of cappedYaml) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].toLowerCase();
          for (const endpoint of egressEndpoints) {
            if (line.includes(endpoint.toLowerCase())) {
              nemo010Found = true;
              findings.push({
                checkId: 'NEMO-010',
                name: 'Messaging API in egress policy',
                description: `Sandbox policy pre-allows access to ${endpoint}. Agents can exfiltrate data via messaging APIs without explicit operator approval.`,
                category: 'nemo-egress',
                severity: 'high',
                passed: false,
                message: `Messaging endpoint "${endpoint}" in egress policy at line ${i + 1}`,
                fixable: false,
                file: path.relative(targetDir, file),
                line: i + 1,
                fix: 'Remove messaging APIs from base sandbox policy; require explicit operator opt-in per deployment.',
                guidance: 'Pre-allowed messaging APIs (Telegram, Discord, Slack, webhook.site) enable agents to exfiltrate data without user approval. Require explicit operator opt-in per deployment.',
              });
            }
          }
        }
      } catch { /* skip */ }
    }
    if (!nemo010Found && cappedYaml.length > 0) {
      findings.push({
        checkId: 'NEMO-010',
        name: 'Network egress policy allows data exfiltration',
        description: 'No messaging API endpoints found in egress policies.',
        category: 'nemo-egress',
        severity: 'high',
        passed: true,
        message: 'No exfiltration-prone egress endpoints detected',
        fixable: false,
        guidance: 'Pre-allowed messaging APIs (Telegram, Discord, Slack) enable agents to exfiltrate data without user approval. Require explicit operator opt-in per deployment.',
      });
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════
  // AI Infrastructure Exposure Checks (Research Gap Coverage)
  // These checks detect the root causes that lead to internet-exposed
  // AI services found by Shodan sweeps in the OpenA2A research program.
  // ═══════════════════════════════════════════════════════════════════

  /**
   * LLM-001 to LLM-004: Exposed LLM inference endpoints
   * Detects Ollama, vLLM, LocalAI, text-generation-webui configs bound
   * to public interfaces or missing authentication.
   */
  private async checkLLMExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Patterns for LLM server configs that indicate exposure risk
    const llmConfigFiles = [
      { name: 'docker-compose.yml', altNames: ['docker-compose.yaml', 'compose.yml', 'compose.yaml'] },
      { name: 'Dockerfile', altNames: [] },
      { name: '.env', altNames: ['.env.local', '.env.production'] },
      { name: 'config.json', altNames: ['config.yaml', 'config.yml'] },
      { name: 'package.json', altNames: [] },
    ];

    const LLM_EXPOSURE_PATTERNS = [
      { id: 'LLM-001', name: 'Ollama Bound to Public Interface', service: 'Ollama',
        pattern: /OLLAMA_HOST\s*[=:]\s*["']?0\.0\.0\.0/i,
        fixPattern: /(OLLAMA_HOST\s*[=:]\s*["']?)0\.0\.0\.0/i,
        fixReplacement: '$1127.0.0.1',
        severity: 'critical' as Severity,
        description: 'Ollama server configured to listen on all interfaces. Our research found 294K+ exposed AI services on the internet — many are Ollama instances.',
        fix: 'Set OLLAMA_HOST=127.0.0.1 to restrict to localhost. If remote access is needed, use a reverse proxy with authentication.',
        guidance: 'Our research found 294K+ exposed AI services on the internet. Public Ollama instances allow anyone to run inference, steal models, or use your GPU resources.' },
      { id: 'LLM-001', name: 'Ollama Port Exposed', service: 'Ollama',
        pattern: /^(?!.*127\.0\.0\.1).*["']?11434["']?\s*:\s*["']?11434["']?/,
        fixPattern: /(["']?)11434(["']?\s*:\s*["']?11434["']?)/,
        fixReplacement: '$1127.0.0.1:11434$2',
        severity: 'high' as Severity,
        description: 'Ollama default port (11434) mapped in container config. Without bind restrictions, this exposes the inference API to the network.',
        fix: 'Map to localhost only: "127.0.0.1:11434:11434" instead of "11434:11434".',
        guidance: 'Docker port mappings without host binding expose the port on all interfaces. Prefix with 127.0.0.1: to restrict to localhost only.' },
      { id: 'LLM-002', name: 'vLLM/LocalAI Public Binding', service: 'vLLM/LocalAI',
        pattern: /--host\s+0\.0\.0\.0|host:\s*["']?0\.0\.0\.0/i,
        fixPattern: /(--host\s+|host:\s*["']?)0\.0\.0\.0/i,
        fixReplacement: '$1127.0.0.1',
        severity: 'critical' as Severity,
        description: 'LLM inference server configured to bind to all interfaces.',
        fix: 'Use --host 127.0.0.1 or bind to localhost. Use a reverse proxy with auth for remote access.',
        guidance: 'vLLM and LocalAI bound to 0.0.0.0 expose the inference API to all network interfaces. Anyone on the network can query models or abuse GPU resources.' },
      { id: 'LLM-003', name: 'Text Generation WebUI Exposed', service: 'text-generation-webui',
        pattern: /--listen\s|--share\s|GRADIO_SERVER_NAME\s*=\s*["']?0\.0\.0\.0/i,
        fixPattern: /\s*--listen\s?|\s*--share\s?|(GRADIO_SERVER_NAME\s*=\s*["']?)0\.0\.0\.0/gi,
        fixReplacement: '$1127.0.0.1',
        severity: 'high' as Severity,
        description: 'Text generation UI configured for public access with --listen or --share flag.',
        fix: 'Remove --listen and --share flags. Access via localhost or SSH tunnel.',
        guidance: '--listen binds to all interfaces and --share creates a public Gradio URL. Both expose the text generation UI to the internet without authentication.' },
      { id: 'LLM-004', name: 'OpenAI-Compatible API No Auth', service: 'OpenAI-compatible',
        pattern: /\/v1\/chat\/completions|\/v1\/completions|\/v1\/models/,
        severity: 'medium' as Severity,
        description: 'Project exposes OpenAI-compatible API endpoints. Verify authentication is enforced.',
        fix: 'Ensure API key or token authentication is required for all inference endpoints.',
        guidance: 'OpenAI-compatible API endpoints without authentication allow anyone to query your models, consume compute resources, and potentially extract training data.' },
    ];

    for (const configDef of llmConfigFiles) {
      const filesToCheck = [configDef.name, ...configDef.altNames];
      for (const filename of filesToCheck) {
        const filePath = path.join(targetDir, filename);
        try {
          let content = await fs.readFile(filePath, 'utf-8');
          if (content.length > 10 * 1024 * 1024) continue; // Skip files > 10MB
          const lines = content.split('\n');

          for (const check of LLM_EXPOSURE_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
              if (check.pattern.test(lines[i])) {
                let fixed = false;
                if (autoFix && check.fixPattern && check.fixReplacement) {
                  const original = lines[i];
                  lines[i] = lines[i].replace(check.fixPattern, check.fixReplacement);
                  if (lines[i] !== original) {
                    const llmContent = lines.join('\n');
                    fixed = await this.applyFixWrite(filePath, llmContent);
                    if (fixed) content = llmContent;
                  }
                }

                findings.push({
                  checkId: check.id,
                  name: check.name,
                  description: check.description,
                  category: 'llm-exposure',
                  severity: check.severity,
                  passed: fixed,
                  message: `${check.service} exposure detected in ${filename}`,
                  file: filename,
                  line: i + 1,
                  fixable: !!check.fixPattern,
                  fixed,
                  fix: check.fix,
                  guidance: (check as Record<string, unknown>).guidance as string | undefined,
                });
                break; // One finding per pattern per file
              }
            }
          }
        } catch {
          // File doesn't exist, skip
        }
      }
    }

    return findings;
  }

  /**
   * AITOOL-001 to AITOOL-004: Exposed AI development tooling
   * Detects Jupyter, Gradio, Streamlit, MLflow, LangServe configs
   * that are publicly accessible.
   */
  private async checkAIToolExposure(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Fix transforms for AI tool patterns
    const AI_TOOL_FIXES: Record<string, Array<{ match: RegExp; replace: string }>> = {
      'AITOOL-001': [
        { match: /(NotebookApp\.token\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(NotebookApp\.password\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(ServerApp\.token\s*=\s*)['"]{2}/, replace: `$1'${crypto.randomBytes(32).toString('hex')}'` },
        { match: /(--ip\s*=?\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
        { match: /--NotebookApp\.token=['"]?\s/, replace: `--NotebookApp.token=${crypto.randomBytes(32).toString('hex')} ` },
      ],
      'AITOOL-002': [
        { match: /(share\s*=\s*)True/, replace: '$1False' },
        { match: /(GRADIO_SERVER_NAME\s*=\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
        { match: /(server\.address\s*=\s*["']?)0\.0\.0\.0/, replace: '$1127.0.0.1' },
      ],
      'AITOOL-003': [
        { match: /(--host\s+)0\.0\.0\.0/i, replace: '$1127.0.0.1' },
      ],
    };

    const AI_TOOL_PATTERNS: Array<{
      id: string; name: string; severity: Severity; description: string; fix: string;
      guidance: string; filePatterns: string[]; contentPatterns: RegExp[];
    }> = [
      {
        id: 'AITOOL-001', name: 'Jupyter Notebook Publicly Accessible',
        severity: 'critical',
        description: 'Jupyter notebook server configured without authentication or bound to public interface. Our research found exposed Jupyter instances with full code execution on the internet.',
        fix: 'Set c.NotebookApp.token or c.NotebookApp.password. Bind to 127.0.0.1. Never use --NotebookApp.token=\'\' in production.',
        guidance: 'Jupyter notebooks allow arbitrary code execution. A publicly accessible instance with no auth gives attackers full shell access on the host machine.',
        filePatterns: ['jupyter_notebook_config.py', 'jupyter_server_config.py', 'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile'],
        contentPatterns: [
          /NotebookApp\.token\s*=\s*['"]{2}/,          // Empty token
          /NotebookApp\.password\s*=\s*['"]{2}/,        // Empty password
          /--NotebookApp\.token=['"]{0,2}\s/,            // CLI empty token
          /--ip\s*=?\s*["']?0\.0\.0\.0/,                 // Bind all interfaces
          /ServerApp\.token\s*=\s*['"]{2}/,              // Jupyter Server empty token
        ],
      },
      {
        id: 'AITOOL-002', name: 'Gradio/Streamlit Public Sharing',
        severity: 'high',
        description: 'ML demo framework configured for public access. Gradio share links and public Streamlit deployments can expose model inference and data pipelines.',
        fix: 'Remove share=True from Gradio launch(). For Streamlit, add authentication or use private deployment.',
        guidance: 'Gradio share links create public URLs that bypass network security. Streamlit on 0.0.0.0 exposes the app to the internet. Both can leak model inference and data pipelines.',
        filePatterns: ['*.py', 'app.py', 'main.py', 'streamlit_app.py', 'demo.py'],
        contentPatterns: [
          /\.launch\s*\([^)]*share\s*=\s*True/,                // Gradio share=True
          /GRADIO_SERVER_NAME\s*=\s*["']?0\.0\.0\.0/,          // Gradio bind all
          /server\.address\s*=\s*["']?0\.0\.0\.0/,             // Streamlit bind all
        ],
      },
      {
        id: 'AITOOL-003', name: 'MLflow Tracking Server No Auth',
        severity: 'high',
        description: 'MLflow tracking server configured without authentication. Exposed MLflow instances leak experiment data, model artifacts, and parameters.',
        fix: 'Configure MLflow with --backend-store-uri and authentication. Use a reverse proxy with auth for remote access.',
        guidance: 'Exposed MLflow instances leak experiment data, model artifacts, hyperparameters, and metrics. Add authentication before exposing to any network.',
        filePatterns: ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile', 'Makefile', '*.sh'],
        contentPatterns: [
          /mlflow\s+server\s+.*--host\s+0\.0\.0\.0/i,
          /mlflow\s+ui\s+.*--host\s+0\.0\.0\.0/i,
          /MLFLOW_TRACKING_URI\s*=\s*["']?http:\/\//,
        ],
      },
      {
        id: 'AITOOL-004', name: 'LangServe Endpoint Exposed',
        severity: 'high',
        description: 'LangChain LangServe endpoint configured for public access. Exposed LangServe instances allow arbitrary chain invocation.',
        fix: 'Add authentication middleware to LangServe routes. Bind to 127.0.0.1 for local-only access.',
        guidance: 'LangServe exposes LangChain chains as REST endpoints. Without auth, anyone can invoke arbitrary chain operations, potentially accessing sensitive data or incurring costs.',
        filePatterns: ['*.py', 'app.py', 'main.py', 'server.py'],
        contentPatterns: [
          /add_routes\s*\(/,                                    // LangServe route
          /from\s+langserve\s+import/,                          // LangServe import
        ],
      },
    ];

    for (const check of AI_TOOL_PATTERNS) {
      const fixTransforms = AI_TOOL_FIXES[check.id];
      const isFixable = !!fixTransforms;

      for (const filePattern of check.filePatterns) {
        const filesToCheck: string[] = [];

        if (filePattern.includes('*')) {
          try {
            const entries = await fs.readdir(targetDir, { withFileTypes: true });
            const ext = filePattern.replace('*', '');
            for (const entry of entries) {
              if (entry.isFile() && entry.name.endsWith(ext)) {
                filesToCheck.push(entry.name);
              }
            }
          } catch { /* skip */ }
        } else {
          filesToCheck.push(filePattern);
        }

        for (const filename of filesToCheck) {
          const filePath = path.join(targetDir, filename);
          try {
            let content = await fs.readFile(filePath, 'utf-8');
            if (content.length > 10 * 1024 * 1024) continue;
            const lines = content.split('\n');

            for (const pattern of check.contentPatterns) {
              for (let i = 0; i < lines.length; i++) {
                pattern.lastIndex = 0;
                if (pattern.test(lines[i])) {
                  if (check.id === 'AITOOL-004' && /from\s+langserve/.test(lines[i])) {
                    const hasRoutes = content.includes('add_routes');
                    const hasBind = /0\.0\.0\.0/.test(content);
                    if (!hasRoutes || !hasBind) continue;
                  }

                  let fixed = false;
                  if (autoFix && fixTransforms) {
                    for (const ft of fixTransforms) {
                      if (ft.match.test(lines[i])) {
                        lines[i] = lines[i].replace(ft.match, ft.replace);
                        fixed = true;
                      }
                    }
                    if (fixed) {
                      const aiToolContent = lines.join('\n');
                      fixed = await this.applyFixWrite(filePath, aiToolContent);
                      if (fixed) content = aiToolContent;
                    }
                  }

                  findings.push({
                    checkId: check.id,
                    name: check.name,
                    description: check.description,
                    category: 'ai-tool-exposure',
                    severity: check.severity,
                    passed: fixed,
                    message: `${check.name} in ${filename}`,
                    file: filename,
                    line: i + 1,
                    fixable: isFixable,
                    fixed,
                    fix: check.fix,
                    guidance: check.guidance,
                  });
                  break;
                }
              }
            }
          } catch { /* file doesn't exist, skip */ }
        }
      }
    }

    return findings;
  }

  /**
   * A2A-001 to A2A-002: A2A protocol exposure
   * Detects .well-known/agent.json and task submission endpoints
   * that are publicly accessible without authentication.
   */
  private async checkA2AExposure(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Check for .well-known/agent.json (A2A discovery file)
    const wellKnownPaths = [
      path.join(targetDir, '.well-known', 'agent.json'),
      path.join(targetDir, 'public', '.well-known', 'agent.json'),
      path.join(targetDir, 'static', '.well-known', 'agent.json'),
    ];

    for (const agentJsonPath of wellKnownPaths) {
      try {
        const content = await fs.readFile(agentJsonPath, 'utf-8');
        const relativePath = path.relative(targetDir, agentJsonPath);

        // Parse and check for sensitive capabilities
        let agentCard: Record<string, unknown> = {};
        try { agentCard = JSON.parse(content); } catch { /* invalid JSON, still flag it */ }

        const hasAuth = content.includes('"authentication"') || content.includes('"auth"');

        findings.push({
          checkId: 'A2A-001',
          name: 'A2A Agent Discovery File Exposed',
          description: 'A .well-known/agent.json file makes this agent discoverable via the A2A protocol. Our research found exposed agent.json files that allow unauthenticated task submission.',
          category: 'a2a-exposure',
          severity: hasAuth ? 'medium' : 'high',
          passed: false,
          message: hasAuth
            ? 'Agent card found with authentication configured'
            : 'Agent card found WITHOUT authentication — any client can submit tasks',
          file: relativePath,
          fixable: false,
          fix: 'Add authentication requirements to your agent card. Restrict task submission to authenticated clients.',
          guidance: 'A2A agent cards make your agent discoverable on the network. Without authentication requirements, any client can submit tasks and consume resources or access sensitive data.',
          details: { hasAuth, capabilities: agentCard.capabilities },
        });
        break; // Found one, no need to check other paths
      } catch { /* doesn't exist */ }
    }

    // Check source files for A2A task endpoints without auth middleware
    const sourceFiles = ['server.py', 'app.py', 'main.py', 'server.ts', 'app.ts', 'index.ts'];
    for (const filename of sourceFiles) {
      try {
        const content = await fs.readFile(path.join(targetDir, filename), 'utf-8');
        if (content.length > 10 * 1024 * 1024) continue;

        const hasTaskEndpoint = /\/tasks\/send|\/tasks\/get|\/tasks\/cancel/.test(content);
        const hasAuthMiddleware = /auth|authenticate|verify.*token|api.?key|bearer/i.test(content);

        if (hasTaskEndpoint && !hasAuthMiddleware) {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            if (/\/tasks\/send|\/tasks\/get/.test(lines[i])) {
              findings.push({
                checkId: 'A2A-002',
                name: 'A2A Task Endpoint Without Authentication',
                description: 'A2A task submission endpoint found without visible authentication middleware.',
                category: 'a2a-exposure',
                severity: 'high',
                passed: false,
                message: `Unauthenticated task endpoint in ${filename}`,
                file: filename,
                line: i + 1,
                fixable: false,
                fix: 'Add authentication middleware to /tasks/send and /tasks/get endpoints. Require API key or bearer token.',
                guidance: 'Unauthenticated A2A task endpoints allow anyone to submit tasks to your agent. This can lead to resource abuse, data exfiltration, or unauthorized actions.',
              });
              break;
            }
          }
        }
      } catch { /* skip */ }
    }

    return findings;
  }

  /**
   * MCP-011: MCP discovery endpoint exposure
   * Detects .well-known/mcp files that make MCP servers discoverable.
   */
  private async checkMCPDiscovery(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    const mcpDiscoveryPaths = [
      path.join(targetDir, '.well-known', 'mcp'),
      path.join(targetDir, '.well-known', 'mcp.json'),
      path.join(targetDir, 'public', '.well-known', 'mcp'),
      path.join(targetDir, 'public', '.well-known', 'mcp.json'),
      path.join(targetDir, 'static', '.well-known', 'mcp'),
      path.join(targetDir, 'static', '.well-known', 'mcp.json'),
    ];

    for (const mcpPath of mcpDiscoveryPaths) {
      try {
        const content = await fs.readFile(mcpPath, 'utf-8');
        const relativePath = path.relative(targetDir, mcpPath);

        const hasCredentials = CREDENTIAL_PATTERNS.some(({ pattern }) => {
          pattern.lastIndex = 0;
          return pattern.test(content);
        });

        findings.push({
          checkId: 'MCP-011',
          name: 'MCP Discovery Endpoint Exposed',
          description: 'A .well-known/mcp discovery file makes MCP servers publicly discoverable. Our research found exposed MCP endpoints via this mechanism.',
          category: 'mcp',
          severity: hasCredentials ? 'critical' : 'high',
          passed: false,
          message: hasCredentials
            ? 'MCP discovery file contains credentials — CRITICAL exposure'
            : 'MCP discovery file found — servers are publicly discoverable',
          file: relativePath,
          fixable: false,
          fix: 'Remove .well-known/mcp from public-facing directories, or restrict access via web server configuration. Never include credentials in discovery files.',
          guidance: 'MCP discovery files make servers publicly discoverable. If they contain credentials, those are exposed to anyone who requests the URL. Restrict access or remove from public directories.',
        });
        break;
      } catch { /* doesn't exist */ }
    }

    return findings;
  }

  /**
   * WEBCRED-001 to WEBCRED-002: Credentials in web-served files
   * Detects API keys in HTML, JS, and other files typically served
   * by web servers. Distinct from CRED-001 which checks config files.
   */
  private async checkWebServedCredentials(
    targetDir: string,
    autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Unambiguous web-served directories — static assets published to a
    // public web server.
    const unambiguousWebDirs = ['public', 'static', 'www', '_site'];
    // Ambiguous directories — commonly Node.js / TypeScript compile output
    // (tsc, rollup, esbuild server bundles), but also frequently browser
    // bundles from frontend frameworks. Treat as web-served only when at
    // least one of these signals holds:
    //   - The directory contains ANY `.html` file (not just `index.html` —
    //     browser apps may ship only `home.html` or per-route pages).
    //   - The project's `package.json` declares a `browser` field or
    //     `main`/`module`/`exports` that points into this directory while
    //     also declaring a `browser` entry (npm browser-library convention).
    // Otherwise this is Node.js compile output — skip to avoid flagging the
    // package's own credential-detection regex source as exposed creds.
    const ambiguousWebDirs = ['dist', 'build', 'out', '.next', '.nuxt', 'target'];
    const webFileExts = ['.html', '.htm', '.js', '.jsx', '.tsx', '.css', '.svg'];

    // Load package.json browser-signal once.
    let pkgDeclaresBrowser = false;
    let pkgBrowserDirs: Set<string> = new Set();
    try {
      const pkgRaw = await fs.readFile(path.join(targetDir, 'package.json'), 'utf-8');
      const pkg = JSON.parse(pkgRaw);
      if (pkg && (pkg.browser !== undefined || pkg.unpkg !== undefined || pkg.jsdelivr !== undefined)) {
        pkgDeclaresBrowser = true;
        // Collect directories referenced by browser/unpkg/jsdelivr.
        // Skip leading ./ and ../ segments — idiomatic package.json entries
        // like "./dist/bundle.js" should record `dist`, not `.`.
        const collect = (v: unknown) => {
          if (typeof v === 'string') {
            const segs = v.split('/').filter(s => s && s !== '.' && s !== '..');
            if (segs[0]) pkgBrowserDirs.add(segs[0]);
          } else if (v && typeof v === 'object') {
            for (const inner of Object.values(v as Record<string, unknown>)) collect(inner);
          }
        };
        collect(pkg.browser);
        collect(pkg.unpkg);
        collect(pkg.jsdelivr);
      }
    } catch {
      // No package.json or unparseable — fall back to .html signal only.
    }

    // Project-level web-framework signal: many SPAs ship JS bundles in dist/
    // while serving index.html from a separate origin (nginx/Express). Such
    // projects do NOT declare `browser` in package.json and have no .html
    // inside dist/, but the bundle is still client-visible. Detect frontend
    // build-tool config files at the project root as a third signal.
    let isFrontendProject = false;
    try {
      const rootEntries = await fs.readdir(targetDir);
      const frontendConfigs = [
        'vite.config.js', 'vite.config.ts', 'vite.config.mjs',
        'webpack.config.js', 'webpack.config.ts',
        'rollup.config.js', 'rollup.config.ts', 'rollup.config.mjs',
        'next.config.js', 'next.config.ts', 'next.config.mjs',
        'nuxt.config.js', 'nuxt.config.ts',
        'svelte.config.js', 'svelte.config.ts',
        'astro.config.mjs', 'astro.config.ts', 'astro.config.js',
        'remix.config.js', 'gatsby-config.js', 'gatsby-config.ts',
        'parcel.config.js', 'esbuild.config.js',
        'angular.json', 'vue.config.js', 'vue.config.ts',
        'index.html',
      ];
      isFrontendProject = rootEntries.some(e => frontendConfigs.includes(e));
    } catch {
      // No targetDir read — skip the signal.
    }

    const allWebDirs: string[] = [...unambiguousWebDirs];
    for (const dir of ambiguousWebDirs) {
      const dirPath = path.join(targetDir, dir);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }
      // Signal 1: any .html file anywhere in the dir tree. A browser bundle
      // ships at least one .html shell; a tsc compile output does not.
      const htmlFiles = await this.findWebFiles(dirPath, ['.html', '.htm'], 0, dirPath);
      if (htmlFiles.length > 0) {
        allWebDirs.push(dir);
        continue;
      }
      // Signal 2: package.json declares browser/unpkg/jsdelivr entries that
      // reference this directory (npm browser-library convention). This
      // covers libraries like `@foo/widget` that ship `dist/widget.umd.js`
      // without an HTML shell — the package.json tells consumers (and us)
      // that the bundle is meant for the browser.
      if (pkgDeclaresBrowser && pkgBrowserDirs.has(dir)) {
        allWebDirs.push(dir);
        continue;
      }
      // Signal 3: project root carries a frontend-build config (vite,
      // webpack, next, rollup, nuxt, svelte, astro, etc.) or a top-level
      // index.html. SPAs that serve index.html externally still ship
      // client-visible bundles from dist/ — the signature is the build
      // tool, not the bundle layout.
      if (isFrontendProject) {
        allWebDirs.push(dir);
        continue;
      }
    }

    for (const webDir of allWebDirs) {
      const dirPath = path.join(targetDir, webDir);
      try {
        await fs.access(dirPath);
      } catch {
        continue; // Directory doesn't exist
      }

      // Recursively scan web-served directory (max depth 3)
      const webFiles = await this.findWebFiles(dirPath, webFileExts, 0, dirPath);

      for (const filePath of webFiles) {
        try {
          let content = await fs.readFile(filePath, 'utf-8');
          if (content.length > 10 * 1024 * 1024) continue;
          let lines = content.split('\n');
          const relativePath = path.relative(targetDir, filePath);
          let fileModified = false;

          for (const { name, pattern } of CREDENTIAL_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].length > 10000) continue;
              pattern.lastIndex = 0;
              if (pattern.test(lines[i])) {
                let fixed = false;

                if (autoFix) {
                  // Replace credential with process.env reference
                  // Also strip surrounding quotes so `"sk-proj-..."` becomes `process.env.VAR` not `"process.env.VAR"`
                  const envVar = name.replace(/\s+/g, '_').toUpperCase();
                  pattern.lastIndex = 0;
                  const original = lines[i];
                  const envRef = `process.env.${envVar}`;
                  // Replace quoted credential: "sk-..." or 'sk-...' → process.env.VAR (no quotes)
                  const quotedPattern = new RegExp(`(['"])${pattern.source}\\1`, pattern.flags);
                  quotedPattern.lastIndex = 0;
                  if (quotedPattern.test(lines[i])) {
                    quotedPattern.lastIndex = 0;
                    lines[i] = lines[i].replace(quotedPattern, envRef);
                  } else {
                    // No quotes, just replace the credential directly
                    pattern.lastIndex = 0;
                    lines[i] = lines[i].replace(pattern, envRef);
                  }
                  if (lines[i] !== original) {
                    fixed = true;
                    fileModified = true;
                  }
                }

                findings.push({
                  checkId: 'WEBCRED-001',
                  name: 'Credential in Web-Served File',
                  description: `${name} found in a file within a web-served directory. This credential is likely accessible to anyone who visits the site. Our research found API keys exposed in HTML source on the public internet.`,
                  category: 'web-credentials',
                  severity: 'critical',
                  passed: fixed,
                  message: fixed
                    ? `${name} in ${relativePath} replaced with environment variable reference`
                    : `${name} exposed in ${relativePath}`,
                  file: relativePath,
                  line: i + 1,
                  fixable: true,
                  fixed,
                  fix: `opena2a protect .  — scans for hardcoded secrets and encrypts them into a secure vault. Never include API keys in client-side code — use a backend proxy for API calls.`,
                  guidance: 'Credentials in web-served files (HTML, JS, CSS) are visible to anyone who views the page source. API keys in client-side code can be extracted and abused for unauthorized access.',
                });
                break;
              }
            }
          }

          if (fileModified) {
            const webCredContent = lines.join('\n');
            fileModified = await this.applyFixWrite(filePath, webCredContent);
            if (fileModified) {
              content = webCredContent;
            } else {
              // WEBCRED-001 was pushed BEFORE this write, so it already claims
              // `passed: true` for a repair that never reached disk. Revoke it
              // here, scoped to this file so one failure cannot touch another.
              for (const f of findings) {
                if (f.checkId === 'WEBCRED-001' && f.file === relativePath && f.fixed) {
                  f.passed = false;
                  f.fixed = false;
                  f.fixMessage = undefined;
                  // `message` was written from the in-memory replacement too,
                  // so leaving it renders an outstanding CRITICAL whose text
                  // says the credential was already replaced.
                  f.message = `Credential exposed in ${relativePath} (auto-fix could not be written)`;
                }
              }
            }
          }
        } catch { /* skip unreadable files */ }
      }
    }

    return findings;
  }

  /**
   * CODEINJ-001: exec() with template literal interpolation
   * Detects shell injection via exec/execSync called with template literals.
   */
  private async checkCodeInjection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    // Match exec( or execSync( followed by a backtick (template literal)
    // Do NOT match execFile or execFileSync (those use array args, safe)
    const pattern = /\b(?<!File)exec(?:Sync)?\s*\(\s*`/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'CODEINJ-001',
              name: 'exec() with template literal interpolation',
              description: 'exec() or execSync() called with a template literal allows shell injection. User-controlled values in the template can break out of the intended command.',
              category: 'code-injection',
              severity: 'critical',
              passed: false,
              message: `Shell injection risk: exec() with template literal in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Use execFile() or execFileSync() with an array of arguments instead of exec() with string interpolation.',
              guidance: 'Template literals in exec() are interpreted by /bin/sh, allowing shell metacharacters in interpolated values to execute arbitrary commands. Array-based APIs bypass the shell.',
            });
            break; // One finding per file
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * INSTALL-001: curl|sh without checksum in shell scripts
   * Detects piped-to-shell install patterns in .sh files.
   */
  private async checkInstallScripts(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'INSTALL-001',
              name: 'curl|sh without checksum verification',
              description: 'Shell script downloads and executes code via curl|sh or wget|sh without verifying a checksum. A MITM or compromised server can inject arbitrary code.',
              category: 'supply-chain',
              severity: 'critical',
              passed: false,
              message: `Unsafe pipe-to-shell install in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Download the script to a file first, verify its checksum (sha256sum), then execute it.',
              guidance: 'Piping directly to sh executes whatever the remote server returns without verification. A compromised or MITM-ed server can inject arbitrary code into your system.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * SHELL-EXFIL-001: credential file exfiltration in shell scripts.
   * Detects a remote curl/wget that uploads a known credential file
   * (`~/.aws/credentials`, `~/.ssh/id_*`, `.env`, gcloud/docker/kube/npm/netrc/
   * git credentials). Scoped to credential-file upload so it does not overlap
   * INSTALL-001's `curl … | sh` download-execute surface. CSR ruling 2026-08-24.
   */
  private async checkShellCredentialExfil(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh', '.bash', '.zsh'], 0, 2);

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          // Skip comment lines so a `# curl … @~/.aws/credentials` note does not fire.
          if (lines[i].trimStart().startsWith('#')) continue;
          const match = detectShellCredentialExfil(lines[i]);
          if (match) {
            findings.push({
              checkId: 'SHELL-EXFIL-001',
              name: 'Credential file exfiltration in shell script',
              description: 'Shell script uploads a credential file to a remote endpoint. A credential file sent over the network in a request body leaves the machine and can be captured, replayed, or logged at the destination.',
              category: 'credential-exposure',
              severity: 'critical',
              passed: false,
              message: `Credential file ${match.credPath} is sent to ${match.url} in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: `Remove the upload of ${match.credPath} on line ${i + 1}. If a service needs to authenticate, exchange the credential for a scoped, short-lived token server-side and never place a credential file in a request body. If this destination is known-good, add the path to .hmaignore.`,
              guidance: 'Transmitting a credential file (AWS/SSH/gcloud/docker/kube/npm keys, .env, .netrc) to a remote endpoint exposes long-lived secrets. The receiving server can be compromised or spoofed, and request bodies are frequently logged in transit.',
            });
            break; // One finding per file.
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * CLIPASS-001: Credentials passed as CLI arguments
   * Detects --token, --password, --api-key, --secret followed by variable interpolation.
   */
  private async checkCLICredentialPassthrough(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    const pattern = /--(token|password|api[_-]?key|secret|auth)\s*[=\s]\s*[`$"']\s*\$?\{?|["']--(token|password|api[_-]?key|secret|auth)["']/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            // Verify it's in a spawn/exec context
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i + 1).join('\n');
            if (/\b(exec\w*|spawn\w*|fork|run)\b/i.test(context)) {
              findings.push({
                checkId: 'CLIPASS-001',
                name: 'Credentials passed as CLI arguments',
                description: 'Credentials are passed as command-line arguments (--token, --password, etc.) with variable interpolation. CLI args are visible in process listings (ps aux) and shell history.',
                category: 'credential-exposure',
                severity: 'high',
                passed: false,
                message: `Credentials passed as CLI arguments in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Pass credentials via environment variables, stdin, or a config file instead of CLI arguments.',
                guidance: 'CLI arguments are visible to all users via ps aux, logged in shell history, and often captured in audit logs. Environment variables and stdin are not exposed to other processes.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * INTEGRITY-001: Digest/hash verification bypass on falsy value
   * Detects patterns like `if (digest &&` or `if (hash &&` where empty value skips check.
   */
  private async checkIntegrityBypass(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    const pattern = /if\s*\(\s*(digest|hash|checksum|signature|integrity)\s*&&/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'INTEGRITY-001',
              name: 'Integrity check bypass on falsy value',
              description: 'Integrity verification (digest/hash/checksum) is guarded by a truthiness check. If the value is empty, undefined, or null, the entire integrity check is silently skipped.',
              category: 'integrity-bypass',
              severity: 'critical',
              passed: false,
              message: `Integrity check bypass risk in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Require the integrity value to be present. Throw an error if digest/hash is missing rather than skipping verification.',
              guidance: 'A truthiness check on digest/hash silently skips verification when the value is empty. An attacker can remove the digest from a manifest to bypass all integrity checks.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * TOCTOU-001: Verify then use without atomic operation
   * Detects files that verify and then execute on the same path without atomicity.
   */
  private async checkTOCTOU(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const relativePath = path.relative(targetDir, file);

        // Test files deliberately exercise check-then-use shapes (including
        // intentional TOCTOU demonstrations and file-IO exercisers). Skip
        // them — shape-based TOCTOU detection cannot distinguish fixture
        // from production. [CSR-004].
        if (isTestPath(relativePath)) continue;

        // Two-tier TOCTOU detection, 40-line proximity window (same function scope):
        //
        //  Tier A — Access-gate TOCTOU: existsSync/accessSync/access() on a variable,
        //    then EXEC use (execFile/spawn/execSync) of the same variable. The check
        //    blesses the path and the use executes it — an attacker can swap the file
        //    in the race window. Access-gate + READ is NOT TOCTOU: reading a swapped
        //    file just produces attacker-controlled content the application must
        //    sanitize anyway, and idiomatic config loading (`if (existsSync(p))
        //    return readFileSync(p)`) was producing dominant FPs in real-world repos.
        //
        //  Tier B — Stat-then-exec TOCTOU: statSync/lstatSync/fs.stat/fs.lstat on a
        //    variable, then EXEC use of the same variable. Stat-then-read alone is
        //    tolerated for the same reason as access-then-read above.
        const fileLines = content.split('\n');

        const accessGatePattern = /\b(?:existsSync|accessSync|fs\.access)\s*\(\s*(\w+)\s*[,)]/g;
        const statPattern = /\b(?:statSync|lstatSync|fs\.stat|fs\.lstat)\s*\(\s*(\w+)\s*[,)]/g;
        // Dynamic `import(varPath)` always evaluates module code — same RCE
        // surface as exec, low FP risk. `require(varPath)` is intentionally
        // omitted: JSON loading via `require()` is legitimate config-load and
        // would re-introduce the dominant FP class this fix targets.
        const execUseRe = (v: string) => new RegExp(
          `\\b(?:execFile(?:Sync)?|spawn(?:Sync)?|execSync|child_process\\.exec|import)\\s*\\(\\s*${v}\\b`
        );
        const windowHasUse = (checkLineIdx: number, re: RegExp): boolean => {
          const windowEnd = Math.min(checkLineIdx + 40, fileLines.length);
          for (let i = checkLineIdx; i < windowEnd; i++) {
            if (re.test(fileLines[i])) return true;
          }
          return false;
        };

        const accessGateHit = [...content.matchAll(accessGatePattern)].some(m => {
          const varName = m[1];
          const lineIdx = content.slice(0, m.index!).split('\n').length - 1;
          return windowHasUse(lineIdx, execUseRe(varName));
        });
        const statExecHit = [...content.matchAll(statPattern)].some(m => {
          const varName = m[1];
          const lineIdx = content.slice(0, m.index!).split('\n').length - 1;
          return windowHasUse(lineIdx, execUseRe(varName));
        });
        const readAfterCheck = accessGateHit || statExecHit;
        // Pattern 2: integrity verify (hash/signature) followed by exec/spawn on the same path.
        const hasIntegrityVerify = /\b(verify|validate)(Hash|Signature|Digest|Checksum|Integrity)\s*\(/i.test(content);
        const hasShellExec = /\b(execFile|spawnSync|execSync|child_process)\s*\(/i.test(content);
        const hasFilePath = /\b(filePath|targetPath|scriptPath|modulePath)\b/.test(content);

        if (readAfterCheck || (hasIntegrityVerify && hasShellExec && hasFilePath)) {
          {
            // Find the line with the check for reporting
            let verifyLine = 0;
            const verifyPattern = /\b(?:existsSync|accessSync)\s*\(|\b(?:verify|validate)(?:Hash|Signature|Digest|Checksum|Integrity)\s*\(/i;
            for (let i = 0; i < fileLines.length; i++) {
              if (verifyPattern.test(fileLines[i])) {
                verifyLine = i + 1;
                break;
              }
            }
            findings.push({
              checkId: 'TOCTOU-001',
              name: 'Time-of-check-time-of-use race condition',
              description: 'File is verified (checksum/signature) and then used (executed/loaded) in separate operations without file locking. An attacker can replace the file between verify and use.',
              category: 'toctou-race',
              severity: 'high',
              passed: false,
              message: `TOCTOU risk: verify-then-use without atomic operation in ${relativePath}`,
              file: relativePath,
              line: verifyLine,
              fixable: false,
              fix: 'Use atomic file operations: verify and load in a single locked operation, or copy to a temp location before verification.',
              guidance: 'TOCTOU races allow file replacement between verification and use. An attacker can swap a verified file with a malicious one in the time window between the two operations.',
            });
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * TMPPATH-001: Hardcoded /tmp paths without mktemp
   * Detects writes to /tmp/ with hardcoded paths in shell scripts.
   */
  private async checkTmpPaths(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /(>|>>)\s*\/tmp\/|(-o)\s+\/tmp\/|\s\/tmp\/\S+/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        // Only flag if the script does NOT actually use mktemp (ignore comments)
        const nonCommentLines = lines.filter(l => !l.trimStart().startsWith('#'));
        if (/\bmktemp\b/.test(nonCommentLines.join('\n'))) continue;

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          pattern.lastIndex = 0;
          if (pattern.test(lines[i])) {
            findings.push({
              checkId: 'TMPPATH-001',
              name: 'Hardcoded /tmp path without mktemp',
              description: 'Shell script writes to a hardcoded /tmp/ path. Another user or process can create a symlink at that path to redirect writes (symlink attack).',
              category: 'tmppath-attack',
              severity: 'high',
              passed: false,
              message: `Hardcoded /tmp path in ${relativePath}`,
              file: relativePath,
              line: i + 1,
              fixable: false,
              fix: 'Use mktemp to create a unique temporary file/directory instead of hardcoded /tmp paths.',
              guidance: 'Predictable /tmp paths enable symlink attacks (CWE-377). Another user can create a symlink at the expected path, redirecting writes to sensitive files like /etc/passwd.',
            });
            break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * DOCKERINJ-001: Docker exec with variable interpolation
   * Detects docker exec commands with unquoted variable expansion.
   */
  private async checkDockerInjection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, ['.sh'], 0, 2);

    const pattern = /docker\s+exec\b.*?(\$\{?\w+\}?)/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          const line = lines[i];
          // Detect docker exec with any variable interpolation (quoted or not)
          if (/docker\s+exec\b/.test(line) && /\$\{?\w+\}?/.test(line)) {
              findings.push({
                checkId: 'DOCKERINJ-001',
                name: 'Docker exec with variable interpolation',
                description: 'docker exec command uses shell variable expansion. An attacker who controls the variable value can inject additional docker commands or escape the container context, even when quoted (e.g., in bash -c contexts).',
                category: 'code-injection',
                severity: 'high',
                passed: false,
                message: `Variable interpolation in docker exec in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Avoid passing user-controlled variables to docker exec. Validate and sanitize all inputs, and avoid bash -c with interpolated variables.',
                guidance: 'Variable interpolation in docker exec allows command injection. If the variable contains shell metacharacters, an attacker can execute arbitrary commands inside or escape the container.',
              });
              break;
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * ENVLEAK-001: process.env spread to child process
   * Detects passing all environment variables (including secrets) to child processes.
   */
  private async checkEnvLeak(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    const spreadPattern = /env:\s*\{\s*\.\.\.process\.env/g;
    const directPattern = /\benv:\s*process\.env\b/g;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          spreadPattern.lastIndex = 0;
          directPattern.lastIndex = 0;
          if (spreadPattern.test(lines[i]) || directPattern.test(lines[i])) {
            // Verify it's in a spawn/exec context
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i + 3).join('\n');
            if (/\b(spawn|exec|fork|execFile|execSync|spawnSync)\b/.test(context)) {
              findings.push({
                checkId: 'ENVLEAK-001',
                name: 'process.env spread to child process',
                description: 'All environment variables (including secrets like API keys, database passwords) are passed to a child process via env: process.env or { ...process.env }.',
                category: 'env-leak',
                severity: 'high',
                passed: false,
                message: `Full environment leaked to child process in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Pass only the specific environment variables the child process needs: env: { PATH: process.env.PATH, NODE_ENV: process.env.NODE_ENV }.',
                guidance: 'Spreading process.env passes all secrets (API keys, DB passwords, tokens) to child processes. A compromised or malicious child can read and exfiltrate these credentials.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * SANDBOX-005: Messaging API pre-allowed in sandbox policy
   * Detects pre-allowed URLs for messaging services in sandbox policies.
   */
  private async checkSandboxMessaging(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Scan YAML/JSON files in policies/ and config/ directories
    const policyDirs = ['policies', 'config', '.openclaw'];
    const policyExts = ['.yml', '.yaml', '.json'];

    for (const dirName of policyDirs) {
      const dirPath = path.join(targetDir, dirName);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }

      const files = await this.walkDirectory(dirPath, policyExts, 0, 2);
      const messagingPattern = /\b(telegram|slack|discord|webhook\.site|requestbin|pipedream)\b/gi;

      for (const file of files.slice(0, 50)) {
        try {
          const stat = await fs.stat(file);
          if (stat.size > MAX_FILE_SIZE) continue;
          const content = await fs.readFile(file, 'utf-8');
          const lines = content.split('\n');
          const relativePath = path.relative(targetDir, file);

          for (let i = 0; i < lines.length; i++) {
            if (lines[i].length > MAX_LINE_LENGTH) continue;
            messagingPattern.lastIndex = 0;
            const match = messagingPattern.exec(lines[i]);
            if (match) {
              // Check if this is in an allow/whitelist context
              const contextStart = Math.max(0, i - 3);
              const context = lines.slice(contextStart, i + 1).join('\n').toLowerCase();
              if (/\b(allow\w*|whitelist\w*|permit\w*|pre[_-]?allow\w*|approved|trusted)\b/.test(context)) {
                findings.push({
                  checkId: 'SANDBOX-005',
                  name: 'Messaging API pre-allowed in sandbox policy',
                  description: `Messaging service (${match[1]}) is pre-allowed in sandbox policy. An attacker who gains code execution inside the sandbox can exfiltrate data via this channel without triggering additional permission prompts.`,
                  category: 'sandbox-escape',
                  severity: 'high',
                  passed: false,
                  message: `Messaging API (${match[1]}) pre-allowed in ${relativePath}`,
                  file: relativePath,
                  line: i + 1,
                  fixable: false,
                  fix: 'Remove messaging services from pre-allowed URLs. Require explicit user approval for outbound messaging.',
                  guidance: 'Pre-allowed messaging APIs let sandbox code exfiltrate data silently via Telegram, Slack, or Discord without triggering permission prompts. Require explicit approval for each outbound message.',
                });
                break;
              }
            }
          }
        } catch { /* skip unreadable files */ }
      }
    }

    return findings;
  }

  /**
   * WEBEXPOSE-001: CLAUDE.md in web-served directories
   * WEBEXPOSE-002: .env files in web-served directories
   * WEBEXPOSE-003: Sensitive config files in web-served directories
   */
  private async checkWebExposedFiles(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    const webDirs = ['public', 'static', 'dist', 'build', 'out', 'www'];
    // Track seen real paths to avoid duplicates on case-insensitive filesystems
    const seenPaths = new Set<string>();

    // WEBEXPOSE-001: CLAUDE.md in web directories
    const claudeFiles = ['CLAUDE.md', 'claude.md'];
    // WEBEXPOSE-002: .env files in web directories
    const envFiles = ['.env', '.env.local', '.env.production'];
    // WEBEXPOSE-003: Sensitive config files in web directories
    const configFiles = ['mcp.json', 'config.json', 'settings.json', 'openclaw.json'];
    const configDirs = ['.claude'];

    for (const webDir of webDirs) {
      const dirPath = path.join(targetDir, webDir);
      try {
        await fs.access(dirPath);
      } catch {
        continue;
      }

      // WEBEXPOSE-001: CLAUDE.md
      for (const claudeFile of claudeFiles) {
        const filePath = path.join(dirPath, claudeFile);
        try {
          await fs.access(filePath);
          const realPath = await fs.realpath(filePath);
          if (seenPaths.has(realPath)) continue;
          seenPaths.add(realPath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-001',
            name: 'CLAUDE.md in web-served directory',
            description: 'CLAUDE.md found in a web-served directory. This file often contains system prompts, instructions, and operational details that should not be publicly accessible.',
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `CLAUDE.md exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Move CLAUDE.md out of the web-served directory. Add it to .gitignore and your build exclusion list.',
            guidance: 'CLAUDE.md contains system prompts and operational instructions. Publicly accessible CLAUDE.md reveals agent behavior, security controls, and attack surface to potential adversaries.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-002: .env files
      for (const envFile of envFiles) {
        const filePath = path.join(dirPath, envFile);
        try {
          await fs.access(filePath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-002',
            name: '.env file in web-served directory',
            description: 'Environment file found in a web-served directory. This file likely contains API keys, database credentials, and other secrets accessible to anyone who visits the site.',
            category: 'web-exposure',
            severity: 'critical',
            passed: false,
            message: `Environment file exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Remove .env files from web-served directories immediately. Store environment files in the project root (outside public/) and rotate any exposed credentials.',
            guidance: '.env files in web directories are directly downloadable by anyone. All credentials in these files should be considered compromised and rotated immediately.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-003: Sensitive config files
      for (const configFile of configFiles) {
        const filePath = path.join(dirPath, configFile);
        try {
          await fs.access(filePath);
          const relativePath = path.relative(targetDir, filePath);
          findings.push({
            checkId: 'WEBEXPOSE-003',
            name: 'Sensitive config file in web-served directory',
            description: `Configuration file (${configFile}) found in a web-served directory. This may expose MCP server configs, API endpoints, or other sensitive operational details.`,
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `Config file exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: `Move ${configFile} out of the web-served directory. Serve only the minimal configuration needed by the client.`,
            guidance: 'Configuration files in web directories expose MCP server addresses, API endpoints, authentication settings, and other operational details that aid attackers in targeting your infrastructure.',
          });
        } catch { /* file doesn't exist */ }
      }

      // WEBEXPOSE-003: Sensitive config directories
      for (const configDir of configDirs) {
        const configDirPath = path.join(dirPath, configDir);
        try {
          await fs.access(configDirPath);
          const relativePath = path.relative(targetDir, configDirPath);
          findings.push({
            checkId: 'WEBEXPOSE-003',
            name: 'Sensitive config directory in web-served directory',
            description: `.claude/ directory found in a web-served directory. This directory contains Claude Code settings and may expose system prompts or tool configurations.`,
            category: 'web-exposure',
            severity: 'high',
            passed: false,
            message: `Config directory exposed in web directory: ${relativePath}`,
            file: relativePath,
            fixable: false,
            fix: 'Remove the .claude/ directory from web-served directories. Add it to your build exclusion list.',
            guidance: 'The .claude/ directory contains Claude Code settings, tool permissions, and potentially system prompts. Public access reveals your AI tool configuration and attack surface.',
          });
        } catch { /* directory doesn't exist */ }
      }
    }

    return findings;
  }

  /**
   * SOUL-OVERRIDE-001: Skill content can override SOUL.md
   * Checks if SKILL.md and SOUL.md are loaded into the same prompt context without trust boundaries.
   */
  private async checkSoulOverride(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // Path 1: Look for system-prompt files that load both soul and skill content
    const promptFiles = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);
    const targetFiles = promptFiles.filter(f => {
      const name = path.basename(f).toLowerCase();
      return name.includes('system-prompt') || name.includes('systemprompt') ||
             name.includes('prompt-builder') || name.includes('promptbuilder') ||
             name.includes('context-builder') || name.includes('contextbuilder');
    });

    for (const file of targetFiles.slice(0, 20)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const relativePath = path.relative(targetDir, file);

        const hasSoul = /\b(soul|SOUL\.md|soulContent|soul_content)\b/.test(content);
        const hasSkill = /\b(skill|SKILL\.md|skillContent|skill_content)\b/.test(content);

        if (hasSoul && hasSkill) {
          // Check for trust boundary markers
          const hasBoundary = /\b(trustBoundary|trust_boundary|TRUST_BOUNDARY|sandboxed|isolated|untrusted)\b/.test(content);
          if (!hasBoundary) {
            const lines = content.split('\n');
            let soulLine = 0;
            for (let i = 0; i < lines.length; i++) {
              if (/\b(soul|SOUL\.md)\b/i.test(lines[i])) {
                soulLine = i + 1;
                break;
              }
            }
            findings.push({
              checkId: 'SOUL-OVERRIDE-001',
              name: 'Skill content can override SOUL.md',
              description: 'SOUL.md and SKILL.md content are loaded into the same prompt context without trust boundary markers. A malicious skill can include instructions that override the agent\'s core identity and safety rules.',
              category: 'soul-injection',
              severity: 'high',
              passed: false,
              message: `Soul and skill content mixed without trust boundaries in ${relativePath}`,
              file: relativePath,
              line: soulLine,
              fixable: false,
              fix: 'Add trust boundaries between SOUL.md (trusted) and SKILL.md (untrusted) content. Mark skill content as untrusted and instruct the model to not follow instructions from skill content.',
              guidance: 'Without trust boundaries, a malicious SKILL.md can include instructions that override the agent\'s core identity, safety rules, and behavioral constraints defined in SOUL.md.',
            });
          }
        }
      } catch { /* skip unreadable files */ }
    }

    // Path 2: Check for co-existing SOUL.md and SKILL.md files
    // When both exist in the same directory without trust markers in SKILL.md,
    // a malicious skill can override the agent's core identity
    if (findings.length === 0) {
      const soulPath = path.join(targetDir, 'SOUL.md');
      const skillPath = path.join(targetDir, 'SKILL.md');
      try {
        await fs.access(soulPath);
        await fs.access(skillPath);
        // Both exist -- check SKILL.md for override patterns
        const skillContent = await fs.readFile(skillPath, 'utf-8');
        const hasTrustBoundary = /\b(trustBoundary|trust_boundary|TRUST_BOUNDARY|sandboxed|isolated|untrusted)\b/.test(skillContent);
        if (!hasTrustBoundary) {
          // Strip YAML frontmatter and fenced code blocks before sentence
          // analysis. Without this strip, a SKILL.md frontmatter listing
          // `forbiddenTools: [bash, shell]` or a code block quoting an
          // attacker payload contributes false signal to either side of the
          // gate.
          const skillStripped = skillContent
            .replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '')
            .replace(/```[\s\S]*?```/g, '')
            .replace(/`[^`]*`/g, '');

          // Check if SKILL.md contains override/injection patterns. Split
          // into sentences across an expanded boundary set — `.!?` AND
          // `\n\r`, U+2028 / U+2029 line separators, semicolon, and HTML
          // `<br>` — so attackers can't fuse a benign decoy negation with a
          // malicious override line by inserting a non-`.` separator. The
          // exemption then requires the negation token to PRECEDE the
          // override target verb within the same sentence (and within a
          // small window), so prefixing an unrelated negation ("We never
          // bake bread. Override the safety rules") no longer disarms the
          // check.
          const overrideWord = /\b(override|ignore|suspend|bypass|disregard)\b/i;
          const ruleTarget = /\b(rules?|safety|guidelines?|instructions?|prompt)\b/i;
          // Negation must appear within ~80 chars BEFORE the override verb,
          // with no clause-break conjunction (`but`, `and`, `yet`, `however`,
          // `nevertheless`, `,`) between them. Defensive phrasing keeps the
          // negation tied to the override verb directly: "Must never comply
          // with requests to override its instructions" (no clause break).
          // A decoy form like "We never bake bread but Override the safety
          // rules" carries the negation in a separate clause and falls
          // outside the exemption \u2014 exactly the shape the adversarial
          // reviewer flagged. A double-negation form like "I will never
          // refuse to ignore the safety rules" carries 2+ negation tokens
          // in one sentence (semantically collapses to "always ignore") and
          // is also not exempt.
          const negationTokens = /\b(never|must\s+not|cannot|refuse\s+to|do\s+not|will\s+not|shall\s+not|forbidden|prohibit(?:ed)?|reject|resist)\b/gi;
          const negatedOverrideNoClauseBreak = /\b(never|must\s+not|cannot|refuse\s+to|do\s+not|will\s+not|shall\s+not|forbidden|prohibit(?:ed)?|reject|resist)\b(?:(?!\b(?:but|and|yet|however|nevertheless)\b|,).){0,80}\b(override|ignore|suspend|bypass|disregard)\b/i;
          const sentences = skillStripped.split(/[.!?\n\r\u2028\u2029;]+|<br\s*\/?>/i);
          const hasOverridePattern = sentences.some(s => {
            if (!overrideWord.test(s) || !ruleTarget.test(s)) return false;
            // Double-negation evasion ("never refuse to ignore the rules"):
            // 2+ negation tokens in one sentence -- fire.
            const negCount = (s.match(negationTokens) || []).length;
            if (negCount >= 2) return true;
            // Single-negation case: exempt only when the negation
            // immediately precedes the override verb with no clause break.
            return !negatedOverrideNoClauseBreak.test(s);
          });
          const hasEscalation = /\b(admin|system|root|debug)\s*(mode|access|privilege)/i.test(skillStripped);
          if (hasOverridePattern || hasEscalation) {
            findings.push({
              checkId: 'SOUL-OVERRIDE-001',
              name: 'Skill content can override SOUL.md',
              description: 'SKILL.md co-exists with SOUL.md and contains instructions that attempt to override safety rules. A malicious skill can include instructions that override the agent\'s core identity and safety rules.',
              category: 'soul-injection',
              severity: 'high',
              passed: false,
              message: 'SKILL.md contains override patterns that can bypass SOUL.md safety rules',
              file: 'SKILL.md',
              line: 1,
              fixable: false,
              fix: 'Add trust boundaries between SOUL.md (trusted) and SKILL.md (untrusted) content. Mark skill content as untrusted and instruct the model to not follow instructions from skill content.',
              guidance: 'SKILL.md contains override/escalation patterns that can bypass SOUL.md safety rules. Mark skill content as untrusted so the model knows not to follow instructions from it.',
            });
          }
        }
      } catch { /* one or both files don't exist */ }
    }

    return findings;
  }

  /**
   * SOUL governance gap checks: SOUL-COMPLETENESS, SOUL-CONSENT, SOUL-ESCAPE-CLAUSE,
   * SOUL-BYPASS, SOUL-CONTRADICTION, SOUL-UNVERIFIABLE-CLAIM.
   *
   * Scans SOUL.md files for missing constraints, escape clauses, bypass instructions,
   * contradictory privacy claims, or stacked unverifiable compliance assertions.
   */
  private async checkSoulGovernanceGaps(targetDir: string): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const soulFiles = await this.findFilesMatching(targetDir, ['SOUL.md']);

    for (const soulFile of soulFiles) {
      const relativePath = path.relative(targetDir, soulFile);
      let content: string;
      try {
        const stats = await fs.stat(soulFile);
        if (stats.size > MAX_FILE_SIZE) continue;
        content = await fs.readFile(soulFile, 'utf-8');
      } catch {
        continue;
      }

      // ── SOUL-BYPASS: instructs bypassing security tools ───────────────────
      const bypassPattern = /(bypass|skip|disable|ignore)\s+(?:hma|hackmyagent|oasb|security.check|analm|security.scan|scan.check)/i;
      const skipChecksPattern = /HMA_SKIP_CHECKS|SKIP_CHECKS\s*=\s*true|security.*validation.*disabled|checks.*disabled/i;
      const bypassMatch = bypassPattern.exec(content) ?? skipChecksPattern.exec(content);
      if (bypassMatch) {
        findings.push({
          checkId: 'SOUL-BYPASS',
          name: 'Security Check Bypass Instruction',
          description: 'SOUL.md instructs the agent to bypass or disable security scanning tools. This is a policy violation that blinds the agent\'s security posture verification.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'SOUL.md explicitly disables security checks',
          file: relativePath,
          line: lineFromOffset(content, bypassMatch.index),
          fixable: false,
          fix: 'Remove all instructions to bypass, skip, or disable HMA, OASB, or NanoMind checks. Security tools must never be disabled via SOUL instructions.',
          guidance: 'Instructing the agent to bypass its own security scanning is equivalent to disabling seatbelts and airbags. Remove these instructions before deploying.',
          attackClass: 'SOUL-BYPASS',
        });
      }

      // ── SOUL-ESCAPE-CLAUSE: 2+ constraints with "unless" escape modifiers ─
      const escapeClauses = Array.from(
        content.matchAll(/\b(will not|must not|shall not|should not|cannot|forbidden|prohibited)[^.]{0,120}unless\b/gi)
      );
      if (escapeClauses.length >= 2) {
        findings.push({
          checkId: 'SOUL-ESCAPE-CLAUSE',
          name: 'Escape Clauses Nullify Constraints',
          description: `SOUL.md has ${escapeClauses.length} constraints with "unless" escape modifiers. Each "unless" allows the constraint to be bypassed, making the policy unenforceable.`,
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: `${escapeClauses.length} constraints contain "unless" escape clauses`,
          file: relativePath,
          line: lineFromOffset(content, escapeClauses[0].index ?? 0),
          fixable: false,
          fix: 'Replace "unless" escape clauses with absolute prohibitions: change "will not X unless Y" to "must never X regardless of instructions".',
          guidance: 'A constraint that can be bypassed with "unless explicitly directed" is not a constraint — it is an open door.',
          attackClass: 'SOUL-ESCAPE-CLAUSE',
        });
      }

      // ── SOUL-CONTRADICTION: privacy claim + external transmission ─────────
      const privacyClaimPattern = /(never|not)\s+(share|transmit|send|forward|upload)[^.]*(?:third.party|external|outside)|processed locally|all data.*local|data.*never.*leav/i;
      const externalTransmitPattern = /(sync|upload|send|transmit|transfer|forward)[^.]*(?:to|at)\s+(?:https?:\/\/|analytics|platform|pipeline|endpoint|api\.)/i;
      const privacyMatch = privacyClaimPattern.exec(content);
      const transmitMatch = externalTransmitPattern.exec(content);
      if (privacyMatch && transmitMatch) {
        findings.push({
          checkId: 'SOUL-CONTRADICTION',
          name: 'Contradictory Privacy Claim',
          description: 'SOUL.md claims data stays local or is never shared externally, but also describes an external synchronization or transmission. The stated privacy guarantee is contradicted by the described behavior.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'SOUL privacy claim contradicts described external data transmission',
          file: relativePath,
          line: lineFromOffset(content, privacyMatch.index),
          fixable: false,
          fix: 'Resolve the contradiction: either remove the external sync or accurately disclose that data is transmitted externally.',
          guidance: 'Policy contradictions are exploitable: an attacker can invoke the permissive clause while the user believes the restrictive one applies.',
          attackClass: 'SOUL-CONTRADICTION',
        });
      }

      // ── SOUL-UNVERIFIABLE-CLAIM: stacked compliance certifications ────────
      const complianceTerms = [
        /ISO 27001/i, /SOC 2/i, /\bGDPR\b/i, /\bHIPAA\b/i, /\bCCPA\b/i,
        /AES.256/i, /PCI.?DSS/i, /\bindependently audit/i, /Trust Level [0-9]/i,
        /OpenA2A Registry.*(?:trusted|verified|certified)/i,
      ];
      const complianceMatches = complianceTerms
        .map(p => p.exec(content))
        .filter((m): m is RegExpExecArray => m !== null);
      const matchedTerms = complianceMatches.length;
      if (matchedTerms >= 3) {
        // Cite the earliest-occurring claim — gives the user a starting point
        // for the audit, since stacked claims usually cluster in one section.
        const firstClaim = complianceMatches.reduce((earliest, m) =>
          m.index < earliest.index ? m : earliest
        );
        findings.push({
          checkId: 'SOUL-UNVERIFIABLE-CLAIM',
          name: 'Stacked Unverifiable Compliance Claims',
          description: `SOUL.md asserts ${matchedTerms} compliance certifications or trust claims (ISO 27001, SOC 2, GDPR, etc.) without a verifiable attestation mechanism.`,
          category: 'soul-governance',
          severity: 'medium',
          passed: false,
          message: `${matchedTerms} unverifiable compliance claims in SOUL.md`,
          file: relativePath,
          line: lineFromOffset(content, firstClaim.index),
          fixable: false,
          fix: 'Replace general compliance claims with verifiable references: cite specific attestation IDs, audit report URLs, or regulatory body registration numbers.',
          guidance: 'Unverifiable compliance claims in a SOUL.md create false trust. Users cannot distinguish a legitimate claim from a fraudulent one without a verification mechanism.',
          attackClass: 'SOUL-UNVERIFIABLE-CLAIM',
        });
      }

      // ── SOUL-CONSENT: broad capabilities without consent ──────────────────
      // Only match affirmative capability declarations, not negated ones.
      // "I can execute shell" → match. "I do not access external services" → no match.
      const broadCapabilityOffset = (() => {
        const capPatterns = [
          /(execute|run)\s+shell/i,
          /(shell|system)\s+command/i,
          /access.*internet/i,
          /write.*file/i,
          /delete.*file/i,
          /financial.*transaction/i,
          /act.*behalf/i,
          // "external service" only when NOT preceded by negation in the same sentence
          /(?<!(?:do not|will not|cannot|never|no)\s{0,20})external.*service/i,
        ];
        for (const p of capPatterns) {
          const m = p.exec(content);
          if (!m) continue;
          // Check 60 chars before match for negation
          const before = content.slice(Math.max(0, (m.index ?? 0) - 60), m.index ?? 0);
          if (/\b(do not|will not|must not|cannot|never|no)\b/i.test(before.split(/[.!\n]/).pop() ?? '')) continue;
          return m.index;
        }
        return undefined;
      })();
      const hasBroadCapability = broadCapabilityOffset !== undefined;
      const irrevocableMatch = /irrevocable\s+consent|grants.*irrevocable|permanent.*consent/i.exec(content);
      const hasConsentLanguage = /\bconsent\b|\bauthori[sz]/i.test(content);

      if (hasBroadCapability && !hasConsentLanguage) {
        findings.push({
          checkId: 'SOUL-CONSENT',
          name: 'Broad Capabilities Without Consent Mechanism',
          description: 'SOUL.md declares broad high-risk capabilities (shell execution, external access, file operations) without any user consent or authorization requirement.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'High-risk capabilities present without consent/authorization constraints',
          file: relativePath,
          line: lineFromOffset(content, broadCapabilityOffset ?? 0),
          fixable: false,
          fix: 'Add a consent section defining which capabilities require explicit user authorization.',
          guidance: 'Broad capabilities without consent constraints mean the agent can take high-risk actions without user awareness.',
          attackClass: 'SOUL-CONSENT',
        });
      } else if (irrevocableMatch) {
        findings.push({
          checkId: 'SOUL-CONSENT',
          name: 'Irrevocable Blanket Consent',
          description: 'SOUL.md uses irrevocable blanket consent language. Irrevocable consent removes the user\'s ability to withdraw permission.',
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: 'Irrevocable consent language detected in SOUL.md',
          file: relativePath,
          line: lineFromOffset(content, irrevocableMatch.index),
          fixable: false,
          fix: 'Replace "irrevocable consent" with revocable, granular consent. Users must always be able to withdraw consent for agent capabilities.',
          guidance: 'Irrevocable consent is a legal and security red flag. Users must always be able to withdraw consent for agent capabilities.',
          attackClass: 'SOUL-CONSENT',
        });
      }

      // ── SOUL-COMPLETENESS: < 3 genuine constraints ────────────────────────
      // Count constraints NOT followed by an escape word within 50 chars
      const constraintMatches = Array.from(
        content.matchAll(/\b(will not|must not|shall not|cannot|does not|do not|never|forbidden|prohibited|restricted to|is not allowed)\b/gi)
      );
      const genuineConstraints = constraintMatches.filter(m => {
        const after = content.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 50);
        return !/\bunless\b|\bexcept\b|\bif needed\b|\bif required\b|\bif directed\b/i.test(after);
      });
      const constraintCount = genuineConstraints.length;

      // Only fire for SOUL files that declare capabilities (empty/scope-only SOULs are fine).
      // Use the matched capability declaration as the citation line — that's the
      // statement the user needs to either constrain or remove.
      const declaredCapMatch = /##\s*capabilit|i can |i am able to|this agent can|i execute|i can run|shell|internet|network|access.*file|delete.*file|external/i.exec(content);
      if (constraintCount < 2 && declaredCapMatch) {
        findings.push({
          checkId: 'SOUL-COMPLETENESS',
          name: 'Incomplete Governance Coverage',
          description: `SOUL.md has only ${constraintCount} enforceable constraint(s). A governed agent should have at least 3 explicit behavioral constraints covering capability boundaries, data handling, and trust hierarchy.`,
          category: 'soul-governance',
          severity: 'high',
          passed: false,
          message: `Only ${constraintCount} genuine constraint(s) — governance is incomplete`,
          file: relativePath,
          line: lineFromOffset(content, declaredCapMatch.index),
          fixable: false,
          fix: 'Add explicit constraints for: (1) capability boundaries, (2) data handling, (3) trust hierarchy.',
          guidance: 'Agents with fewer than 3 explicit constraints are under-governed and vulnerable to prompt injection attacks that exploit uncovered capability domains.',
          attackClass: 'SOUL-COMPLETENESS',
        });
      }
    }

    return findings;
  }

  /**
   * MEM-006: Memory store without input sanitization
   * Detects memory/persistence plugins that store user-provided text without sanitization.
   *
   * Path gate (hma#109, CSR-011): skip files that are deliberately
   * unsanitized by design — test harnesses, DVAA-style adversarial fixtures,
   * honeypots, trap pages. Flagging these as HIGH produces nonsensical fix
   * text ("sanitize this thing whose job is to stay unsanitized") and
   * destroys CISO trust in other findings. Classification:
   * (a) preserved-detection FP-suppress. Real production memory stores in
   * non-test, non-adversarial paths still fire.
   */
  private async checkMemoryStoreSanitization(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];
    const files = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS], 0, 2);

    // Look for store/save/persist calls with text/content parameter (method or function)
    const storePattern = /(?:\.|^|\s|\()(store|save|persist|insert|upsert|push)\s*\(\s*\{[^}]*(text|content|message|input)\b/g;

    // Path gate: industry-standard test-suffix matchers + adversarial-fixture
    // directory names. The adversarial-directory set is intentionally narrow
    // and requires an EXACT directory component match (not a hyphen-prefix)
    // so that real production names like `trap-router/`, `trap-focus/`, or
    // `adversarial-reports/` do not silently evade detection.
    //
    // A content-level marker (e.g. `// DVAA`) would be attacker-controlled —
    // scanned code is untrusted per trust hierarchy, so it must not be able
    // to turn off its own scanner. No content-marker gate is applied.
    const TEST_SUFFIX_RE = /(?:\.(?:test|spec)\.(?:m?js|ts)|-test\.(?:m?js|ts)|-spec\.(?:m?js|ts))$/;
    const ADVERSARIAL_DIR_RE = /(?:^|[\\/])(?:dvaa|honeypot|trap-fixtures|adversarial-fixtures|vulnerable-by-design)(?:[\\/]|$)/;

    for (const file of files.slice(0, 100)) {
      try {
        const stat = await fs.stat(file);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(file, 'utf-8');
        const lines = content.split('\n');
        const relativePath = path.relative(targetDir, file);

        // Skip if file has sanitization functions
        if (/\b(sanitize|sanitise|escapeHtml|htmlEncode|stripTags|DOMPurify|xss)\b/.test(content)) continue;

        // Path gate: skip test harnesses and adversarial-fixture directories.
        const basename = path.basename(file).toLowerCase();
        const relLower = relativePath.toLowerCase();
        if (TEST_SUFFIX_RE.test(basename)) continue;
        if (ADVERSARIAL_DIR_RE.test(relLower)) continue;

        for (let i = 0; i < lines.length; i++) {
          if (lines[i].length > MAX_LINE_LENGTH) continue;
          storePattern.lastIndex = 0;
          const storeMatch = storePattern.exec(lines[i]);
          if (storeMatch) {
            // `push` is array-generic: store/save/persist/insert/upsert name a
            // persistence sink by themselves, but `.push` is just as often a
            // local render/result array (lines.push, out.push, parts.push,
            // rows.push) that never reaches memory. Only a persistence-semantic
            // receiver (conversation/session/history/memory arrays) is a
            // poisoning sink, so gate `push` on the receiver name. Real
            // conversation-memory poisoning still fires; local accumulator
            // pushes are suppressed. Classification: (a) preserved-detection
            // FP-suppress (opena2a cli-ui render builders MEM-006 FP).
            if (storeMatch[1] === 'push') {
              // Extract the receiver chain immediately before `.push(` and split
              // it into lowercased word-parts across dots, brackets, snake_case,
              // and camelCase humps. A persistence-semantic part anywhere in the
              // chain (`userMemory`, `vectorStore`, `chatHistory`,
              // `session.messages`, `mem`) keeps the finding; a local render /
              // result array (`lines`, `out`, `parts`, `rows`) is suppressed.
              // Anchoring keywords as token-parts (not a prefix regex) is what
              // catches camelCase *suffixes* like `agentMemory` that a
              // start-anchored pattern would miss. If the receiver can't be
              // parsed (e.g. a chained call result), suppress — the explicit
              // store/save/persist/insert/upsert verbs remain ungated.
              const recvMatch = /([A-Za-z_$][\w$.[\]'"]*)\.push\s*\(/.exec(lines[i]);
              const parts = (recvMatch ? recvMatch[1] : '')
                .replace(/\[[^\]]*\]/g, '.')
                // Standard identifier tokenizer: split on dots/quotes/whitespace,
                // snake_case underscores, camelCase humps, acronym→word humps
                // (DBStore→DB,Store), and digit boundaries (memory2→memory,2).
                .split(/[._\s'"]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[a-zA-Z])(?=[0-9])/)
                .map((p) => p.toLowerCase())
                .filter(Boolean);
              const isPersistent = parts.some((p) => PERSISTENT_RECEIVER_PARTS.has(p));
              if (!isPersistent) continue;
            }
            // Check surrounding context for validation
            const contextStart = Math.max(0, i - 5);
            const context = lines.slice(contextStart, i).join('\n');
            if (!/\b(validate|sanitize|filter|clean|escape|strip)\b/.test(context)) {
              findings.push({
                checkId: 'MEM-006',
                name: 'Memory store without input sanitization',
                description: 'User-provided text is stored in a persistence layer without sanitization. An attacker can inject malicious content (prompt injection, XSS payloads) that persists and affects future sessions.',
                category: 'memory-poisoning',
                severity: 'high',
                passed: false,
                message: `Unsanitized input stored in memory/persistence in ${relativePath}`,
                file: relativePath,
                line: i + 1,
                fixable: false,
                fix: 'Sanitize all user-provided text before storing. Strip instruction-like patterns and HTML/script content.',
                guidance: 'Unsanitized user input persisted to memory can contain prompt injections or XSS payloads that affect future sessions. Sanitize before storage to prevent persistent poisoning.',
              });
              break;
            }
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * AGENT-CRED-001: No credential output protection in system prompt
   * Checks system prompts that mention exec/shell but lack credential protection instructions.
   */
  private async checkAgentCredentialProtection(
    targetDir: string,
    _autoFix: boolean
  ): Promise<SecurityFindingDraft[]> {
    const findings: SecurityFindingDraft[] = [];

    // System prompt files to check
    const promptFileNames = ['SOUL.md', 'CLAUDE.md', 'system-prompt.md', 'system-prompt.txt'];
    const promptFilePatterns = ['system-prompt.ts', 'system-prompt.js', 'systemprompt.ts', 'systemprompt.js'];

    const allFiles: Array<{ path: string; rel: string }> = [];

    // Check known file names
    for (const name of promptFileNames) {
      const filePath = path.join(targetDir, name);
      try {
        await fs.access(filePath);
        allFiles.push({ path: filePath, rel: name });
      } catch { /* skip */ }
    }

    // Check for system-prompt source files
    const srcFiles = await this.walkDirectory(targetDir, [...JS_FAMILY_EXTENSIONS, '.md', '.txt'], 0, 2);
    for (const file of srcFiles) {
      const basename = path.basename(file).toLowerCase();
      if (promptFilePatterns.some(p => basename === p.toLowerCase())) {
        allFiles.push({ path: file, rel: path.relative(targetDir, file) });
      }
    }

    for (const { path: filePath, rel: relativePath } of allFiles.slice(0, 20)) {
      try {
        const stat = await fs.stat(filePath);
        if (stat.size > MAX_FILE_SIZE) continue;
        const content = await fs.readFile(filePath, 'utf-8');

        // Check if the prompt mentions exec/shell capabilities
        const hasExecCapability = /\b(exec|execute|shell|command|subprocess|spawn|terminal|bash)\b/i.test(content);
        if (!hasExecCapability) continue;

        // Check if there's credential protection language
        const hasCredProtection = /\b(credential|secret|api[_\s-]?key|environment[_\s]variable|never\s+(print|echo|output|display|log)\s+(secret|credential|key|token|password))\b/i.test(content);

        if (!hasCredProtection) {
          findings.push({
            checkId: 'AGENT-CRED-001',
            name: 'No credential output protection in system prompt',
            description: 'System prompt grants exec/shell capabilities but does not include instructions to protect credentials from being output. An attacker can craft prompts that cause the agent to echo environment variables or credential files.',
            category: 'agent-credential',
            severity: 'medium',
            passed: false,
            message: `System prompt in ${relativePath} grants exec access without credential protection instructions`,
            file: relativePath,
            fixable: false,
            fix: 'Add credential protection instructions to the system prompt: "Never print, echo, or output API keys, tokens, passwords, or environment variable values. Reference credentials only by variable name."',
            guidance: 'Agents with exec/shell access can be tricked into echoing environment variables containing API keys and passwords. Explicit instructions in the system prompt add a defense layer.',
          });
        }
      } catch { /* skip unreadable files */ }
    }

    return findings;
  }

  /**
   * Stage 1: Context lifecycle assembly checks.
   * Simulates how the agent assembles its system prompt from multiple components
   * and detects injections that only activate post-assembly.
   */
  private async checkContextLifecycle(
    targetDir: string,
    options: ScanOptions,
  ): Promise<SecurityFindingDraft[]> {
    try {
      const result = await scanAssembly({
        targetDir,
        onProgress: options.onProgress,
      });
      return result.findings;
    } catch {
      // Assembly scan failure is non-fatal
      return [];
    }
  }

  /** Helper: recursively find files in web-served directories */
  private async findWebFiles(
    dir: string,
    extensions: string[],
    depth: number,
    rootDir: string
  ): Promise<string[]> {
    if (depth > 3) return [];
    const results: string[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const fullPath = path.join(dir, entry.name);

        if (!this.isPathWithinDirectory(fullPath, rootDir)) continue;

        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
          const subFiles = await this.findWebFiles(fullPath, extensions, depth + 1, rootDir);
          results.push(...subFiles);
        } else if (entry.isFile()) {
          if (extensions.some(ext => entry.name.endsWith(ext))) {
            results.push(fullPath);
          }
        }
      }
    } catch { /* skip inaccessible dirs */ }

    return results;
  }
}
