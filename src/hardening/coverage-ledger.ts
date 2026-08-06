/**
 * Runtime coverage ledger for `secure`.
 *
 * Before this existed, the scan's coverage claim was derived from
 * `TAXONOMY_MAP` — the CONFIGURED check set — so the Observations block
 * printed the same three lines whether 310 checks ran against the tree or
 * none of them did:
 *
 *   Checks      310 static · 200 semantic (NanoMind AST) · 0 skipped
 *   Categories  credentials, MCP, network, injection, ... + 16 more  (all clear)
 *   Verdict     No security issues detected. This library looks safe to use.
 *
 * Measured on a 528-file copy of a real repo carrying a planted
 * `sk-ant-api03-...` key, an `AKIAIOSFODNN7EXAMPLE`, and a
 * `curl … | sh`: byte-identical output, `100/100`. That is not a missed
 * detection — it is a false assurance line, and it is worse than silence
 * because it invites the reader to record a pass.
 *
 * This module replaces configuration with measurement. It records what each
 * check method ACTUALLY touched inside the target and derives the category
 * states from that.
 *
 * ## The ledger fails closed
 *
 * Every category starts `not-examined`. Only positive runtime evidence — a
 * path inspected INSIDE the target root while a registered check was on the
 * stack — upgrades it. This direction is deliberate and is the whole safety
 * property: instrumentation that is missing, wrong, or bypassed makes the
 * ledger UNDERSTATE coverage. It can never overstate it, which is the
 * failure mode that produced the defect in the first place.
 *
 * Method entry is NOT evidence. A check that runs and reads nothing from the
 * target examined nothing, and says so.
 */

import * as path from 'path';

/**
 * What a scan can honestly say about one category.
 *
 * - `examined`     — a check in this category ran AND inspected at least one
 *                    path inside the target.
 * - `not-examined` — the fail-closed default. Either no check in the category
 *                    ran, or every one that ran touched nothing in the target.
 * - `truncated`    — checks ran and inspected the target, but a cap stopped
 *                    the layer short of the whole tree, so a clear result
 *                    covers only the part that was reached.
 */
export type CoverageState = 'examined' | 'not-examined' | 'truncated';

/** One registered check method and what it actually did. */
export interface CheckExecution {
  /** Scanner method name, e.g. `checkCredentialExposure`. */
  method: string;
  /** Check-ID prefixes this method emits, e.g. `['CRED', 'ENVLEAK']`. */
  prefixes: string[];
  /** True once the method returned without throwing. */
  completed: boolean;
  /** Distinct paths inside the target this method read the CONTENTS of. */
  filesRead: number;
  /** Distinct paths inside the target it inspected without reading (stat/readdir). */
  pathsInspected: number;
  /** Set when the orchestration skipped the method outright. */
  skipReason?: string;
  /** Set when the method threw. A thrower examined nothing it can vouch for. */
  error?: string;
}

/** A cap that stopped a layer short of the whole tree. */
export interface CoverageTruncation {
  /** Layer that was capped, e.g. `semantic` or `nemo-source`. */
  layer: string;
  /** The cap value. */
  cap: number;
  /** Prefixes the capped layer covers. */
  prefixes: string[];
  /** Human-readable reason, rendered to the user verbatim. */
  reason: string;
}

/** Per-category rollup, derived entirely from the records above. */
export interface CategoryCoverage {
  /** Category label, matching the renderer's vocabulary. */
  category: string;
  state: CoverageState;
  /** Check methods that ran and inspected something for this category. */
  methods: string[];
  /** Distinct files whose contents were read for this category. */
  filesRead: number;
  /** Why it is `not-examined` / `truncated`. Empty when `examined`. */
  reason?: string;
}

/**
 * Map from scanner check method to the check-ID prefixes it emits.
 *
 * This table declares WHICH category a method's findings belong to. It does
 * NOT declare that the method ran or that it looked at anything — those are
 * measured. A wrong entry here mis-files evidence; it cannot manufacture it.
 *
 * `__tests__/hardening/coverage-honesty.test.ts` holds this
 * honest in two directions: every prefix named here must exist in
 * `TAXONOMY_MAP`, and every `check*` method reached by the orchestration must
 * appear here. A method added without a registration fails that test rather
 * than silently reporting its category as never examined.
 */
export const CHECK_METHOD_PREFIXES: Readonly<Record<string, readonly string[]>> = {
  checkCredentialExposure: ['CRED'],
  checkClaudeMd: ['CLAUDE'],
  checkMcpConfig: ['MCP'],
  checkFilePermissions: ['PERM'],
  checkGitSecurity: ['GIT'],
  checkNetworkSecurity: ['NET'],
  checkMcpAdvanced: ['MCP'],
  checkClaudeAdvanced: ['CLAUDE'],
  checkCursorConfig: ['CURSOR'],
  checkVscodeConfig: ['VSCODE'],
  checkCredentialsAdvanced: ['CRED'],
  checkPermissionsAdvanced: ['PERM'],
  checkEnvironmentSecurity: ['ENV'],
  checkLoggingSecurity: ['LOG'],
  checkDependencySecurity: ['DEP'],
  checkAuthSecurity: ['AUTH'],
  checkProcessSecurity: ['PROC'],
  checkClaudeExtended: ['CLAUDE'],
  checkMcpExtended: ['MCP'],
  checkNetworkExtended: ['NET'],
  checkIOSecurity: ['IO'],
  checkAPISecurity: ['API'],
  checkSecretManagement: ['SEC'],
  checkPromptSecurity: ['PROMPT'],
  checkInputValidation: ['INJ'],
  checkRateLimiting: ['RATE'],
  checkSessionSecurity: ['SESSION'],
  checkEncryption: ['ENCRYPT'],
  checkAuditTrail: ['AUDIT'],
  checkSandboxing: ['SANDBOX'],
  checkToolBoundaries: ['TOOL'],
  checkOpenclawSkills: ['SKILL', 'HEARTBEAT', 'SCAN'],
  checkOpenclawHeartbeat: ['HEARTBEAT', 'SCAN'],
  checkOpenclawGateway: ['GATEWAY', 'SCAN'],
  checkOpenclawConfig: ['CONFIG', 'SCAN'],
  checkOpenclawSupplyChain: ['SUPPLY', 'SCAN'],
  checkOpenclawCVE: ['CVE'],
  checkUnicodeSteganography: ['UNICODE-STEGO'],
  checkMemoryPoisoning: ['MEM'],
  checkRAGPoisoning: ['RAG'],
  checkAgentIdentity: ['AIM'],
  checkAgentDNA: ['DNA'],
  checkSkillMemory: ['SKILL-MEM'],
  checkNemoClawPatterns: ['NEMO'],
  checkLLMExposure: ['LLM'],
  checkAIToolExposure: ['AITOOL'],
  checkA2AExposure: ['A2A'],
  checkMCPDiscovery: ['MCP'],
  checkWebServedCredentials: ['WEBCRED'],
  checkInstallScripts: ['INSTALL'],
  checkCLICredentialPassthrough: ['CLIPASS'],
  checkIntegrityBypass: ['INTEGRITY'],
  checkTOCTOU: ['TOCTOU'],
  checkDockerInjection: ['DOCKERINJ'],
  checkSandboxMessaging: ['SANDBOX'],
  checkWebExposedFiles: ['WEBEXPOSE'],
  checkSoulOverride: ['SOUL-OVERRIDE'],
  checkSoulGovernanceGaps: ['SOUL'],
  checkMemoryStoreSanitization: ['MEM'],
  checkAgentCredentialProtection: ['AGENT-CRED'],
  checkContextLifecycle: ['LIFECYCLE'],
};

/**
 * Check-ID prefixes whose implementation exists but has no caller.
 *
 * `checkCodeInjection` (`CODEINJ-001`), `checkTmpPaths` (`TMPPATH-001`) and
 * `checkEnvLeak` (`ENVLEAK-001`) are defined in `scanner.ts` and emit
 * findings, but `grep -n 'this.checkCodeInjection('` and its two siblings
 * return NOTHING — the scan orchestration never calls them. Their three IDs
 * are nonetheless counted in the `310 static` the Observations block
 * advertises, so the advertised suite is 3 checks larger than the suite that
 * can fire.
 *
 * They are listed here rather than silently omitted so the `--json` inventory
 * can name them as unreachable instead of leaving the reader to infer it from
 * an absence. Wiring them in is a DETECTION change with its own FP surface and
 * belongs to its own unit, not to this one.
 */
export const UNREACHABLE_PREFIXES: readonly string[] = ['CODEINJ', 'TMPPATH', 'ENVLEAK'];

/**
 * Check-ID prefixes the NanoMind semantic layer can emit.
 *
 * The semantic pass is not a `check*` method — it runs in the scanner bridge
 * over the artifacts it compiled — so its evidence enters the rollup through
 * `SummarizeOptions.semantic` rather than through an execution record. This
 * list is what that evidence is credited to.
 *
 * Derived from the emission sites, not from `TAXONOMY_MAP`: the taxonomy holds
 * only 14 semantic IDs while the analyzers emit 15 distinct families, so
 * taking the taxonomy as the source would have silently dropped AST-CAP,
 * AST-CODE, AST-CRED, AST-GOV, AST-HEARTBEAT, AST-INJECT, AST-MANIP,
 * AST-PERSIST and AST-PROMPT from the coverage claim. The registration test
 * re-derives this list from `src/nanomind-core/` and `src/semantic/` and fails
 * on drift.
 */
export const SEMANTIC_PREFIXES: readonly string[] = [
  'AST-CAP', 'AST-CODE', 'AST-CRED', 'AST-EXFIL', 'AST-GOV', 'AST-HEARTBEAT',
  'AST-INJECT', 'AST-MANIP', 'AST-PERSIST', 'AST-PROMPT', 'AST-SCOPE',
  'SEM-CRED', 'SEM-INST', 'SEM-MCP', 'SEM-PERM',
];

/**
 * Category label for a check-ID prefix.
 *
 * Mirrors `CATEGORY_MAP` in `@opena2a/cli-ui`'s observations renderer so the
 * ledger speaks the same vocabulary the Categories line prints. Kept in step
 * by `__tests__/hardening/coverage-honesty.test.ts`, which
 * imports `ALL_CATEGORY_LABELS` from the renderer and asserts every label
 * this table produces is one the renderer knows.
 */
const PREFIX_TO_CATEGORY: Readonly<Record<string, string>> = {
  CRED: 'credentials', 'AST-CRED': 'credentials', WEBCRED: 'credentials',
  'SEM-CRED': 'credentials', 'AGENT-CRED': 'credentials', ENVLEAK: 'credentials',
  CLIPASS: 'credentials',
  MCP: 'MCP', 'AST-MCP': 'MCP', 'SEM-MCP': 'MCP',
  NET: 'network', GATEWAY: 'network', WEBEXPOSE: 'network',
  // `AST-EXFIL` is egress, so it is credited to network. It, `AST-INJECT`,
  // `AST-MANIP` and `AST-PERSIST` are absent from the renderer's own
  // CATEGORY_MAP, so a FINDING carrying one of them displays under "other"
  // while its COVERAGE is credited here. Those are different questions —
  // where a finding is filed, and whether the category was looked at — and
  // leaving these unmapped would understate coverage the semantic layer
  // genuinely performed.
  'AST-EXFIL': 'network',
  INJ: 'injection', IO: 'injection', CODEINJ: 'injection', DOCKERINJ: 'injection',
  'AST-INJECT': 'injection',
  PROMPT: 'prompt', 'AST-PROMPT': 'prompt', 'SEM-INST': 'prompt',
  'AST-MANIP': 'prompt',
  'AST-PERSIST': 'sandbox',
  ENCRYPT: 'encryption',
  SESSION: 'session',
  SANDBOX: 'sandbox', PROC: 'sandbox', PERM: 'sandbox', 'SEM-PERM': 'sandbox',
  TMPPATH: 'sandbox', TOCTOU: 'sandbox', 'AST-CODE': 'sandbox',
  'AST-CAP': 'capabilities', 'AST-SCOPE': 'capabilities',
  SUPPLY: 'supply-chain', DEP: 'supply-chain', INSTALL: 'supply-chain',
  INTEGRITY: 'supply-chain',
  'AST-GOV': 'governance', 'AST-GOVERN': 'governance', SOUL: 'governance',
  GOV: 'governance', 'SOUL-OVERRIDE': 'governance',
  SKILL: 'skill', 'SKILL-MEM': 'skill',
  'UNICODE-STEGO': 'unicode-stego', STEGO: 'unicode-stego',
  MEM: 'memory', RAG: 'memory',
  AIM: 'identity', 'AST-AIM': 'identity', DNA: 'identity',
  NEMO: 'sandbox-escape',
  CVE: 'CVE',
  A2A: 'A2A',
  LIFECYCLE: 'lifecycle',
  LLM: 'LLM risk',
  HEARTBEAT: 'heartbeat', 'AST-HEARTBEAT': 'heartbeat',
  CONFIG: 'config', ENV: 'config', VSCODE: 'config', CURSOR: 'config',
  CLAUDE: 'config', SEC: 'config',
  AUDIT: 'audit', LOG: 'audit', RATE: 'audit', SCAN: 'audit', CHK: 'audit',
  'CHK-FAIL': 'audit',
  AUTH: 'auth', TOOL: 'auth', API: 'auth', AITOOL: 'auth',
  GIT: 'git hygiene',
};

/** Category label for a check-ID prefix, or null when unmapped. */
export function categoryForPrefix(prefix: string): string | null {
  return PREFIX_TO_CATEGORY[prefix] ?? null;
}

/**
 * Category label for a full check ID (`SOUL-OVERRIDE-001` -> `governance`).
 *
 * Longest prefix wins, so `SOUL-OVERRIDE-001` is not filed under `SOUL`
 * because that also matches. Exported so callers and tests resolve IDs
 * through this one implementation rather than each re-deriving the rule.
 */
export function categoryForCheckId(checkId: string): string | null {
  const id = (checkId || '').toUpperCase();
  const prefix = Object.keys(PREFIX_TO_CATEGORY)
    .filter(p => id === p || id.startsWith(p + '-'))
    .sort((a, b) => b.length - a.length)[0];
  return prefix ? PREFIX_TO_CATEGORY[prefix] : null;
}

/**
 * Records what a single scan actually examined.
 *
 * One ledger per `scan()` call. The scanner installs it as the active ledger
 * for the duration of the run, so the tracked `fs` namespace can attribute
 * reads to whichever check is on the stack.
 */
export class CoverageLedger {
  /** Absolute, resolved target root. Reads outside it are not evidence. */
  private readonly targetRoot: string;
  private readonly executions = new Map<string, CheckExecution>();
  private readonly truncations: CoverageTruncation[] = [];
  /** Stack of running methods — the innermost gets the attribution. */
  private readonly stack: string[] = [];
  /** Distinct target paths whose contents were read, across the whole scan. */
  private readonly filesReadAll = new Set<string>();
  /** Per-method distinct path sets, so two reads of one file count once. */
  private readonly readsByMethod = new Map<string, Set<string>>();
  private readonly inspectedByMethod = new Map<string, Set<string>>();

  constructor(targetRoot: string) {
    this.targetRoot = path.resolve(targetRoot);
  }

  /** Total distinct files inside the target whose contents the scan read. */
  get filesExamined(): number {
    return this.filesReadAll.size;
  }

  /**
   * Run `fn` attributed to `method`.
   *
   * Registration is by method name; the prefixes come from
   * `CHECK_METHOD_PREFIXES`. An unregistered method still records its
   * evidence, but with no prefixes that evidence reaches no category — the
   * fail-closed direction.
   */
  async run<T>(method: string, fn: () => Promise<T>): Promise<T> {
    const rec = this.ensure(method);
    this.stack.push(method);
    try {
      const out = await fn();
      rec.completed = true;
      return out;
    } catch (err) {
      // A method that threw cannot vouch for what it did or did not cover.
      // `completed` stays false, so its category degrades to not-examined
      // unless another method in the same category supplies evidence.
      rec.error = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      this.stack.pop();
      rec.filesRead = this.readsByMethod.get(method)?.size ?? 0;
      rec.pathsInspected = this.inspectedByMethod.get(method)?.size ?? 0;
    }
  }

  /** Record that the orchestration skipped a method outright, and why. */
  skip(method: string, reason: string): void {
    const rec = this.ensure(method);
    rec.skipReason = reason;
  }

  /**
   * Mark every registered method with no execution record as skipped.
   *
   * Used by the quick-depth branch, where 55 of the 61 orchestrated checks
   * sit inside one `if (!isQuick)` block. Deriving the set from "has no record
   * yet" rather than from a hand-written list is deliberate: a list would
   * drift the moment a check is added to or moved out of that block, and a
   * drifted list would report a check as run when it was not — the same class
   * of false claim this ledger exists to remove.
   *
   * Call AFTER the depth-gated block, so checks that did run keep their
   * records.
   */
  skipUnrun(reason: string): void {
    for (const method of Object.keys(CHECK_METHOD_PREFIXES)) {
      if (this.executions.has(method)) continue;
      this.skip(method, reason);
    }
  }

  /** Record a cap that stopped a layer short of the whole tree. */
  truncate(t: CoverageTruncation): void {
    this.truncations.push(t);
  }

  /**
   * Attribute a content read. Called by the tracked `fs` namespace.
   *
   * Only paths inside the target root count: a check reading HMA's own model
   * files or the user's `~/.claude` is not evidence that it examined the
   * thing being scanned.
   */
  noteRead(target: string): void {
    this.note(target, this.readsByMethod, true);
  }

  /** Attribute a stat/readdir-style inspection (no content read). */
  noteInspect(target: string): void {
    this.note(target, this.inspectedByMethod, false);
  }

  private note(target: string, into: Map<string, Set<string>>, isRead: boolean): void {
    const method = this.stack[this.stack.length - 1];
    if (!method) return; // outside any registered check — not attributable
    let resolved: string;
    try {
      resolved = path.resolve(target);
    } catch {
      return;
    }
    if (!this.isInsideTarget(resolved)) return;
    let set = into.get(method);
    if (!set) {
      set = new Set<string>();
      into.set(method, set);
    }
    set.add(resolved);
    if (isRead) this.filesReadAll.add(resolved);
  }

  private isInsideTarget(resolved: string): boolean {
    if (resolved === this.targetRoot) return true;
    // Compare on a separator boundary so `/a/bc` is not read as inside `/a/b`.
    return resolved.startsWith(this.targetRoot + path.sep);
  }

  private ensure(method: string): CheckExecution {
    let rec = this.executions.get(method);
    if (!rec) {
      rec = {
        method,
        prefixes: [...(CHECK_METHOD_PREFIXES[method] ?? [])],
        completed: false,
        filesRead: 0,
        pathsInspected: 0,
      };
      this.executions.set(method, rec);
    }
    return rec;
  }

  /** Every registered execution record, for the `--json` inventory. */
  get records(): CheckExecution[] {
    return [...this.executions.values()];
  }

  /** Every cap that fired, for the `--json` inventory. */
  get caps(): CoverageTruncation[] {
    return [...this.truncations];
  }

  /**
   * Roll the raw records up into per-category states.
   *
   * `semanticPrefixes` carries the AST/SEM layer's evidence, which is
   * collected by the NanoMind bridge rather than by a `check*` method: the
   * layer reports how many artifacts it compiled and whether its cap fired.
   */
  summarize(opts?: SummarizeOptions): CategoryCoverage[] {
    return summarizeCoverage(this.records, this.caps, opts);
  }
}

/** Extra evidence from layers that are not `check*` methods. */
export interface SummarizeOptions {
  /** Prefixes the semantic layer examined, with its compiled-artifact count. */
  semantic?: { prefixes: string[]; artifactsCompiled: number };
  /**
   * Check IDs of findings this scan actually reported.
   *
   * A finding is the strongest evidence there is: the check ran, looked at
   * this target, and had something to say. Needed because some checks assert
   * on ABSENCE — `checkGitSecurity` reports `GIT-001` for a missing
   * `.gitignore` without reading a single byte, so a read-count rule alone
   * filed `git hygiene` as never examined while the same output listed a
   * `git hygiene` finding. Two lines of one report contradicting each other
   * is the defect this ledger exists to remove, so findings are counted.
   */
  observedCheckIds?: readonly string[];
}

/**
 * Roll execution records up into per-category states.
 *
 * Pure, and exported separately from the ledger class so the renderer and the
 * tests can run it over a serialized `ScanResult.coverage` — the same code
 * path the CLI uses, rather than a second implementation that could disagree
 * with it.
 */
export function summarizeCoverage(
  executions: readonly CheckExecution[],
  truncations: readonly CoverageTruncation[],
  opts?: SummarizeOptions,
): CategoryCoverage[] {
  const byCategory = new Map<string, CategoryCoverage>();
  const byMethod = new Map(executions.map(e => [e.method, e]));

  const bucket = (category: string): CategoryCoverage => {
    let c = byCategory.get(category);
    if (!c) {
      c = { category, state: 'not-examined', methods: [], filesRead: 0 };
      byCategory.set(category, c);
    }
    return c;
  };

  // Seed every category the ledger can speak about, all closed.
  for (const prefix of Object.keys(PREFIX_TO_CATEGORY)) {
    bucket(PREFIX_TO_CATEGORY[prefix]);
  }

  // Positive evidence only, and the evidence is a CONTENT read: the method
  // completed and read at least one file inside the target.
  //
  // `pathsInspected` (stat/readdir) deliberately does NOT establish coverage
  // on its own. A check that listed a directory, found no file of its kind and
  // read nothing has examined no content, and reporting that as `examined`
  // reproduces the defect one level down — measured on a 529-file repo, six
  // categories qualified on inspections alone while reading zero files, and
  // "examined, 0 files" is not a claim that survives being read aloud. Those
  // categories now report `not examined` with the surface named as the reason.
  //
  // The cost is understatement for an inspection-only check (file permissions
  // is examined by `stat`, not by reading). Understating is the only safe
  // direction for a coverage claim, so it is the one taken. `pathsInspected`
  // stays in the `--json` record, where it informs without asserting.
  for (const rec of executions) {
    if (!rec.completed || rec.filesRead === 0) continue;
    for (const prefix of rec.prefixes) {
      const category = PREFIX_TO_CATEGORY[prefix];
      if (!category) continue;
      const c = bucket(category);
      c.state = 'examined';
      c.methods.push(rec.method);
      c.filesRead += rec.filesRead;
    }
  }

  // A reported finding proves its category was examined, whatever the read
  // count says. Applied before the cap pass below, so a finding upgrades a
  // closed category to `examined` and the cap can still downgrade it to
  // `truncated` — a category that produced a finding under a capped layer is
  // still only partly covered.
  for (const checkId of opts?.observedCheckIds ?? []) {
    const category = categoryForCheckId(checkId);
    if (!category) continue;
    const c = bucket(category);
    if (c.state === 'not-examined') {
      c.state = 'examined';
      if (!c.methods.includes('reported-finding')) c.methods.push('reported-finding');
    }
  }

  if (opts?.semantic && opts.semantic.artifactsCompiled > 0) {
    for (const prefix of opts.semantic.prefixes) {
      const category = PREFIX_TO_CATEGORY[prefix];
      if (!category) continue;
      const c = bucket(category);
      c.state = 'examined';
      c.methods.push('nanomind-semantic');
      c.filesRead += opts.semantic.artifactsCompiled;
    }
  }

  // A cap downgrades an examined category to truncated: the checks ran, but a
  // clear result only covers the part of the tree they reached.
  for (const t of truncations) {
    for (const prefix of t.prefixes) {
      const category = PREFIX_TO_CATEGORY[prefix];
      if (!category) continue;
      const c = bucket(category);
      if (c.state === 'examined') {
        c.state = 'truncated';
        c.reason = t.reason;
      }
    }
  }

  // Reasons for everything still closed.
  for (const c of byCategory.values()) {
    if (c.state !== 'not-examined') continue;
    const methods = methodsForCategory(c.category);
    const skipped = methods.map(m => byMethod.get(m)).filter(r => r?.skipReason);
    const unreachable = UNREACHABLE_PREFIXES.some(
      p => PREFIX_TO_CATEGORY[p] === c.category,
    ) && methods.length === 0;
    if (skipped.length > 0) {
      c.reason = skipped[0]!.skipReason;
    } else if (unreachable) {
      c.reason = 'the check for this category has no caller in the scan (unreachable)';
    } else if (methods.length === 0) {
      c.reason = 'no check in this category ran';
    } else {
      c.reason = 'checks ran but found no file of this kind in the target';
    }
  }

  return [...byCategory.values()].sort((a, b) => a.category.localeCompare(b.category));
}

/** Registered method names whose prefixes map to `category`. */
function methodsForCategory(category: string): string[] {
  const out: string[] = [];
  for (const [method, prefixes] of Object.entries(CHECK_METHOD_PREFIXES)) {
    if (prefixes.some(p => PREFIX_TO_CATEGORY[p] === category)) out.push(method);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Active-ledger plumbing
// ---------------------------------------------------------------------------

/**
 * The ledger currently collecting evidence.
 *
 * Module-scoped because the tracked `fs` namespace is module-scoped: wrapping
 * the namespace once is what lets all 153 read sites be attributed without
 * touching any of them. Set and cleared by `withActiveLedger` around a scan.
 *
 * Nested scans (the verify pass inside `--fix` constructs its own scanner)
 * save and restore, so the inner run's reads are attributed to the inner
 * ledger and the outer one resumes intact.
 */
let activeLedger: CoverageLedger | null = null;

/** Run `fn` with `ledger` collecting evidence, restoring any prior ledger. */
export async function withActiveLedger<T>(
  ledger: CoverageLedger,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = activeLedger;
  activeLedger = ledger;
  try {
    return await fn();
  } finally {
    activeLedger = previous;
  }
}

/** Report a content read to the active ledger, if any. */
export function noteRead(target: unknown): void {
  if (!activeLedger) return;
  if (typeof target !== 'string') return; // fd / URL / Buffer — not attributable
  activeLedger.noteRead(target);
}

/** Report a stat/readdir-style inspection to the active ledger, if any. */
export function noteInspect(target: unknown): void {
  if (!activeLedger) return;
  if (typeof target !== 'string') return;
  activeLedger.noteInspect(target);
}

/** Test seam: the ledger currently installed, or null. */
export function currentLedger(): CoverageLedger | null {
  return activeLedger;
}
