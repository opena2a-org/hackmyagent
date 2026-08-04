/**
 * What "this AI config grants broad permissions" is allowed to mean (#299).
 *
 * The finding this feeds used to be a bare word test over the whole file:
 *
 *     /(?:allow|permit|grant|unrestricted|all\s+bash)/i.test(content)
 *
 * so a `CLAUDE.md` reading
 *
 *     The agent must never allow shell access to untrusted input.
 *     Do not permit writes outside the repository.
 *
 * was reported `HIGH — AI config files grant broad permissions`. The document
 * asserts the opposite of the finding, and governance documents are where the
 * words "allow" and "permit" live, so the rule fired hardest on exactly the
 * files whose presence is the good outcome. That is not a weak finding, it is a
 * false one, and it is the 0.22.0 release-blocker shape a second time.
 *
 * The replacement asks for a GRANT rather than a permissive vocabulary, and it
 * reports WHERE. Two things follow from that and both matter:
 *
 * 1. **A grant is a construction, not a word.** `allow` is a direction-free
 *    verb — a sentence is only a grant when what is being allowed is broad
 *    (`any`, `all`, `unrestricted`, `full`). `no restrictions` and
 *    `never refuse` are grants that begin with a negative word, so they are
 *    matched as phrases rather than assembled from a negation rule.
 *
 * 2. **Negation is scoped to the sentence, never to the file.** Every malicious
 *    fixture in `~/.opena2a/corpus/repo/malicious/kitchen-sink` carries a
 *    Secretless block dense with "never" and "NEVER" — `never read, write, or
 *    reference`, `Never hardcode credentials`. A file-level "does this document
 *    contain a negation" guard would suppress all four of them. The guard
 *    therefore looks only between the start of the containing sentence and the
 *    start of the match.
 *
 * `without` is deliberately NOT a negation token: it is the head of several
 * grant phrases (`without restriction`, `without safety checks`), and reading
 * it as a negation would suppress the clearest grants in the corpus.
 *
 * Coverage is anchored on real fixtures rather than on imagination. Every
 * pattern below matches a line in a corpus fixture or in the issue's
 * reproduction; a speculative `run (any|all) …` pattern was drafted and dropped
 * because it added no corpus coverage and matched ordinary prose such as
 * "run all commands from the repo root". `__tests__/scanner/permission-grant.test.ts`
 * pins both directions.
 */

/** Where a config file grants broad permissions, and what said so. */
export interface PermissionGrant {
  /** 1-indexed line within the config file. */
  line: number;
  /** The phrase that matched, exactly as it appears in the file. */
  token: string;
  /** The whole matched line, trimmed and length-capped, for the report. */
  text: string;
}

/** Longest line this will quote back into a report. */
const MAX_TEXT = 120;

/**
 * Constructions that actually hand an agent broad authority.
 *
 * Ordered structured-first so a JSON grant is cited at its wildcard rather than
 * at a prose sentence elsewhere in the same file.
 */
const GRANT_PATTERNS: RegExp[] = [
  // ── Structured config: a permission entry whose VALUE is unbounded ──────
  //
  // The key alone is not the signal. `"allow": ["Bash(npm test)"]` is a
  // restriction — it is the narrowing that makes the rest denied — and flagging
  // it HIGH is the same error as flagging restrictive prose. What matters is a
  // wildcard reaching the value.
  /"[A-Za-z]+\(\s*\*\s*\)"/,
  /\ballow(?:ed)?(?:Tools|Commands|Hosts)?\b\s*[:=]\s*\[?\s*["']?\*/i,
  /\bauto[_-]?approve\b\s*[:=]\s*(?:true|["']?(?:all|\*)["']?)/i,
  /\b(?:bypass|skip)[_-]?permissions?\b\s*[:=]\s*true/i,
  /--dangerously-skip-permissions\b/,
  /\bpermissions?\b\s*[:=]\s*["']?(?:all|\*)["']?/i,

  // ── Prose: the agent is told it may act without a bound ─────────────────
  /\bunrestricted\b/i,
  /\bwithout\s+(?:any\s+)?(?:restrictions?|limitations?|limits?|question|approval|confirmation|asking|permission|safety\s+checks?|security\s+checks?)/i,
  /\bno\s+(?:restrictions?|limits?|limitations?|safety\s+checks?|security\s+checks?)\b/i,
  /\b(?:full|complete|unlimited|unfettered|total)\s+access\b/i,
  /\ball\s+bash\b/i,
  /\b(?:bypass|skip|disable|ignore|override)\s+(?:the\s+)?(?:safety|security|permission)/i,
  /\balways\s+(?:execute|run|comply|obey)\b/i,
  /\bnever\s+(?:refuse|decline)\b/i,
  /\bnever\s+ask\s+for\s+(?:permission|approval|confirmation)\b/i,
  // A permissive verb whose object is broad. The distance bound keeps the two
  // halves in one clause: "allow the agent to run any command" is a grant,
  // "allow X" three sentences above the word "all" is not.
  /\b(?:allow|permit|grant|enable)\b[^.!?\n]{0,40}\b(?:any|all|every|anything|everything|unrestricted|full|arbitrary)\b/i,
];

/**
 * Words that reverse a grant when they precede it in the same sentence.
 *
 * Applied to the text BEFORE the match only. A grant phrase that opens with a
 * negative word (`no restrictions`, `never refuse`) carries that word inside
 * the match, so it is not read as its own negation.
 */
const NEGATIONS = /\b(?:never|not|n't|avoid|prohibit|prohibited|forbid|forbidden|disallow|disallowed|deny|denied|refuse|must\s+not|cannot|can't)\b/i;

/** Sentence boundaries, for scoping the negation test. */
const SENTENCE_BREAK = /[.!?;]/g;

/**
 * The start of the sentence containing `index` within `line`.
 *
 * Markdown bullets and JSON lines frequently carry no terminator at all, in
 * which case the sentence is the line.
 */
function sentenceStart(line: string, index: number): number {
  SENTENCE_BREAK.lastIndex = 0;
  let start = 0;
  let m: RegExpExecArray | null;
  while ((m = SENTENCE_BREAK.exec(line)) !== null) {
    if (m.index >= index) break;
    start = m.index + 1;
  }
  return start;
}

/**
 * The first genuine broad-permission grant in `content`, or undefined.
 *
 * Scans line by line so the finding can cite `file:line` and quote the phrase
 * that triggered it — the specificity half of #299. Returns the FIRST grant
 * rather than all of them: the finding names one place to look, and a reader
 * who fixes it re-runs the scan.
 */
export function findPermissionGrant(content: string): PermissionGrant | undefined {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4096) continue; // minified or generated; not prose
    for (const pattern of GRANT_PATTERNS) {
      const m = pattern.exec(line);
      if (!m) continue;
      const before = line.slice(sentenceStart(line, m.index), m.index);
      if (NEGATIONS.test(before)) continue;
      return {
        line: i + 1,
        token: m[0].trim(),
        text: capped(redactLikelySecrets(line.trim())),
      };
    }
  }
  return undefined;
}

function capped(s: string): string {
  return s.length > MAX_TEXT ? `${s.slice(0, MAX_TEXT - 1)}…` : s;
}

/**
 * Mask credential-shaped runs before a scanned line is quoted into a report.
 *
 * Quoting the matched line is what makes the finding verifiable, and the line
 * comes out of the user's tree — so a config that puts a grant and a key on one
 * line (`{"allow": ["Bash(*)"], "apiKey": "sk-…"}`) would otherwise print the
 * key to the terminal and into any CI log capturing it. A security tool must not
 * be the thing that copies a secret somewhere new.
 *
 * Deliberately local and small. It is a guard on one quoted line, not a
 * credential scanner — `src/hardening/scanner.ts` owns that job, and reaching
 * into it (or into the NanoMind redactor) to reuse a regex would couple this
 * report to a detector that answers a different question.
 */
export function redactLikelySecrets(s: string): string {
  return s
    .replace(
      /\b(api[_-]?key|apikey|secret|token|password|passwd|pwd|authorization)(\s*[:=]\s*["']?)([A-Za-z0-9_\-.+/]{12,})/gi,
      (_all, key: string, sep: string) => `${key}${sep}[redacted]`,
    )
    .replace(/\b(sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|xox[baprs]-|AKIA)[A-Za-z0-9_\-]{8,}/g, '$1[redacted]');
}
