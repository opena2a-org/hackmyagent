/**
 * The `explain` command's knowledge, extracted from src/cli.ts (HMA-29).
 *
 * Four sources answer `explain <id>`: this static explanations table, the
 * scan-soul findings table (SOUL_SCAN_EXPLANATIONS), the scan-soul
 * governance catalog (CONTROL_DEFS), and the attack-class lookup over
 * TAXONOMY_MAP. `isKnownExplainId` is their union — the predicate the
 * CLI's refusal branch calls, extracted here so the AC2 sweep
 * (__tests__/cli/explain-unknown-id.test.ts) can walk every source
 * in-process instead of spawning the binary four hundred times.
 *
 * Before HMA-29 an unknown hyphenated id whose prefix appeared in
 * PREFIX_DESCRIPTIONS ('NEMO-999') printed the generic "<Category> finding."
 * stub and exited 0 — a confident non-answer with a green exit code.
 *
 * The check-definition table (src/hardening/check-definitions.ts) answers
 * every check the tool reports with its name, description, why it matters
 * where its findings say, and its fix or a line saying none is recorded.
 * Before it, a known id with no hand-written line here printed that
 * same generic stub: 260 of the 306 ids `check-metadata` lists.
 */
import { CLI_PREFIX } from './cli-prefix';
import { CONTROL_DEFS, PROFILE_DOMAINS, VIOLATION_CATALOG } from './soul/scanner';
import { getTaxonomyMap } from './hardening/taxonomy';
import { DEEP_SCAN_NOT_RUN_FIX, DEEP_SCAN_NOT_RUN_NAME } from './hardening/settled-outcome';
import { CHECK_DEFINITIONS, getCheckDefinition, type CheckDefinition } from './hardening/check-definitions';

/**
 * Hand-written explanations for the checks users ask about most.
 *
 * An entry for a check in the check-definition table describes the check and
 * names a command; it states no fix of its own. `explainBody` prints the
 * definition's reason and fix after it, which are the ones the finding
 * carries (#1132): AST-CRED-001's entry said `opena2a protect .` while its
 * findings say never to request or retransmit credentials.
 */
export const STATIC_EXPLANATIONS: Record<string, string> = {
  'CRED-001': 'Hardcoded credential detected. API keys, tokens, or passwords are embedded directly in source code. Run: opena2a protect . — migrates hardcoded secrets into the Secretless vault (local, keychain, 1Password, or HashiCorp Vault). Keys are injected at runtime; source files reference them by name only. Rotate any already-exposed credentials.',
  // #918 — secure files CRED-002 as a private key file; this line described
  // an OpenAI API key, so explain and the finding named different things.
  'CRED-002': 'Private key file in the project directory. A .key file, a .pem file holding a private key, or a JSON file whose field value holds a private key (the finding names the field) sits where it is easily committed to git; once pushed, the key is compromised.',
  // CRED-003, CRED-004, MCP-001, SKILL-005, PERM-001 to PERM-003 and
  // SUPPLY-001 had lines here that described other checks than the ones
  // secure files under those ids (an API key shape for "Secrets in
  // package.json", TLS for "MCP Root Filesystem Access"). They answer from
  // the check-definition table now, which copies each finding's own text.
  // #477 — fix-all reads source files now, and a finding it can report has
  // to be a finding it can explain. Says plainly that this one is not
  // rewritten for you: fix-all edits config files, never source.
  'CRED-005': 'Hardcoded credential in a source file. fix-all reports it but does not rewrite source. Rotate the credential at the provider, then read it from the environment or a secrets manager. Run: opena2a protect . — migrates hardcoded secrets into the Secretless vault so source files reference them by name only.',
  // #536 — reported only by `secure --scan-history`. The remedy is rotation,
  // not a tree edit: the commit keeps serving the value whatever the tree holds.
  'CRED-HIST-001': 'Credential in git history. A commit reachable from a branch, tag or remote ref added this value, so every clone that contains the commit can read it, whether or not the file still holds it. Rotate the credential at its issuer first; that is the step that ends the exposure. Rewriting history (for example with git filter-repo) is a separate step that changes every later commit and needs every clone re-fetched. A rotated value keeps reporting while a commit holds it; after rotating, --since <ref> limits later runs to the commits after <ref>. Reported by: hackmyagent secure --scan-history',
  'GOV-001': 'No governance policy found. Agents should declare behavioral constraints in a SOUL.md or governance file. Create a SOUL.md with mission, boundaries, and allowed actions.',
  'GOV-002': 'Governance file lacks boundary definitions. Without explicit boundaries, the agent may act outside intended scope. Add "boundaries" or "constraints" sections to your governance file.',
  'GOV-003': 'Governance file missing escalation policy. Define when and how the agent should escalate to a human. Add an escalation section with trigger conditions and contact methods.',
  'SOUL-001': `No SOUL.md file found. SOUL.md defines the agent identity, mission, and behavioral constraints. Run \`${CLI_PREFIX} secure --fix\` to generate one.`,
  'SOUL-002': 'SOUL.md missing identity section. The agent lacks a declared identity, making impersonation easier. Add name, version, and publisher fields.',
  'SOUL-003': 'SOUL.md missing behavioral boundaries. Without explicit limits, the agent may perform unintended actions. Add a boundaries section listing prohibited behaviors.',
  'PRIV-001': 'PII handling not declared. The agent processes data but has no privacy policy or data handling declaration. Add a data handling section specifying what data is collected, stored, and shared.',
  'DATA-001': 'Sensitive data logged to console or file. Credentials, tokens, or PII appear in log output. Sanitize log statements to redact sensitive values before output.',
  'DATA-002': 'Data retention policy missing. The agent stores data without a defined retention or deletion policy. Define how long data is kept and when it is purged.',
  'INJECT-001': 'No prompt injection defense detected. The agent does not validate or sanitize inputs against injection attacks. Add input validation and consider using a system prompt with injection resistance instructions.',
  'INJECT-002': 'Indirect prompt injection surface found. External data (URLs, files, API responses) is passed to the LLM without sanitization. Sanitize or sandbox external content before including it in prompts.',
  'ATTEST-001': 'No attestation mechanism found. The agent cannot prove its identity or integrity to other agents. Implement agent attestation using signed identity tokens or SOUL.md signatures.',
  'AST-PROMPT-001': `Jailbreak susceptibility. The instruction hierarchy is weak — the system prompt lacks mandatory language ("must never", "shall not") and clear authority over user input. Jailbreak attacks ("ignore previous instructions", "you are now...") can override the system prompt. Run: ${CLI_PREFIX} harden-soul <dir>`,
  'AST-PROMPT-003': `Missing injection resistance. No explicit clause rejects instruction overrides from user data, tool outputs, or retrieved documents. Without this, the agent will comply with injected instructions in external content. Run: ${CLI_PREFIX} harden-soul <dir>`,
  'AST-INJECT-001': `Active prompt injection surface. The artifact contains language that enables instruction override — "ignore previous instructions", "you are now", or conditional compliance patterns. This is a high-confidence attack vector, not a theoretical risk. Run: ${CLI_PREFIX} harden-soul <dir> to generate injection-resistant governance.`,
  'AST-GOV-001': `Governance domain gap. The artifact has capabilities but missing constraint coverage across governance domains (data handling, trust hierarchy, scope, human oversight, safety). Without coverage, the agent has no guardrails for uncovered areas. Run: ${CLI_PREFIX} harden-soul <dir> to auto-generate missing governance sections.`,
  'AST-GOV-002': `Weak constraint enforceability. Declared constraints use advisory language ("should", "try to", "when appropriate") that an adversary can argue against. Constraints using "should" have bypass risk above 50%. Run: ${CLI_PREFIX} scan-soul --verbose to see enforceability scores.`,
  'AST-CRED-001': 'Credentials in non-environment context. The artifact reads, transmits, or references credential data from a context where it can be extracted via prompt injection, leaked in git history, or exposed in build artifacts.',
  'AST-CRED-002': 'Credential forwarding. The artifact transmits credential data to an external destination — even to "trusted" endpoints this is dangerous because the destination can be compromised or spoofed.',
  'AST-CRED-003': 'Hardcoded secret. The artifact contains patterns consistent with hardcoded API keys, tokens, or passwords. These are exposed in version control history and to anyone who can read the file.',
  'TEXT-001': `Instruction-override payload in a free text. A line of a pull-request body, issue, comment or agent card asks to be read as an instruction to whoever is processing it — setting aside instructions already in force — rather than as content. Run: ${CLI_PREFIX} scan-text <file> to see the line and column.`,
  'TEXT-002': `Authority-claim payload in a free text. A line asserts an authorization, or waives a control, on the strength of the text itself rather than of any system that records one — "pre-approved by the owner", "the security gate can be skipped". Run: ${CLI_PREFIX} scan-text <file> to see the line and column.`,
  // #901 — removed in #395 and no longer in the check suite, but a
  // `.hmaignore` line or a saved report can still carry the id. Answering
  // "Unknown check ID" pointed nowhere; these name the check that remains.
  'CODEINJ-001': `Removed check. CODEINJ-001 (exec() or execSync() called with a template literal) is no longer in the check suite and no finding carries it, so a .hmaignore entry for it matches nothing. NEMO-005 (exec() with user-controlled string interpolation) reports this risk at the standard and deep scan depths, but not every line CODEINJ-001 matched. Run: ${CLI_PREFIX} explain NEMO-005`,
  'TMPPATH-001': `Removed check. TMPPATH-001 (a shell script writing to a hardcoded /tmp/ path without mktemp) is no longer in the check suite and no finding carries it, so a .hmaignore entry for it matches nothing. NEMO-006 (predictable /tmp path without mktemp) reports this risk at the standard and deep scan depths, but not every line TMPPATH-001 matched. Run: ${CLI_PREFIX} explain NEMO-006`,
  'ENVLEAK-001': `Removed check. ENVLEAK-001 (the whole process.env passed to a child process) is no longer in the check suite and no finding carries it, so a .hmaignore entry for it matches nothing. NEMO-007 (full process.env passthrough to subprocess) reports this risk at the standard and deep scan depths, but not every line ENVLEAK-001 matched. Run: ${CLI_PREFIX} explain NEMO-007`,
  // #914 — the three checks above point here with `Run: explain NEMO-00x`.
  // Without an entry each answered only "Static analysis pattern finding."
  'NEMO-005': `exec() with user-controlled string interpolation. A line in a JavaScript or TypeScript file calls exec() or execSync(), not execFile(), with a template literal whose interpolation names an input-like value (its text contains name, id, input, arg, param, flag or option, in any case). exec() hands the whole string to /bin/sh, which interprets shell metacharacters, so a value that reaches the interpolation can run commands. Run: ${CLI_PREFIX} secure --verbose to see each matching line.`,
  'NEMO-006': `Predictable /tmp path without mktemp. A line in a shell script (.sh) names a hardcoded /tmp/ path and redirects output (>), passes -o /tmp/..., or runs install with a /tmp/ path; a line that calls mktemp is not reported. A predictable name lets another local user create a symlink at that path first, so the write lands on a file of their choosing (CWE-377). Run: ${CLI_PREFIX} secure --verbose to see each matching line.`,
  'NEMO-007': `Full process.env passthrough to subprocess. A line in a JavaScript or TypeScript file outside test paths spreads ...process.env into an env: { } object, the subprocess option that hands the child every variable in the parent's environment, API keys and tokens included. Run: ${CLI_PREFIX} secure --verbose to see each matching line.`,
  // #918 — secure --deep reports this id and exits 2 on it; explain answered
  // "Unknown check ID". Both records it files under the id are described.
  'SEM-LLM-NOT-ANALYZED': `Deep analysis coverage gap. A --deep scan asked the deep analysis tier (Layer 3) to analyze files and got no result it could read, so those files have not been checked for the credential shapes only that tier detects. This is a gap in coverage, not a clean result: the checks that did run are unaffected. The finding is "${DEEP_SCAN_NOT_RUN_NAME}" once for the run when the tier could not run at all (ANTHROPIC_API_KEY is not set, or the call failed; the message names the cause and how many files it would have analyzed), or "Deep analysis did not complete for this file" for each file whose answer could not be read. It is medium, and secure exits 2 on it unless a critical or high finding exits 1 first; --ignore does not lower that exit code. Fix: ${DEEP_SCAN_NOT_RUN_FIX}. If one file repeats, its own content may be interfering with the analysis. Run: ${CLI_PREFIX} secure <dir> --deep`,
};

/**
 * Check IDs removed from the suite, each with the check that remains for its
 * risk. No finding carries a removed ID, so `explain` points its Next Steps at
 * the remaining check rather than at a scan that cannot show it (#914).
 */
export const REMOVED_CHECKS: Readonly<Record<string, string>> = Object.freeze({
  'CODEINJ-001': 'NEMO-005',
  'TMPPATH-001': 'NEMO-006',
  'ENVLEAK-001': 'NEMO-007',
});

/**
 * Ids scan-soul prints that are not governance controls: the two profile
 * findings, the tier mismatch (#451), the conformance line, the bare SOUL-VIOLATION that leads the
 * --ci gate line (#863) and every SOUL-VIOLATION-* class (#760).
 * Before this
 * table, `scan-soul` printed SOUL-PROFILE-MISMATCH as a HIGH and
 * `explain SOUL-PROFILE-MISMATCH` answered "Unknown check ID" with exit 1.
 * The violation entries are built from the scanner's own catalog, so a new
 * violation class is explainable the day it ships.
 */
export const SOUL_SCAN_EXPLANATIONS: Record<string, string> = {
  'SOUL-PROFILE-MISMATCH': `Declared profile narrows scope past the body content. The SOUL.md declares a profile (a <!-- soul:profile=... --> marker, or --profile when the file has no marker) whose domain set skips governance domains the body itself calls for: its headings or tool mentions suggest a broader profile, and scan-soul does not evaluate the skipped domains under the declared one. Fix: remove the marker and let scan-soul detect the profile from the body, or revise the body to match the declared profile. Run: ${CLI_PREFIX} scan-soul <dir> to see the declared and inferred profiles, the body signals and the skipped domains.`,
  'SOUL-TIER-MISMATCH': `Declared tier narrows scope past the body content. The governance file declares a tier (a <!-- soul:tier=... --> marker, or --tier) below the tier its own text calls for, read from the file without its tier marker and without the sections harden-soul writes. A lower tier applies fewer controls and can leave whole domains out, so the score covers less of the file than it appears to; scan-soul reports it as HIGH and holds the score below the hardened band. Fix: set the marker to the tier the body suggests, or remove it. Run: ${CLI_PREFIX} scan-soul <dir> to see both tiers and what the declared tier left unevaluated.`,
  'SOUL-PROFILE-MARKER-INVALID': `Unrecognized profile declaration. A <!-- soul:profile=... --> marker (or a --profile flag) names a value that is not a recognized profile, is empty, or is malformed, so scan-soul ignored it and evaluated the file with the profile it detected from body keywords. Recognized profiles: ${Object.keys(PROFILE_DOMAINS).join(', ')}. Fix: replace the value with a recognized profile, or remove the marker and let scan-soul detect from the body. Run: ${CLI_PREFIX} scan-soul <dir> to see the attempted value and the profile used.`,
  // Printed on stderr as `SOUL-CONFORMANCE NONE: ...` on every text run
  // that misses a critical control; a user reads it as an id.
  'SOUL-CONFORMANCE': `Governance conformance level. scan-soul rates a governance file none, essential, standard or hardened: any critical control that applies to the file's tier and profile and is not detected holds it at none; standard needs every applicable high control and a score of 60 or more, and hardened needs every applicable control and a score of 75 or more; anything else is essential. SOUL-CONFORMANCE NONE names every missing critical control; run explain on each control id for the clause the scanner looks for. Fix: add the missing critical controls. Run: ${CLI_PREFIX} harden-soul <dir>, then ${CLI_PREFIX} scan-soul <dir> to re-check the level.`,
  // The bare family id leads the `SOUL-VIOLATION HIGH: ...` line --ci
  // writes to stderr; the line names the first per-class id (#863).
  'SOUL-VIOLATION': `Governance violations. A sentence in the governance file actively subverts a scan-soul control, rather than merely not implementing it. Under --ci, SOUL-VIOLATION HIGH counts the violations, names the first one's class id and line, and fails the run. Classes: ${VIOLATION_CATALOG.map((v) => v.id).join(', ')}; run explain on a class id for its fix. Fix: remove or rewrite each violating sentence. Run: ${CLI_PREFIX} scan-soul <dir> to see every violation with its line.`,
  ...Object.fromEntries(
    VIOLATION_CATALOG.map((v) => [
      v.id,
      `${v.name}. A sentence in the governance file actively subverts scan-soul control ${v.controlId} (${v.domain} domain), rather than merely not implementing it. Fix: ${v.fix} Run: ${CLI_PREFIX} scan-soul <dir> to see the sentence and its line.`,
    ]),
  ),
};

/** Map check ID prefixes to human-readable category labels. */
export const PREFIX_DESCRIPTIONS: Record<string, string> = {
  'CRED': 'credential exposure',
  'MCP': 'MCP server configuration',
  'SKILL': 'skill package security',
  'GOV': 'governance policy',
  'PERM': 'permission scope',
  'SOUL': 'behavioral governance (SOUL.md)',
  'PRIV': 'privacy and data handling',
  'DATA': 'data protection',
  'INJECT': 'prompt injection defense',
  'ATTEST': 'agent attestation',
  'SUPPLY': 'supply chain security',
  'NET': 'network security',
  'GIT': 'git repository hygiene',
  'PROMPT': 'prompt security',
  'NEMO': 'static analysis pattern',
  'LIFECYCLE': 'prompt assembly lifecycle',
  'AST': 'deep code analysis',
  'ENCRYPT': 'encryption and hashing',
  'LOG': 'logging and audit',
  'AUTH': 'authentication',
  'TOOL': 'tool permission and safety',
  'TEXT': 'free-text payload (scan-text)',
};

/**
 * The check inventory `explain` answers from: static explanations,
 * scan-soul findings, scan-soul governance controls, the check-definition
 * table, and every TAXONOMY_MAP key.
 */
export function getKnownExplainIds(): Set<string> {
  return new Set<string>([
    ...Object.keys(STATIC_EXPLANATIONS),
    ...Object.keys(SOUL_SCAN_EXPLANATIONS),
    ...CONTROL_DEFS.map((c) => c.id),
    ...Object.keys(CHECK_DEFINITIONS),
    ...Object.keys(getTaxonomyMap()),
  ]);
}

/** A description as a sentence: the table copies some without a full stop. */
function asSentence(text: string): string {
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

/**
 * The fix line for a definition, or, where no push site states a fix, a
 * line that says so and names the command that shows each finding with
 * its file and message. A remedy is never made up here.
 */
function fixLine(def: CheckDefinition): string {
  if (def.fix) return `Fix: ${def.fix}`;
  return def.deepOnly
    ? `No fix is recorded for this check. Run: ${CLI_PREFIX} secure <dir> --deep --verbose to see each finding under this id with its file and message.`
    : `No fix is recorded for this check. Run: ${CLI_PREFIX} secure <dir> --verbose to see each finding under this id with its file and message.`;
}

/** Why the check matters, where its findings say, then its fix line. */
function reasonAndFix(def: CheckDefinition): string[] {
  return def.why ? [`Why it matters: ${def.why}`, fixLine(def)] : [fixLine(def)];
}

/**
 * The lines `explain <id>` prints under its header, as plain text, or
 * undefined when no source here knows the id (the caller then falls back
 * to the attack-class line).
 *
 * A check in the check-definition table leads with its name, so the
 * `Explain:` pointer on a finding lands on the check that finding names.
 * A hand-written explanation or the scan-soul control follows when there is
 * one; otherwise the definition's description and the other names the id is
 * reported under. Every check in the table then ends with why it matters,
 * where its findings say, and its fix line.
 */
export function explainBody(checkId: string): string[] | undefined {
  const def = getCheckDefinition(checkId);
  // scan-soul's own findings (SOUL-PROFILE-MISMATCH, SOUL-VIOLATION-*)
  // render like the hand-written table (#760).
  const written = STATIC_EXPLANATIONS[checkId] ?? SOUL_SCAN_EXPLANATIONS[checkId];
  if (written) {
    if (!def) return [written];
    const named = written.toLowerCase().startsWith(def.name.toLowerCase());
    return [...(named ? [written] : [def.name, written]), '', ...reasonAndFix(def)];
  }

  // Governance catalog ids (SOUL-TH-001, SOUL-IH-003, …) carry the control
  // name and remediation; without this, `explain SOUL-IH-003` fell through
  // to the generic "behavioral governance finding" line (release-test P3).
  // The table holds every control, with the remediation as its fix.
  const control = CONTROL_DEFS.find((c) => c.id === checkId);
  if (control) {
    return [
      `${control.name} — ${control.domain} domain (scan-soul control ${control.id}).`,
      '',
      ...(def ? reasonAndFix(def) : []),
      `Run: ${CLI_PREFIX} harden-soul <dir> to add governance that satisfies this control.`,
    ];
  }

  if (!def) return undefined;
  const lines = [def.name, asSentence(def.description)];
  if (def.altNames && def.altNames.length > 0) {
    lines.push(`Also reported as: ${def.altNames.join('; ')}.`);
  }
  lines.push('', ...reasonAndFix(def));
  return lines;
}

/** True when `explain` has something real to say about `checkId`. */
export function isKnownExplainId(checkId: string): boolean {
  return getKnownExplainIds().has(checkId);
}

/** Classic Levenshtein distance; ids are short, the inventory is ~450. */
function editDistance(a: string, b: string): number {
  const prev = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cur = prev[j];
      prev[j] = Math.min(
        prev[j] + 1,
        prev[j - 1] + 1,
        diag + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      diag = cur;
    }
  }
  return prev[b.length];
}

/**
 * The nearest known check ids to an unknown one: ids sharing the family
 * prefix rank first (a NEMO-999 typo means a NEMO check), then
 * edit-distance neighbours, ties broken lexically for a stable message.
 */
export function suggestExplainIds(unknownId: string, limit = 3): string[] {
  const probe = unknownId.toUpperCase();
  const probeFamily = probe.split('-')[0];
  return [...getKnownExplainIds()]
    .map((id) => ({
      id,
      sameFamily: id.split('-')[0] === probeFamily ? 1 : 0,
      distance: editDistance(probe, id),
    }))
    .sort(
      (a, b) =>
        b.sameFamily - a.sameFamily ||
        a.distance - b.distance ||
        (a.id < b.id ? -1 : 1),
    )
    .slice(0, limit)
    .map((s) => s.id);
}
