/**
 * Structural tripwire (#601): a print in src/cli.ts that interpolates one of
 * the non-path finding/registry FIELD names must escape it on the printing
 * line — unless the line is on the allowlist below, which records (with a
 * verified source classification) that the value there is a tool-authored
 * constant or an already-sanitized analyst string, not raw bytes from a
 * scanned tree, a Registry/HTTP response, or an LLM.
 *
 * WHY A SEPARATE TRIPWIRE. The render-source gate (render-source.ts) keys on
 * PATH-NAMED expressions; a raw `${finding.description}` carrying an ESC byte
 * from a scanned artifact, or `${stub.name}` from a Registry response, is
 * invisible to it. A census on main found 34 field-interpolating prints; the
 * Registry `stubs` render (now escaped) was the one live hole, plus a dead
 * `displayRegistryResult` (now deleted). The analyst-channel prints are
 * stripped of control bytes once at their IPC boundary
 * (`shapeResultForTask` → `sanitizeAnalystString`, verified this session),
 * so they carry no per-line escape and are allowlisted with that reason.
 *
 * WHY EXACT-LINE, NOT BY object.field TOKEN. The receiver name `r` is
 * overloaded — `r.evidence` is an attack result, `r.impact`/`r.description`
 * are analyst output — so a token key would conflate distinct sources. The
 * line is the unambiguous key, at the cost that an EDIT to a listed line must
 * re-justify it here: the deliberate-edit contract, same as the exit-surface
 * baseline.
 *
 * SCOPE, stated honestly (as error-render-idiom.test.ts): the predicate is
 * line-based. A field copied into a local and printed on another line evades
 * it. It is a tripwire against the observed failure mode — a raw
 * `${obj.field}` inside a print call for one of these field names — so the
 * class cannot REGROW silently, not a taint analysis.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const src = readFileSync(path.join(__dirname, '..', '..', 'src', 'cli.ts'), 'utf8');
const lines = src.split('\n');

const PRINT = /console\.(log|error|warn)\(|process\.std(out|err)\.write\(/;
// The non-path fields a finding / registry / analyst object carries that can
// hold attacker-influenced bytes. These field names ALSO name authored
// constants throughout this file — hence the classified allowlist, not a ban.
const FIELD = /\$\{[^}]*\.(evidence|message|fix|guidance|description|impact|remediation|reason|value|attemptedValue|name|title)\b[^}]*\}/;
const ESCAPED = /escapeForDisplay\(|escapePathForDisplay\(|escapeForTerminal\(|sanitizeAnalystString\(/;

/**
 * Allowlisted print lines: trimmed source line → why its interpolated field
 * is safe without a per-line escape (a tool-authored constant, or an analyst
 * string already sanitized at its IPC boundary). Verified by the #601 source
 * classification; each entry is a claim reviewed as a gate change.
 */
const AUTHORED_ALLOW: ReadonlyArray<readonly [string, string]> = [
  ["console.log(`Publisher: @${result.publisher.name}`);", "authored: publisher parsed from the user CLI arg"],
  ["console.log(`└─ [!!] Revoked: ${result.revocation.reason}`);", "authored: hardcoded revocation reason string"],
  ["console.log(`  ${borderColor}│${RESET()} ${colors.cyan}${colors.bold}━━ ${explainer.title} ━━${RESET()} ${colors.dim}(shown once per scan)${RESET()}`);", "authored: CONCEPT_EXPLAINERS[].title catalog"],
  ["console.log(`  ${colors.bold}${colors.white}${block.header.name}${RESET()}${metaSuffix}`);", "authored: registry-only header name = user identifier"],
  ["console.log(`  ${colors.dim}${label}${RESET()}${paintCheckTone(line.tone, line.value)}`);", "authored: check meter/label/count lines (registry-only)"],
  ["console.log(`  ${colors.dim}${labelPad}${RESET()}${toneColor(line.tone)}${line.value}${RESET()}`);", "authored: surfaces/checks labels + counts + project kind enum"],
  ["console.log(`  ${' '.repeat(LABEL_WIDTH)}${colors.dim}${tag} — ${c.reason ?? 'not examined'}${RESET()}`);", "authored: coverage-ledger reasons (templates + skip strings)"],
  ["console.log(`  ${colors.dim}${labelPad}${RESET()}${color}${accent}${line.value}${RESET()}`);", "authored: categories/verdict labels + counts + kind"],
  ["if (r.impact) console.log(`  ${colors.yellow}Impact:${RESET()} ${r.impact}`);", "llm: analyst impact = sanitizeAnalystString(verdict) at the IPC boundary"],
  ["if (r.description) console.log(`  ${r.description}`);", "llm: analyst description = sanitized analysis (unreachable default branch aside)"],
  ["console.log(`     [-] ${ctrl.controlId}: ${ctrl.name}`);", "authored: OASB control.name"],
  ["console.log(`     [+] ${ctrl.controlId}: ${ctrl.name}`);", "authored: OASB control.name"],
  ["console.log(`     [?] ${ctrl.controlId}: ${ctrl.name} (${reason})`);", "authored: OASB control.name"],
  ["console.log(`  ${verifyIcon} [${finding.checkId}] ${location} - ${finding.name}`);", "authored: scanner check-def name"],
  ["console.log(`${risk.description}\\n`);", "authored: assessRiskLevel templates + counts"],
  ["console.log(`   ${finding.description}`);", "authored: openclaw check description constants"],
  ["console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);", "authored: scanner check-def name"],
  ["console.log(`  ${colors.green}✓${RESET()} [${finding.checkId}] ${finding.name}`);", "authored: scanner check-def name"],
  ["console.log(`${risk.description}\\n`);", "authored: assessNemoClawRiskLevel templates + counts"],
  ["console.log(`   ${finding.description}`);", "authored: nemoclaw check description constants (scanned bytes go to .message)"],
  ["console.log(`  ${colors.green}[ok]${RESET()} [${finding.checkId}] ${finding.name}`);", "authored: scanner check-def name"],
  ["console.log(`  ${icon} ${catInfo.name}: ${stats.successful}/${stats.total} successful`);", "authored: ATTACK_CATEGORIES[].name"],
  ["console.log(`  ${sevColor}[${r.payload.severity.toUpperCase()}]${RESET()} ${r.payload.id}: ${r.payload.name}`);", "authored: payload catalog / local --payloads file (user config, not a scan channel)"],
  ["console.log(`       Evidence: ${r.evidence}`);", "authored: analysis.evidence = pattern-match templates; raw target response is stored separately"],
  ["console.log(`       Remediation: ${r.payload.remediation}`);", "authored: payload catalog / local --payloads file remediation"],
  ["console.log(`  [+] ${r.payload.id}: ${r.payload.name}`);", "authored: payload catalog / local --payloads file name"],
  ["console.log(`  ${colors.brightRed}${colors.bold}HIGH${RESET()}  ${colors.bold}${v.id}${RESET()}  ${colors.dim}${v.name}${RESET()}`);", "authored: SoulViolation.name = VIOLATION_PATTERNS[].name"],
  ["console.log(`    ${colors.dim}${ctrl.id}:${RESET()} ${status}  ${colors.dim}${ctrl.name}${RESET()}`);", "authored: soul DomainResult control.name = CONTROL_DEFS"],
  ["console.log(`  ${label} ${colors.bold}${c.id}${RESET()}  ${colors.dim}${c.name} (${c.domain})${RESET()}`);", "authored: missingCritical name from CONTROL_DEFS"],
  ["console.log(`            ${colors.dim}${c.remediation}${RESET()}`);", "authored: CONTROL_DEFS remediation"],
  ["console.log(`  No agent was executed${result.evaluation.reason ? ` — ${result.evaluation.reason}` : ''}.`);", "authored: NOT_EXECUTED_REASON constant"],
  ["console.error(`  ${colors.dim}${l.label.padEnd(LABEL_WIDTH)}${RESET()}${paintNotFoundTone(l.tone, l.value)}`);", "authored: not-found meter lines (user arg, regex-constrained)"],
  ["console.error(`  ${paintNotFoundTone(l.tone, l.value)}`);", "authored: not-found meter lines (user arg, regex-constrained)"],
  ["process.stderr.write(`  Failed: ${check.name} -- ${check.reason}\\n`);", "authored: integrity check names are literals; reasons interpolate the tool own signed manifest"],
];
const ALLOW = new Map(AUTHORED_ALLOW);

const analystSrc = readFileSync(
  path.join(__dirname, '..', '..', 'src', 'nanomind-core', 'inference', 'security-analyst.ts'),
  'utf8',
);

describe('#601 field-interpolation render source (src/cli.ts)', () => {
  it('every print interpolating an attacker-channel field escapes it, or is an allowlisted authored/sanitized constant', () => {
    const offenders: string[] = [];
    lines.forEach((l) => {
      if (!PRINT.test(l)) return;
      if (!FIELD.test(l)) return;
      if (ESCAPED.test(l)) return;
      const key = l.trim();
      if (ALLOW.has(key)) return;
      offenders.push(key);
    });
    expect(
      offenders,
      'A print in src/cli.ts interpolates a finding/registry/analyst field with no display escape. If the value is ' +
        'bytes from a scanned tree, a Registry/HTTP response, or an unsanitized LLM string, wrap it in ' +
        'escapeForDisplay(...) on this line. If it is a tool-authored constant (or already sanitized at a boundary), ' +
        'add the trimmed line to AUTHORED_ALLOW with its source classification:\n\n' + offenders.join('\n'),
    ).toEqual([]);
  });

  it('the allowlist has no dead entries — every allowlisted line still exists verbatim', () => {
    const present = new Set(lines.map((l) => l.trim()));
    const dead = [...ALLOW.keys()].filter((k) => !present.has(k));
    expect(dead, 'allowlisted lines no longer in src/cli.ts (delete the stale entry): ' + dead.join(' | ')).toEqual([]);
  });

  it('the analyst boundary sanitizer still strips terminal control bytes', () => {
    // The analyst-block prints are allowlisted on the strength of THIS
    // function; if it stops stripping, they become live holes. Pin its
    // existence, its CSI + bare-ESC strips, and that it is applied at the
    // shaping boundary rather than merely defined.
    // Matched as literal source substrings (the file contains these exact
    // characters) rather than regexes-about-regexes, which are unreadable.
    expect(analystSrc.includes('function sanitizeAnalystString')).toBe(true);
    expect(analystSrc.includes('\\x1b\\['), 'CSI strip removed from sanitizeAnalystString').toBe(true);
    expect(analystSrc.includes('\\x00-\\x08'), 'C0 strip removed from sanitizeAnalystString').toBe(true);
    expect(analystSrc).toMatch(/=\s*sanitizeAnalystString\(response\.(analysis|verdict|evidence|remediation)\)/);
  });
});
