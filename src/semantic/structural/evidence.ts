/**
 * Evidence for the structural detectors (Layer 2).
 *
 * A detector that saw a specific line of a file records it here as positive
 * evidence: the 1-based line, the line as written, and why it is dangerous.
 * `toSecurityFinding` resolves a finding's line from that evidence, so the
 * finding renders `<file>:<N>` and a `Verify:` command.
 *
 * Which findings carry evidence
 * -----------------------------
 * POSITIVE findings point at text that is in the file, and carry positive
 * evidence:
 *   SEM-MCP-001 (overprivileged scope), SEM-MCP-002 (sandbox bypass),
 *   SEM-MCP-003 (secret in args), SEM-MCP-004 (wildcard), SEM-MCP-007
 *   (typosquatted package), SEM-MCP-008 (bootstrap script),
 *   SEM-PERM-001 (allow: ["*"]), SEM-PERM-003 (write outside the project),
 *   SEM-CRED-004 (secret in an MCP env block).
 *
 * ABSENCE and AGGREGATE findings have no single line to cite and are left
 * UNLOCATED on purpose, with no `line` and no `evidence`:
 *   SEM-MCP-005 and SEM-MCP-006 are properties of the whole set of servers
 *   (a capability chain across servers; a server count), SEM-INST-003 is the
 *   absence of security guidance anywhere in the file, SEM-INST-004 is the
 *   size of the whole file, and SEM-PERM-002 is reported for the absence of a
 *   restriction on the Bash grant. A line chosen for any of them would be a
 *   citation the reader cannot check against the finding.
 *
 * A detector never guesses: when it cannot say which line a finding is about,
 * it records no evidence, and the finding stays unlocated.
 */

import type { Evidence } from '../../types/finding-evidence';

/** The longest line recorded as evidence; a minified config can be one huge line. */
const MAX_EVIDENCE_CHARS = 500;

/**
 * The lines of the content last asked about. A file can carry thousands of
 * findings, and each would otherwise split the whole text again.
 */
let cachedContent: string | undefined;
let cachedLines: string[] = [];

function linesOf(content: string): string[] {
  if (cachedContent !== content) {
    cachedLines = content.split('\n');
    cachedContent = content;
  }
  return cachedLines;
}

/**
 * The text of 1-based `line` of `content`, with every occurrence of each of
 * `secrets` (as written, and as JSON-escaped) replaced by `[REDACTED]`.
 * Undefined when the line does not exist.
 */
function lineText(content: string, line: number, secrets: string[]): string | undefined {
  const lines = linesOf(content);
  if (!Number.isInteger(line) || line < 1 || line > lines.length) return undefined;
  let text = lines[line - 1];
  for (const secret of secrets) {
    if (!secret) continue;
    const escaped = JSON.stringify(secret).slice(1, -1);
    text = text.split(secret).join('[REDACTED]');
    if (escaped !== secret) text = text.split(escaped).join('[REDACTED]');
  }
  text = text.trim();
  return text.length > MAX_EVIDENCE_CHARS ? `${text.slice(0, MAX_EVIDENCE_CHARS)}…` : text;
}

/**
 * Positive evidence for `line` of `content`, or undefined when there is no
 * such line (the finding then stays unlocated). `secrets` are values that
 * must not reach the evidence: they are redacted out of the recorded line.
 */
export function positiveEvidenceAt(
  content: string,
  line: number | undefined,
  why: string,
  secrets: string[] = [],
): Evidence | undefined {
  if (line === undefined) return undefined;
  const text = lineText(content, line, secrets);
  if (text === undefined) return undefined;
  return { kind: 'positive', lines: [{ n: line, content: text, why }] };
}

/**
 * True when 1-based `line` of `content` holds `needle`: the check that a
 * located line is the line the detector meant before it is cited.
 */
export function lineHolds(content: string, line: number | undefined, needle: string): boolean {
  if (line === undefined || !needle) return false;
  const text = linesOf(content)[line - 1];
  if (text === undefined) return false;
  return text.includes(needle) || text.includes(JSON.stringify(needle).slice(1, -1));
}
