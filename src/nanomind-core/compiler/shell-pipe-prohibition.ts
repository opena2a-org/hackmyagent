/**
 * AST-HEARTBEAT-001, "download piped into a shell": which occurrences a line
 * forbids.
 *
 * The finding is made whenever the pattern is in the text. This module never
 * removes one. It only decides, per occurrence, whether a prohibition governs
 * that very command, in which case the finding is reported as informational
 * and says the line forbids the pattern. Every other occurrence stays critical.
 *
 * "Governs that very command" is decided narrowly, from the text directly
 * before the command on the same line:
 *
 *   - a negator (never, do not, don't, must not, mustn't, should not,
 *     shouldn't, cannot, can't, no, avoid, refuse to, forbidden to,
 *     prohibited from), optionally followed by a verb it negates (run,
 *     execute, pipe, use, do, invoke, curl, wget, download, or their -ing
 *     forms) and then at most three words from a short list of plain words;
 *     or "not" directly before one of those verbs;
 *   - nothing else between them and the command: no comma, colon, dash,
 *     conjunction (and, but, then, so, just, instead, unless, except, ...) and
 *     no second verb, because only the listed plain words may stand there;
 *   - the sentence is not a question, and nothing before the negator in the
 *     same sentence makes it a conditional ("if ... isn't ...",
 *     "when ... not ...").
 *
 * A negator that governs another verb, one before a comma or conjunction, one
 * on the previous line, or one after the command lowers nothing.
 */

/** The surface raised when every occurrence is forbidden by its own line. */
export const SHELL_PIPE_FORBIDDEN_SURFACE = 'Shell pipe execution forbidden by its line';

/** One "download piped into a shell" occurrence in the content. */
export interface ShellPipeOccurrence {
  /** Offset of the command (`curl` / `wget`) in the content. */
  index: number;
  /** The occurrence, verbatim: from the command to the shell it pipes into. */
  text: string;
  /** True when a prohibition on its own line governs this very command. */
  forbidden: boolean;
}

/**
 * The pattern AST-HEARTBEAT-001 has always matched. It decides WHETHER there is
 * a finding; nothing in this module can make it not fire.
 */
const SHELL_PIPE_PATTERN = /curl\s+.*\|\s*(ba)?sh|wget\s+.*\|\s*(ba)?sh/i;

/**
 * One occurrence each: the command nearest the shell it pipes into, so that a
 * second command on the same line is its own occurrence and is judged by the
 * text directly before it, not by a prohibition in front of the first.
 */
const SHELL_PIPE_OCCURRENCE =
  /(?:curl|wget)\s+(?:(?!\b(?:curl|wget)\s).)*?\|\s*(?:ba)?sh/giu;

const NEGATOR =
  "never|do\\s+not|don['’]t|must\\s+not|mustn['’]t|should\\s+not|shouldn['’]t|cannot|can\\s+not|can['’]t|no|avoid|refuse\\s+to|forbidden\\s+to|prohibited\\s+from";

const VERB =
  'run|running|execute|executing|pipe|piping|use|using|do|doing|invoke|invoking|curl|curling|wget|download|downloading';

/**
 * The only words that may stand between the negated verb and the command.
 * An allow-list, so a second verb or a conjunction can never pass as "plain".
 */
const PLAIN_WORD =
  'a|an|the|any|this|that|these|those|such|as|like|something|anything|command|commands|script|scripts|installer|installers|snippet|snippets|line|lines|code|pattern|patterns|untrusted|unverified|unknown|remote|arbitrary|random|external|downloaded|shell|install|setup';

/** Markdown emphasis right after a word (`**Never** run`) is not punctuation. */
const EMPHASIS = '[*_]{0,2}';

/**
 * The prohibition, anchored at the end of the text before the command. Read
 * the alternatives as: NEGATOR [VERB [PLAIN{0,3}]] or not VERB [PLAIN{0,3}],
 * then an optional opening quote or backtick, then the command.
 */
const PROHIBITION_BEFORE_COMMAND = new RegExp(
  `(?:^|[^\\p{L}\\p{N}'’])` +
    `(?:(?:${NEGATOR})${EMPHASIS}\\s+(?:(?:${VERB})${EMPHASIS}\\s+(?:(?:${PLAIN_WORD})\\s+){0,3})?` +
    `|not\\s+(?:${VERB})${EMPHASIS}\\s+(?:(?:${PLAIN_WORD})\\s+){0,3})` +
    `[\`"'“‘]?$`,
  'iu',
);

/** A word that makes the sentence before the negator a condition. */
const CONDITIONAL = /\b(?:if|when|whenever|unless|until|while|once|whether|in\s+case)\b/i;

/** The end of the sentence before an offset: a stop, then space. */
const SENTENCE_BREAK = /[.!?](?:\s|$)/g;

/**
 * Whether a prohibition on its own line governs the command at
 * `[index, index + length)` of `content`.
 */
export function isForbiddenByItsLine(content: string, index: number, length: number): boolean {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const nextNewline = content.indexOf('\n', index + length);
  const lineEnd = nextNewline === -1 ? content.length : nextNewline;

  const before = content.slice(lineStart, index);
  const prohibition = PROHIBITION_BEFORE_COMMAND.exec(before);
  if (!prohibition) return false;

  // The sentence the negator stands in, up to the negator: a conditional
  // there ("If node isn't installed ...") lowers nothing.
  const upToNegator = before.slice(0, prohibition.index);
  let sentenceStart = 0;
  for (const stop of upToNegator.matchAll(SENTENCE_BREAK)) {
    sentenceStart = stop.index + stop[0].length;
  }
  if (CONDITIONAL.test(upToNegator.slice(sentenceStart))) return false;

  // A question lowers nothing: the rest of the sentence after the command.
  const after = content.slice(index + length, lineEnd);
  const sentenceEnd = /[.!](?:\s|$)/.exec(after);
  const restOfSentence = sentenceEnd ? after.slice(0, sentenceEnd.index) : after;
  if (restOfSentence.includes('?')) return false;

  return true;
}

/**
 * Every occurrence of the pattern, each with whether its own line forbids it.
 *
 * Non-empty whenever {@link SHELL_PIPE_PATTERN} matches: if the per-occurrence
 * split finds nothing the pattern found, the pattern's own match is returned as
 * an occurrence no prohibition governs.
 */
export function findShellPipeOccurrences(content: string): ShellPipeOccurrence[] {
  const fallback = SHELL_PIPE_PATTERN.exec(content);
  if (!fallback) return [];

  const occurrences: ShellPipeOccurrence[] = [];
  for (const match of content.matchAll(SHELL_PIPE_OCCURRENCE)) {
    occurrences.push({
      index: match.index,
      text: match[0],
      forbidden: isForbiddenByItsLine(content, match.index, match[0].length),
    });
  }
  if (occurrences.length === 0) {
    occurrences.push({ index: fallback.index, text: fallback[0], forbidden: false });
  }
  return occurrences;
}
