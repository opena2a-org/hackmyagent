/**
 * Method-scope disclosure for `scan-soul` (#251), and its `--deep` variant
 * (#260).
 *
 * Coverage at the keyword tier is template conformance, not a semantic
 * evaluation of prose, so a scan that finds controls "not detected" has to
 * say which method it used and hand over the escape hatch:
 *
 *   Keyword conformance scan — controls implemented as prose may not be
 *   detected. Semantic pass: hackmyagent scan-soul <dir> --deep
 *
 * #260: a `--deep` run re-printed that line verbatim — the escape hatch
 * suggesting itself while already running. Anyone following the pointer had
 * already followed it. Once the semantic pass has run, the disclosure has to
 * report what it found and hand over a next step that has not been spent.
 */

export interface SoulScopeDisclosureInput {
  /** Controls still undetected after every tier that ran. */
  missing: number;
  /** True when `--deep` was requested. */
  deep: boolean;
  /**
   * False when `--deep` was requested but no LLM backend was reachable. The
   * pointer stays valid in that case: the pass did not run, so it has not
   * been spent.
   */
  deepAvailable: boolean;
  /** Controls the semantic pass recovered. Only meaningful when it ran. */
  upgraded: number;
  /** CLI prefix (`hackmyagent`, or the parent CLI when bundled). */
  prefix: string;
  /** Target directory as the user typed it. */
  directory: string;
}

/**
 * Build the disclosure lines. Returns one or two lines, already plain text —
 * the caller paints them, since HMA and its wrappers use different palettes.
 */
export function soulScopeDisclosureLines(input: SoulScopeDisclosureInput): string[] {
  const { missing, deep, deepAvailable, upgraded, prefix, directory } = input;

  if (deep && deepAvailable) {
    // The semantic pass ran. Report it, then hand over a next step that is
    // still available — pointing at --deep again would imply a recovery path
    // the user has already exhausted.
    return [
      `Keyword + semantic scan — ${upgraded} control${upgraded === 1 ? '' : 's'} recovered by the semantic pass; ` +
        `the remaining ${missing} were recognised by neither tier.`,
      `Prose that implements a control may still go undetected. ` +
        `Add the control's section heading, or run ${prefix} harden-soul ${directory}.`,
    ];
  }

  if (deep) {
    // Requested but no backend. The pass has not been spent, so the pointer
    // is still the right advice — but do not imply it ran.
    return [
      'Keyword conformance scan — controls implemented as prose may not be detected. ' +
        'The semantic pass could not run (see below).',
    ];
  }

  return [
    'Keyword conformance scan — controls implemented as prose may not be detected. ' +
      `Semantic pass: ${prefix} scan-soul ${directory} --deep`,
  ];
}
