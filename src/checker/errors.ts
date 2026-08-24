/**
 * Errors whose message text is DEVELOPER-AUTHORED, so its line structure is
 * trusted and the CLI catch sites may render it across real lines (#523).
 */

import { escapeForDisplay } from '../ui/display-safe';

/**
 * A usage/guidance error: multi-line help text written by us, not derived from
 * scanned trees, argv, or the environment.
 *
 * Trust is a property of the construction site, not the type (#324/#334): every
 * value interpolated into the message must be display-escaped at interpolation
 * time, so an embedded newline in argv or env cannot become a line boundary.
 * Build instances with the `usageError` tagged template, which does that
 * escaping for every interpolated value. The constructor additionally escapes
 * each authored line — idempotent on text `usageError` produced — so a hazard
 * that slips into a literal still renders visibly instead of steering the
 * terminal.
 *
 * Never construct one from another error's `message`, a `cause` chain, or any
 * text that concatenated bytes from a scanned artifact: wrapping does not
 * launder trust, and the catch sites will render every line of this message as
 * our own.
 */
export class UsageError extends Error {
  constructor(message: string) {
    super(message.split('\n').map(escapeForDisplay).join('\n'));
    this.name = 'UsageError';
  }
}

/**
 * Tagged template for `UsageError`: authored literals keep their line
 * structure; every interpolated value is display-escaped, so it cannot add,
 * split, or forge a line.
 */
export function usageError(strings: TemplateStringsArray, ...values: unknown[]): UsageError {
  let text = strings[0];
  for (let i = 0; i < values.length; i++) {
    text += escapeForDisplay(String(values[i])) + strings[i + 1];
  }
  return new UsageError(text);
}
