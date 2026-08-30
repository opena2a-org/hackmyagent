/**
 * The report side of out-of-tree link confinement.
 *
 * The guard lives in `tracked-fs.ts` and the channel on the `CoverageLedger`;
 * this module turns the ledger's `{rel, resolved, call}` records into what the
 * reader sees. A link the scan did not follow is a policy skip that is
 * announced, never a scan failure: it does not change the exit code, it is
 * not an unread input, and the disclosure carries the one thing the reader
 * needs next — the scan target that would include the file.
 */

import * as path from 'path';
import type { WithheldLink } from './coverage-ledger';
import type { WithheldLinkRecord } from './security-check';
import { citationTarget } from '../ui/shell-quote';
import { escapePathForDisplay } from '../ui/display-safe';

/**
 * The retarget instruction, in the operator's terms. "point the scan at" is
 * the phrase the README and CHANGELOG use for the same behaviour, and a drift
 * test holds all three to it.
 */
export function retargetInstruction(resolved: string, cliName: string): string {
  const parent = path.dirname(resolved);
  return `point the scan at ${escapePathForDisplay(parent)}: ${cliName} secure ${citationTarget(parent)}`;
}

/** Ledger records plus the retarget copy, deduped by `rel` (first wins). */
export function withheldLinkRecords(
  entries: readonly WithheldLink[],
  cliName: string,
  retarget: (resolved: string) => string = (r) => retargetInstruction(r, cliName),
): WithheldLinkRecord[] {
  const byRel = new Map<string, WithheldLinkRecord>();
  for (const e of entries) {
    if (byRel.has(e.rel)) continue;
    byRel.set(e.rel, { rel: e.rel, resolved: e.resolved, call: e.call, retarget: retarget(e.resolved) });
  }
  return [...byRel.values()];
}

/** Merge two record lists, deduped by `rel`, first list winning. */
export function mergeWithheldLinks(
  ...lists: ReadonlyArray<readonly WithheldLinkRecord[] | undefined>
): WithheldLinkRecord[] {
  const byRel = new Map<string, WithheldLinkRecord>();
  for (const list of lists) {
    for (const r of list ?? []) if (!byRel.has(r.rel)) byRel.set(r.rel, r);
  }
  return [...byRel.values()];
}

/**
 * The disclosure block, one line per link plus a heading. Paths come out of
 * the scanned tree and are escaped for display; the retarget command inside
 * each record is already citation-quoted.
 */
export function withheldLinkLines(records: readonly WithheldLinkRecord[]): string[] {
  if (records.length === 0) return [];
  const n = records.length;
  const lines = [
    `${n} link${n === 1 ? '' : 's'} inside the scanned tree resolve${n === 1 ? 's' : ''} outside it and ${n === 1 ? 'was' : 'were'} not read:`,
  ];
  for (const r of records) {
    lines.push(`  ${escapePathForDisplay(r.rel)} -> ${escapePathForDisplay(r.resolved)}`);
  }
  // One instruction per distinct target, not one per link: eight links into
  // one shared directory are one retarget.
  for (const retarget of new Set(records.map((r) => r.retarget))) {
    lines.push(`  To scan ${n === 1 ? 'it' : 'them'}, ${retarget}`);
  }
  return lines;
}
