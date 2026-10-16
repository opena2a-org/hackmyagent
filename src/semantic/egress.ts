/**
 * What deep analysis sends off this machine, and what it never sends.
 *
 * One module, so every outbound path answers the question the same way: the
 * Layer 3 request (`LLMAnalyzer`), the `hackmyagent_deep_scan` MCP result, the
 * `scan-soul --deep` coverage request and the behavioural simulation's walk.
 *
 * Three rules, applied where each request or result is built:
 *
 *  1. Env files and config files are never sent. Their purpose is to hold
 *     values, so a model can only judge them by reading the values. Layers 1
 *     and 2 examine them on this machine, and Layer 3 records each one on the
 *     coverage ledger as withheld by design.
 *  2. Every file that is sent passes through `redactTargetArtifact` first, the
 *     same redaction the behavioural simulation and `attack` apply. It
 *     replaces the credential values it recognises with a marker that says a
 *     value was removed and carries none of it. Content over the redaction's
 *     size limit becomes the withheld marker alone, and is not sent.
 *  3. A run that sends anything writes one line to stderr first, naming the
 *     host, the variable that enabled it, the number of files and requests, and
 *     how to send nothing.
 *
 * Lives outside `semantic/llm/` and `semantic/structural/` on purpose: both
 * the MCP result and the simulation use it, and the structural layer and the
 * LLM layer share no import edge (`structural-boundary.test.ts`).
 */

import type { AnalysisFile, FileType } from './types';
import { redactTargetArtifact } from '../attack-engine/target-reader';
import { MAX_REDACTION_INPUT_BYTES } from '../nanomind-core/security/defense-in-depth';

/** The one host deep analysis sends to. `AnthropicClient` takes no other base URL from a caller. */
export const PROVIDER_HOST = 'api.anthropic.com';

/** The variable whose presence turns the provider path on. */
export const PROVIDER_KEY_VARIABLE = 'ANTHROPIC_API_KEY';

/**
 * The file kinds deep analysis sends: agent instructions, MCP configs and
 * Claude settings. An allowlist, so a kind added to discovery later is
 * withheld until someone decides it may leave the machine.
 */
const SENT_FILE_TYPES: ReadonlySet<FileType> = new Set<FileType>([
  'agent_instructions',
  'mcp_config',
  'claude_settings',
]);

/** Why an env or config file was not sent. Recorded on the coverage ledger and in the MCP result. */
export const WITHHELD_BY_DESIGN_REASON =
  'withheld from Layer 3 by design: env and config files never leave this machine. Layers 1 and 2 examined it locally.';

/** Whether deep analysis may send a file of this kind at all. */
export function isSentFileType(type: FileType): boolean {
  return SENT_FILE_TYPES.has(type);
}

export interface WithheldFile {
  path: string;
  type: FileType;
  reason: string;
}

/** Split discovered files into the ones deep analysis may send and the ones it withholds by design. */
export function partitionForEgress(files: readonly AnalysisFile[]): { send: AnalysisFile[]; withheld: WithheldFile[] } {
  const send: AnalysisFile[] = [];
  const withheld: WithheldFile[] = [];
  for (const file of files) {
    if (isSentFileType(file.type)) send.push(file);
    else withheld.push({ path: file.path, type: file.type, reason: WITHHELD_BY_DESIGN_REASON });
  }
  return { send, withheld };
}

/**
 * The text of a file as it may leave the machine.
 *
 * `overLimit` is true when the content is larger than the redaction reads, in
 * which case `text` is the withheld marker alone. A caller sends nothing for
 * such a file and reports it as not analysed: sending the marker would return a
 * clean answer about a file no model saw.
 */
export function redactForEgress(content: string): { text: string; overLimit: boolean } {
  const overLimit = Buffer.byteLength(content, 'utf-8') > MAX_REDACTION_INPUT_BYTES;
  return { text: redactTargetArtifact(content).text, overLimit };
}

/** Why a file over the redaction's size limit was not sent. */
export const OVER_REDACTION_LIMIT_REASON =
  `it is over the ${MAX_REDACTION_INPUT_BYTES}-byte limit the credential redaction reads, so it was not sent`;

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

/**
 * The line a run writes to stderr before its first provider request.
 *
 * `label` names the stage (`[Deep analysis]`, `[Simulation]`), `files` the
 * number of distinct files sent and `requests` the number of requests that will
 * carry them, which is the number made unless the run stops early. `stop` says
 * how to run the same command without sending anything.
 */
export function providerSendNotice(label: string, files: number, requests: number, stop: string): string {
  return `${label} Sending ${plural(files, 'file')} to ${PROVIDER_HOST} in ${plural(requests, 'request')}, `
    + `because ${PROVIDER_KEY_VARIABLE} is set. Credential values are removed before sending, and .env and config `
    + `files are never sent. ${stop}`;
}

/** How to run `secure` without sending anything. */
export const SECURE_STOP_SENDING =
  `To send nothing, run without --deep and --scan-depth deep, or prefix the command with env -u ${PROVIDER_KEY_VARIABLE}.`;

/** How to run `scan-soul` without sending anything. */
export const SCAN_SOUL_STOP_SENDING =
  `To send nothing, run scan-soul without --deep, or prefix the command with env -u ${PROVIDER_KEY_VARIABLE}.`;

/**
 * Write the notice to stderr. Not to the progress callback: progress is shown
 * in text output only, and this line is written in every output format, beside
 * whatever stdout carries.
 */
export function announceProviderSend(line: string): void {
  process.stderr.write(line + '\n');
}
