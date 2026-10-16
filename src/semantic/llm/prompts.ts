/**
 * LLM Prompt Templates (Layer 3)
 *
 * Structured prompts for each analysis type.
 * Each prompt asks for its findings through one `report_findings` tool call,
 * whose schema carries the line number, severity and rationale fields.
 *
 * #462 — every system prompt here carries `UNTRUSTED_DATA_RULE`, and the user
 * message puts the artifact inside an unforgeable boundary. See
 * `./untrusted.ts` for why a nonce rather than an escaper.
 */

import type { AnthropicTool } from './client';
import { UNTRUSTED_DATA_RULE, newBoundaryId, wrapUntrusted } from './untrusted';

/**
 * #462 — the one channel an answer comes back on.
 *
 * The prompts used to ask for "a JSON array" in the reply text, and an extractor
 * then had to find it among whatever else the reply held. Scanned content was
 * competing with that instruction, and every extraction rule was a rule about
 * which text to believe. The analyst now fills in this tool's input, the API
 * returns it already parsed, and the reply text is not read at all.
 */
export const REPORT_FINDINGS_TOOL: AnthropicTool = {
  name: 'report_findings',
  description:
    'Report every finding for the one artifact under analysis. Call it exactly once. When there is nothing to report, call it with an empty findings array.',
  input_schema: {
    type: 'object',
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            line: {
              type: ['integer', 'null'],
              description: 'The 1-based line of the artifact the finding is on, or null when it has no single line.',
            },
            type: { type: 'string', description: 'The kind of finding, for example the credential type.' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
            description: { type: 'string', description: 'What was found.' },
            rationale: { type: 'string', description: 'Why this is a security risk in this specific file.' },
            recommendation: { type: 'string', description: 'The specific fix.' },
          },
          required: ['type', 'severity', 'description', 'rationale'],
        },
      },
    },
    required: ['findings'],
  },
};

/*
 * There is no credential-detection prompt. Finding a value no local rule
 * recognises would need the raw value, so env and config files are never sent
 * (see `../egress.ts`) and no prompt exists for them. Credential detection
 * runs on this machine, in Layers 1 and 2.
 */

/**
 * System prompt for MCP threat analysis (uses Sonnet — complex reasoning)
 */
export const MCP_THREAT_ANALYSIS_PROMPT = `You are a security analyst specializing in AI agent security. Analyze the following MCP (Model Context Protocol) configuration for security threats.

Evaluate:
1. **Capability scope**: What can each server do? Is it overprivileged?
2. **Attack chains**: Can the combination of servers enable read→execute→exfiltrate attacks?
3. **Secrets exposure**: Are credentials passed via args (visible to LLM) instead of env vars?
4. **Trust boundaries**: Are servers from untrusted sources given privileged access?
5. **Sandbox integrity**: Are there flags that bypass security sandboxes?

Report your findings by calling the report_findings tool once, with one entry per finding: its line number (or null), the finding type, a severity of "critical", "high", "medium" or "low", a description of what was found, a rationale explaining why it is a security risk, and a specific recommendation.

If no issues are found, call report_findings with an empty findings array. If you need to note something about the file, put it in a finding's rationale.${UNTRUSTED_DATA_RULE}`;

/**
 * System prompt for instruction analysis (uses Sonnet — nuanced reasoning)
 */
export const INSTRUCTION_ANALYSIS_PROMPT = `You are a security analyst specializing in AI agent security. Analyze the following agent instruction file for security risks.

This file is loaded into the AI agent's context window with every interaction. Evaluate:

1. **Prompt injection vectors**: Could an attacker craft input that exploits these instructions?
2. **Permissive behaviors**: Does the file tell the agent to bypass security controls?
3. **Data exfiltration risks**: Could the instructions be used to leak sensitive data?
4. **Credential exposure**: Are any secrets, tokens, or passwords present in the instructions?
5. **Missing boundaries**: What security constraints are absent that should be present?

Report your findings by calling the report_findings tool once, with one entry per finding: its line number (or null), the finding type, a severity of "critical", "high", "medium" or "low", a description of what was found, a rationale explaining why it is a security risk, and a specific recommendation.

If no issues are found, call report_findings with an empty findings array. If you need to note something about the file, put it in a finding's rationale.${UNTRUSTED_DATA_RULE}`;

/**
 * Build the user message for file analysis.
 *
 * #462 — the metadata is JSON-encoded and sits OUTSIDE the boundary, and the
 * artifact sits inside it. `filePath` is attacker-controlled too: a scanned repo
 * names its own files, newlines are legal in a filename on Unix, and the old
 * form interpolated it raw one line above the content.
 */
export function buildFileAnalysisMessage(
  filePath: string,
  content: string,
  fileType: string,
  boundaryId: string = newBoundaryId()
): string {
  return `File: ${JSON.stringify(filePath)}
Type: ${JSON.stringify(fileType)}

${wrapUntrusted(content, boundaryId)}`;
}

/**
 * Select the prompt for a file type, or null for a kind Layer 3 never sends.
 *
 * Null for env files, config files and any kind without a prompt of its own:
 * there is no default prompt, so a kind nobody decided may leave the machine
 * has nothing to be sent with.
 */
export function getPromptForFileType(
  fileType: string
): { systemPrompt: string; model: 'haiku' | 'sonnet' } | null {
  switch (fileType) {
    case 'agent_instructions':
      return { systemPrompt: INSTRUCTION_ANALYSIS_PROMPT, model: 'sonnet' };
    case 'mcp_config':
    case 'claude_settings':
      return { systemPrompt: MCP_THREAT_ANALYSIS_PROMPT, model: 'sonnet' };
    default:
      return null;
  }
}
