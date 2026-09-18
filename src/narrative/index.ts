/**
 * @internal — entry point for the package-narrative emission pipeline.
 *
 * Re-exports the public surface used by `secure --publish` and tests.
 *
 * Design brief: rich check context for skills and MCP, v1
 */
export {
  buildSkillNarrative,
  SKILL_THREAT_MODEL_QUESTIONS,
  type BuildSkillNarrativeInput,
} from "./skill-narrative.js";
export {
  buildMcpNarrative,
  MCP_THREAT_MODEL_QUESTIONS,
  type BuildMcpNarrativeInput,
  type McpToolRegistration,
} from "./mcp-narrative.js";
export {
  generateNarrativeSummary,
  isAcceptedByInputClassifier,
  emptyResult,
  type NarrativeSummaryOptions,
  type NarrativeSummaryResult,
} from "./narrative-summary.js";
export {
  buildPackageNarrative,
  type BuildPackageNarrativeInput,
} from "./build-narrative.js";
export {
  publishNarrative,
  narrativeToRequestBody,
  type PublishNarrativeOptions,
  type PublishNarrativeRequest,
  type PublishNarrativeResult,
} from "./publish-narrative.js";
