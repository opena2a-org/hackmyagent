/**
 * Telemetry module -- community contribution of anonymized scan findings.
 */

export {
  generateContributorToken,
  buildContributionPayload,
  buildContributionPayloadFromDir,
  submitContribution,
  type ContributionFinding,
  type ContributionPayload,
  type ContributionResult,
} from './contribute';

export {
  isContributeEnabled,
  shouldPromptContribute,
  incrementScanCount,
  saveContributeChoice,
  showContributePrompt,
} from './opt-in';
