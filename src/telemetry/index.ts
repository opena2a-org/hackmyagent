/**
 * Telemetry module -- community contribution of anonymized scan findings.
 */

export {
  getContributorToken,
  generateContributorToken,
  buildScanEvent,
  buildContributionPayloadFromDir,
  queueEvent,
  queueAndMaybeFlush,
  flushQueue,
  submitContribution,
  type ContributionEvent,
  type ContributionBatch,
} from './contribute';

export {
  isContributeEnabled,
  shouldPromptContribute,
  incrementScanCount,
  saveContributeChoice,
  showContributePrompt,
  recordScanAndMaybeShowTip,
  migrateLegacyContributeChoice,
  _resetBackend,
} from './opt-in';
