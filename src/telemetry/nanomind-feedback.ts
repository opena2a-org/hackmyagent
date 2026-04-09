/**
 * NanoMind Classification Feedback
 *
 * Submits user corrections to the Registry's NanoMind feedback endpoint.
 * When a user disagrees with a classification (e.g., a benign skill
 * flagged as malicious), the correction is sent to improve future models.
 *
 * Endpoint:  POST api.oa2a.org/api/v1/nanomind/feedback
 *
 * This is Tier 2 data: it includes the artifact content for retraining.
 * Only submitted when the user explicitly provides a correction.
 *
 * Respects the same contribute.enabled opt-in as scan contributions.
 */

import { VERSION } from '../index.js';
import { isContributeEnabled } from './opt-in.js';

const REGISTRY_URL = 'https://api.oa2a.org';
const FEEDBACK_ENDPOINT = '/api/v1/nanomind/feedback';
const SUBMIT_TIMEOUT_MS = 5000;

export interface ClassificationFeedback {
  content: string;
  contentType: string;
  modelClassification: string;
  modelConfidence: number;
  correctedLabel: string | null;  // null = confirmed correct
  confirmed: boolean;             // true = user confirmed classification is correct
  modelVersion: string;
}

/**
 * Submit a single correction to the Registry.
 * Called when a user disagrees with a NanoMind classification.
 *
 * @param feedback - The correction details
 * @param registryUrl - Override Registry URL (for testing)
 * @param verbose - Log submission status to stderr
 * @returns true if submission succeeded
 */
export async function submitFeedback(
  feedback: ClassificationFeedback,
  registryUrl?: string,
  verbose?: boolean,
): Promise<boolean> {
  if (!isContributeEnabled()) {
    if (verbose) {
      process.stderr.write('NanoMind feedback: skipped (contribute not enabled)\n');
    }
    return false;
  }

  const url = (registryUrl || REGISTRY_URL) + FEEDBACK_ENDPOINT;

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        toolId: `hackmyagent@${VERSION}`,
        feedback: [{
          content: feedback.content,
          contentType: feedback.contentType,
          modelClassification: feedback.modelClassification,
          modelConfidence: feedback.modelConfidence,
          correctedLabel: feedback.correctedLabel,
          confirmed: feedback.confirmed,
          modelVersion: feedback.modelVersion,
          toolId: `hackmyagent@${VERSION}`,
          timestamp: new Date().toISOString(),
        }],
      }),
      signal: AbortSignal.timeout(SUBMIT_TIMEOUT_MS),
    });

    if (verbose) {
      const body = await resp.json().catch(() => ({}));
      process.stderr.write(
        `NanoMind feedback: ${resp.status} (${(body as Record<string, unknown>).accepted ?? 0} accepted)\n`,
      );
    }

    return resp.ok;
  } catch {
    if (verbose) {
      process.stderr.write('NanoMind feedback: submission failed (network error)\n');
    }
    return false;
  }
}

/**
 * Confirm that a classification is correct (positive feedback).
 * This is just as valuable as corrections for training data quality.
 */
export async function confirmClassification(
  content: string,
  contentType: string,
  classification: string,
  confidence: number,
  modelVersion: string,
  registryUrl?: string,
): Promise<boolean> {
  return submitFeedback({
    content,
    contentType,
    modelClassification: classification,
    modelConfidence: confidence,
    correctedLabel: null,
    confirmed: true,
    modelVersion,
  }, registryUrl);
}

/**
 * Correct a misclassification (negative feedback).
 */
export async function correctClassification(
  content: string,
  contentType: string,
  originalClassification: string,
  originalConfidence: number,
  correctedLabel: string,
  modelVersion: string,
  registryUrl?: string,
): Promise<boolean> {
  return submitFeedback({
    content,
    contentType,
    modelClassification: originalClassification,
    modelConfidence: originalConfidence,
    correctedLabel,
    confirmed: false,
    modelVersion,
  }, registryUrl);
}
