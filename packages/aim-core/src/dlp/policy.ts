import type { DLPPolicy, DLPPattern } from './types';

/** Default DLP policy: mask credentials and PII, allow infrastructure */
const DEFAULT_DLP_POLICY: DLPPolicy = {
  enabled: true,
  defaultAction: 'mask',
  categories: {
    credential: 'block',
    pii: 'mask',
    financial: 'mask',
    infrastructure: 'allow',
  },
};

/**
 * Determine the DLP action for a matched pattern.
 * Priority: per-pattern override > per-category override > default action.
 */
export function getDLPAction(
  pattern: DLPPattern,
  dlpPolicy?: DLPPolicy,
): 'allow' | 'mask' | 'block' {
  const policy = dlpPolicy ?? DEFAULT_DLP_POLICY;

  if (!policy.enabled) return 'allow';

  // Per-pattern override
  if (policy.patterns?.[pattern.id]) {
    return policy.patterns[pattern.id];
  }

  // Per-category override
  const categoryAction = policy.categories?.[pattern.category];
  if (categoryAction) {
    return categoryAction;
  }

  return policy.defaultAction;
}

/** Create a default DLP policy */
export function defaultDLPPolicy(): DLPPolicy {
  return { ...DEFAULT_DLP_POLICY };
}
