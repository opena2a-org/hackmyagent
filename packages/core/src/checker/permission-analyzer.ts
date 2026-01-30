/**
 * Permission analyzer
 * Analyzes skill permissions and categorizes them by risk level
 */

export interface PermissionAnalysis {
  safe: string[];
  dangerous: string[];
  reviewNeeded: string[];
  riskScore: number;
}

// Permissions that are always safe (read-only, limited scope)
const SAFE_PERMISSIONS = new Set([
  'messages:read',
  'config:read',
  'storage:local',
]);

// Patterns that indicate dangerous permissions
const DANGEROUS_PATTERNS = [
  /^shell:/,           // Any shell access
  /^filesystem:\*$/,   // Wildcard filesystem
  /^filesystem:\/$/,   // Root filesystem
  /^filesystem:~$/,    // Home directory (broad)
  /^network:\*$/,      // Wildcard network
  /^mcp:\*$/,          // Wildcard MCP
];

// Patterns that need review (scoped but still sensitive)
const REVIEW_PATTERNS = [
  /^filesystem:~\/.+/, // Scoped home directory paths
  /^network:[^*]+$/,   // Specific network hosts
  /^mcp:[^*]+$/,       // Specific MCP servers
];

export function analyzePermissions(permissions: string[]): PermissionAnalysis {
  const safe: string[] = [];
  const dangerous: string[] = [];
  const reviewNeeded: string[] = [];

  for (const permission of permissions) {
    if (SAFE_PERMISSIONS.has(permission)) {
      safe.push(permission);
      continue;
    }

    const isDangerous = DANGEROUS_PATTERNS.some((pattern) => pattern.test(permission));
    if (isDangerous) {
      dangerous.push(permission);
      continue;
    }

    const needsReview = REVIEW_PATTERNS.some((pattern) => pattern.test(permission));
    if (needsReview) {
      reviewNeeded.push(permission);
      continue;
    }

    // Default: if not recognized, mark as needing review
    reviewNeeded.push(permission);
  }

  // Calculate risk score (0-100)
  const riskScore = calculateRiskScore(safe, dangerous, reviewNeeded);

  return {
    safe,
    dangerous,
    reviewNeeded,
    riskScore,
  };
}

function calculateRiskScore(
  safe: string[],
  dangerous: string[],
  reviewNeeded: string[]
): number {
  if (safe.length === 0 && dangerous.length === 0 && reviewNeeded.length === 0) {
    return 0;
  }

  // Weights for each category
  const SAFE_WEIGHT = 5;
  const REVIEW_WEIGHT = 25;
  const DANGEROUS_WEIGHT = 50;

  const totalPermissions = safe.length + dangerous.length + reviewNeeded.length;
  const weightedSum =
    safe.length * SAFE_WEIGHT +
    reviewNeeded.length * REVIEW_WEIGHT +
    dangerous.length * DANGEROUS_WEIGHT;

  // Normalize to 0-100, with a minimum based on dangerous permissions
  const baseScore = Math.min(100, (weightedSum / totalPermissions));

  // If any dangerous permissions, ensure minimum score of 71
  if (dangerous.length > 0) {
    return Math.max(71, baseScore);
  }

  // If only review-needed, ensure minimum score of 31
  if (reviewNeeded.length > 0 && safe.length === 0) {
    return Math.max(31, baseScore);
  }

  return baseScore;
}
