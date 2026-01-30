/**
 * Security check types and interfaces
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityCheck {
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  /** Function to detect if the issue exists */
  detect: () => Promise<CheckResult>;
  /** Function to fix the issue (if auto-fixable) */
  fix?: () => Promise<FixResult>;
}

export interface CheckResult {
  passed: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface FixResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface SecurityFinding {
  checkId: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  passed: boolean;
  message: string;
  fixable: boolean;
  fixed?: boolean;
  fixMessage?: string;
  details?: Record<string, unknown>;
}

export interface ScanResult {
  timestamp: Date;
  platform: string;
  findings: SecurityFinding[];
  score: number;
  maxScore: number;
  /** Path to backup directory (only set when autoFix is true) */
  backupPath?: string;
}
