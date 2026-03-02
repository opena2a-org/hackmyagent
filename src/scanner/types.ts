/**
 * External scanner types
 */

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ExternalFinding {
  id: string;
  checkId: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  port?: number;
  path?: string;
  evidence: string;
  impact: string;
  fix: string;
}

export interface ExternalScanResult {
  id: string;
  target: string;
  score: number;
  grade: string;
  findings: ExternalFinding[];
  duration: number;
  timestamp: Date;
  openPorts: number[];
}

export interface ScannerOptions {
  timeout?: number;
  ports?: number[];
  skipPortScan?: boolean;
}
