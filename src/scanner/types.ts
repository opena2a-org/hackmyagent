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

/**
 * What one TCP connect learned about a port.
 * open: accepted; closed: refused (the host answered); filtered: no answer
 * inside the timeout; unresolved: the hostname has no address; error: the
 * connect failed for another reason (no route, permission).
 */
export type PortState = 'open' | 'closed' | 'filtered' | 'unresolved' | 'error';

export interface ExternalScanResult {
  id: string;
  target: string;
  score: number;
  grade: string;
  findings: ExternalFinding[];
  duration: number;
  timestamp: Date;
  openPorts: number[];
  /**
   * Whether anything at the target answered at all: an open or refused port
   * counts, a silent or unresolved one does not. Absent when the port scan was
   * skipped, because then nothing was asked.
   */
  hostReachable?: boolean;
  /** The state of every port scanned, keyed by port number. */
  portStates?: Record<number, PortState>;
}

export interface ScannerOptions {
  timeout?: number;
  ports?: number[];
  skipPortScan?: boolean;
  insecure?: boolean;
}
