import type { ARPEvent, EnforcementResult } from '../../arp';

/** Annotation metadata for test cases */
export interface TestAnnotation {
  /** Is this scenario an actual attack? */
  isAttack: boolean;
  /** MITRE ATLAS technique ID */
  atlasId?: string;
  /** OWASP Agentic Top 10 category */
  owaspId?: string;
  /** Whether ARP should detect this */
  expectedDetection: boolean;
  /** Expected minimum severity if detected */
  expectedSeverity?: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Timestamp when the attack was initiated */
  attackTimestamp?: number;
}

/** Collected test result with timing info */
export interface TestResult {
  testId: string;
  annotation: TestAnnotation;
  detected: boolean;
  detectionTimeMs?: number;
  events: ARPEvent[];
  enforcements: EnforcementResult[];
}

/** Suite-level metrics */
export interface SuiteMetrics {
  totalTests: number;
  attacks: number;
  benign: number;
  truePositives: number;
  falsePositives: number;
  trueNegatives: number;
  falseNegatives: number;
  detectionRate: number;
  falsePositiveRate: number;
  meanDetectionTimeMs: number;
  p95DetectionTimeMs: number;
}

/** ARP wrapper configuration for tests */
export interface LabConfig {
  monitors?: {
    process?: boolean;
    network?: boolean;
    filesystem?: boolean;
  };
  rules?: import('../../arp').AlertRule[];
  intelligence?: {
    enabled?: boolean;
  };
  /** Temp data dir (auto-created per test) */
  dataDir?: string;
  /** Filesystem paths to watch (for real FilesystemMonitor) */
  filesystemWatchPaths?: string[];
  /** Filesystem allowed paths (for real FilesystemMonitor) */
  filesystemAllowedPaths?: string[];
  /** Network allowed hosts (for real NetworkMonitor) */
  networkAllowedHosts?: string[];
  /** Process monitor poll interval in ms */
  processIntervalMs?: number;
  /** Network monitor poll interval in ms */
  networkIntervalMs?: number;
  /** Application-level interceptors (zero-latency hooks) */
  interceptors?: {
    process?: boolean;
    network?: boolean;
    filesystem?: boolean;
  };
  /** Interceptor network allowed hosts */
  interceptorNetworkAllowedHosts?: string[];
  /** Interceptor filesystem allowed paths */
  interceptorFilesystemAllowedPaths?: string[];
}
