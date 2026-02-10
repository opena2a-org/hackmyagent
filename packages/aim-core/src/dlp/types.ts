/** DLP pattern definition */
export interface DLPPattern {
  /** Unique pattern identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Detection regex */
  regex: RegExp;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Category for policy matching */
  category: 'pii' | 'credential' | 'financial' | 'infrastructure';
  /** Masking strategy */
  maskStrategy: 'full' | 'partial' | 'hash';
}

/** A single DLP detection match */
export interface DLPMatch {
  /** Pattern that matched */
  patternId: string;
  /** Pattern name */
  patternName: string;
  /** Severity */
  severity: DLPPattern['severity'];
  /** Category */
  category: DLPPattern['category'];
  /** Character offset of match start */
  offset: number;
  /** Length of matched text */
  length: number;
  /** Original matched text */
  original: string;
  /** Masked replacement */
  masked: string;
}

/** Result of scanning text for DLP violations */
export interface DLPScanResult {
  /** Whether any patterns were detected */
  detected: boolean;
  /** All matches found */
  matches: DLPMatch[];
  /** Text with all detections masked */
  maskedText: string;
  /** Action taken based on policy */
  action: 'allowed' | 'masked' | 'blocked';
}

/** DLP policy rules (extends capability policy) */
export interface DLPPolicy {
  /** Whether DLP is enabled */
  enabled: boolean;
  /** Default action for unmatched patterns */
  defaultAction: 'allow' | 'mask' | 'block';
  /** Per-category overrides */
  categories?: Partial<Record<DLPPattern['category'], 'allow' | 'mask' | 'block'>>;
  /** Per-pattern overrides */
  patterns?: Record<string, 'allow' | 'mask' | 'block'>;
}
