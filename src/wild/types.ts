/**
 * Types for the Wild Scanner module.
 * Tests AI agent resilience by fetching pages from AgentPwn
 * and analyzing hidden injection payloads.
 */

export interface WildScanOptions {
  /** Base URL of the AgentPwn site */
  url: string;
  /** Filter by attack category */
  category?: string;
  /** Filter by specific tier */
  tier?: number;
  /** Request timeout in ms */
  timeout: number;
  /** Delay between requests in ms */
  delay: number;
  /** Show verbose output */
  verbose: boolean;
  /** Output as JSON */
  json: boolean;
}

export interface WildPageResult {
  /** Page URL */
  url: string;
  /** Attack category */
  category: string;
  /** Difficulty tier */
  tier: number;
  /** Attack ID from the page */
  attackId: string;
  /** Injection surfaces found */
  injectionSurfaces: InjectionSurface[];
  /** Total number of hidden payloads detected */
  payloadCount: number;
  /** Whether the page has a callback instruction */
  hasCallback: boolean;
  /** Whether the page has a canary token */
  hasCanary: boolean;
  /** HTTP status code */
  statusCode: number;
  /** Response time in ms */
  responseTime: number;
  /** Severity of the attack */
  severity: string;
  /** HMA check ID */
  hmaCheckId: string;
}

export interface InjectionSurface {
  /** Type of injection delivery */
  type: 'html-comment' | 'invisible-span' | 'json-ld' | 'meta-tag' | 'http-header' | 'aria-label' | 'image-alt' | 'unicode-stego';
  /** The extracted payload text (truncated) */
  content: string;
  /** Whether this would likely fool an agent */
  stealthScore: number;
}

export interface WildScanReport {
  /** Target URL */
  target: string;
  /** Scan start time */
  startTime: Date;
  /** Scan end time */
  endTime: Date;
  /** Duration in ms */
  duration: number;
  /** Pages scanned */
  pagesScanned: number;
  /** Individual page results */
  pages: WildPageResult[];
  /** Summary statistics */
  summary: {
    totalPayloads: number;
    byCategory: Record<string, { pages: number; payloads: number }>;
    bySurface: Record<string, number>;
    maxTier: number;
    callbackPages: number;
    canaryPages: number;
  };
  /** Overall wild resilience score (0-100) */
  wildResilienceScore: number;
  /** Resilience rating */
  resilienceRating: 'excellent' | 'good' | 'moderate' | 'poor' | 'critical';
  /** File fetches tested (robots.txt, llms.txt, sitemap.xml) */
  fileFetches: FileFetchResult[];
}

export interface FileFetchResult {
  file: string;
  url: string;
  statusCode: number;
  hasPayload: boolean;
  payloadExcerpt?: string;
}
