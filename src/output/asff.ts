/**
 * AWS Security Finding Format (ASFF) adapter.
 *
 * Transforms HMA security findings into ASFF JSON for import
 * into AWS Security Hub via BatchImportFindings API.
 *
 * Usage:
 *   hackmyagent secure --format asff
 *   hackmyagent secure --format asff | aws securityhub batch-import-findings --findings file:///dev/stdin
 *
 * Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
 */

import { VERSION } from '../index.js';
import { countsAgainstScore } from '../ui/verdict-band';

export interface SecurityFinding {
  checkId: string;
  name: string;
  severity: string;
  passed: boolean;
  fixed?: boolean;
  message?: string;
  file?: string;
  line?: number;
  recommendation?: string;
  category?: string;
}

interface ASSFinding {
  SchemaVersion: string;
  Id: string;
  ProductArn: string;
  GeneratorId: string;
  AwsAccountId: string;
  Types: string[];
  CreatedAt: string;
  UpdatedAt: string;
  Severity: { Label: string; Original: string };
  Title: string;
  Description: string;
  Remediation?: {
    Recommendation: {
      Text: string;
      Url: string;
    };
  };
  Resources: Array<{
    Type: string;
    Id: string;
    Details?: Record<string, unknown>;
  }>;
  ProductFields: Record<string, string>;
  RecordState: string;
  Workflow: { Status: string };
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  informational: 'INFORMATIONAL',
  info: 'INFORMATIONAL',
};

const CATEGORY_TYPE_MAP: Record<string, string> = {
  credentials: 'Software and Configuration Checks/Vulnerabilities/CVE',
  mcp: 'Software and Configuration Checks/Industry and Regulatory Standards',
  network: 'Software and Configuration Checks/Vulnerabilities/CVE',
  injection: 'Software and Configuration Checks/Vulnerabilities/CVE',
  supply_chain: 'Software and Configuration Checks/Vulnerabilities/CVE',
  governance: 'Software and Configuration Checks/Industry and Regulatory Standards',
  config: 'Software and Configuration Checks/AWS Security Best Practices',
};

/**
 * Convert HMA findings to AWS Security Finding Format.
 */
export function toASSF(
  findings: SecurityFinding[],
  options: {
    awsAccountId?: string;
    awsRegion?: string;
    targetDir?: string;
  } = {},
): string {
  const accountId = options.awsAccountId || process.env.AWS_ACCOUNT_ID || '000000000000';
  const region = options.awsRegion || process.env.AWS_REGION || 'us-east-1';
  const targetDir = options.targetDir || process.cwd();
  const now = new Date().toISOString();

  const productArn = `arn:aws:securityhub:${region}:${accountId}:product/${accountId}/default`;

  // Only include failed (not passed, not fixed) findings
  const failed = findings.filter(f => countsAgainstScore(f));

  const assfFindings: ASSFinding[] = failed.map(f => {
    const severity = SEVERITY_MAP[f.severity] || 'INFORMATIONAL';
    const category = f.category || f.checkId.split('-')[0].toLowerCase();
    const types = CATEGORY_TYPE_MAP[category]
      ? [CATEGORY_TYPE_MAP[category]]
      : ['Software and Configuration Checks'];

    const title = f.name || f.checkId;
    const description = (f.message || f.name || f.checkId).slice(0, 1024);

    const finding: ASSFinding = {
      SchemaVersion: '2018-10-08',
      Id: `opena2a/hma/${f.checkId}/${Date.now()}`,
      ProductArn: productArn,
      GeneratorId: `hackmyagent/${f.checkId}`,
      AwsAccountId: accountId,
      Types: types,
      CreatedAt: now,
      UpdatedAt: now,
      Severity: {
        Label: severity,
        Original: f.severity,
      },
      Title: title.slice(0, 256),
      Description: description,
      Resources: [{
        Type: 'Other',
        Id: f.file || targetDir,
      }],
      ProductFields: {
        'opena2a/checkId': f.checkId,
        'opena2a/scanner': 'hackmyagent',
        'opena2a/scannerVersion': VERSION,
      },
      RecordState: 'ACTIVE',
      Workflow: { Status: 'NEW' },
    };

    if (f.recommendation) {
      finding.Remediation = {
        Recommendation: {
          Text: f.recommendation.slice(0, 512),
          Url: `https://hackmyagent.com/docs/checks/${f.checkId.toLowerCase()}`,
        },
      };
    }

    if (f.file) {
      finding.Resources[0].Details = {
        Other: {
          filePath: f.file,
          ...(f.line ? { lineNumber: String(f.line) } : {}),
        },
      };
    }

    return finding;
  });

  return JSON.stringify(assfFindings, null, 2);
}

/**
 * Split ASFF findings into batches of 100 (AWS API limit).
 */
export function batchASSF(assfJson: string): string[] {
  const findings = JSON.parse(assfJson);
  const batches: string[] = [];

  for (let i = 0; i < findings.length; i += 100) {
    batches.push(JSON.stringify(findings.slice(i, i + 100), null, 2));
  }

  return batches;
}
