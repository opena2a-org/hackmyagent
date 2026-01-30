/**
 * Publisher verification via DNS TXT records
 *
 * Publishers can verify ownership by adding a TXT record to their domain:
 *   - hackmyagent-verify=<publisher-name>
 *   - hackmyagent-publisher=<publisher-name>
 *   - opena2a-verify=<publisher-name>
 *
 * The record can be at:
 *   - The root domain (e.g., TXT @ for publisher.dev)
 *   - A _hackmyagent subdomain (e.g., TXT _hackmyagent.publisher.dev)
 */

import { promises as dns } from 'dns';

export type VerificationMethod = 'dns' | 'github' | 'none';

export interface PublisherVerification {
  verified: boolean;
  method: VerificationMethod;
  domain?: string;
  txtRecord?: string;
  verifiedAt?: Date;
  failureReason?: string;
}

export interface VerifyOptions {
  mockDnsRecords?: Record<string, string[]>;
  registryDomains?: Record<string, string>;
}

// Accepted TXT record prefixes (case-insensitive)
const VALID_PREFIXES = [
  'hackmyagent-verify=',
  'hackmyagent-publisher=',
  'opena2a-verify=',
  'publisher=', // For _hackmyagent subdomain
];

// Domain suffixes to try when looking up a publisher
const DOMAIN_SUFFIXES = ['.dev', '.com', '.io', '.org'];

/**
 * Look up TXT records for a domain
 */
export async function lookupDnsTxt(domain: string): Promise<string[]> {
  try {
    const records = await dns.resolveTxt(domain);
    // dns.resolveTxt returns string[][] (chunks), flatten them
    return records.map((chunks) => chunks.join(''));
  } catch (error: unknown) {
    // ENOTFOUND, ENODATA, etc. - domain doesn't exist or has no TXT records
    return [];
  }
}

/**
 * Check if a TXT record verifies the publisher
 */
function checkTxtRecord(record: string, publisherName: string): boolean {
  const lowerRecord = record.toLowerCase();
  const lowerPublisher = publisherName.toLowerCase();

  for (const prefix of VALID_PREFIXES) {
    if (lowerRecord.startsWith(prefix.toLowerCase())) {
      const value = record.substring(prefix.length).trim();
      return value.toLowerCase() === lowerPublisher;
    }
  }

  return false;
}

/**
 * Get domains to check for a publisher
 */
function getDomainsToCheck(
  publisherName: string,
  options?: VerifyOptions
): string[] {
  const domains: string[] = [];

  // If registry has a custom domain for this publisher, check it first
  if (options?.registryDomains?.[publisherName]) {
    const customDomain = options.registryDomains[publisherName];
    domains.push(customDomain);
    domains.push(`_hackmyagent.${customDomain}`);
  }

  // Try common domain patterns
  for (const suffix of DOMAIN_SUFFIXES) {
    const baseDomain = `${publisherName}${suffix}`;
    domains.push(baseDomain);
    domains.push(`_hackmyagent.${baseDomain}`);
  }

  return domains;
}

/**
 * Look up DNS TXT records (with mock support for testing)
 */
async function getDnsRecords(
  domain: string,
  options?: VerifyOptions
): Promise<string[]> {
  // Use mock records if provided (for testing)
  if (options?.mockDnsRecords) {
    return options.mockDnsRecords[domain] ?? [];
  }

  // Real DNS lookup
  return lookupDnsTxt(domain);
}

/**
 * Extract the base domain from a full domain (removes _hackmyagent. prefix)
 */
function getBaseDomain(domain: string): string {
  if (domain.startsWith('_hackmyagent.')) {
    return domain.substring('_hackmyagent.'.length);
  }
  return domain;
}

/**
 * Verify a publisher's identity via DNS TXT records
 */
export async function verifyPublisher(
  publisherName: string,
  options?: VerifyOptions
): Promise<PublisherVerification> {
  const domainsToCheck = getDomainsToCheck(publisherName, options);
  const checkedDomains: string[] = [];

  for (const domain of domainsToCheck) {
    checkedDomains.push(domain);
    const records = await getDnsRecords(domain, options);

    for (const record of records) {
      if (checkTxtRecord(record, publisherName)) {
        return {
          verified: true,
          method: 'dns',
          domain: getBaseDomain(domain),
          txtRecord: record,
          verifiedAt: new Date(),
        };
      }
    }
  }

  return {
    verified: false,
    method: 'none',
    failureReason: `No valid TXT record found for publisher "${publisherName}". Checked domains: ${checkedDomains.join(', ')}`,
  };
}
