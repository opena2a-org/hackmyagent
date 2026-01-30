import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  verifyPublisher,
  lookupDnsTxt,
  PublisherVerification,
  VerificationMethod,
} from './publisher-verifier';

describe('lookupDnsTxt', () => {
  it('returns TXT records for a domain', async () => {
    // Using a well-known domain that has TXT records
    const records = await lookupDnsTxt('google.com');

    expect(Array.isArray(records)).toBe(true);
    // Google has SPF and other TXT records
    expect(records.length).toBeGreaterThan(0);
  });

  it('returns empty array for domain with no TXT records', async () => {
    // Use a subdomain unlikely to have TXT records
    const records = await lookupDnsTxt('no-txt-records.example.com');

    expect(records).toEqual([]);
  });

  it('returns empty array for non-existent domain', async () => {
    const records = await lookupDnsTxt('this-domain-definitely-does-not-exist-12345.com');

    expect(records).toEqual([]);
  });
});

describe('verifyPublisher', () => {
  describe('DNS TXT verification', () => {
    it('verifies publisher with valid hackmyagent TXT record', async () => {
      const result = await verifyPublisher('test-publisher', {
        mockDnsRecords: {
          'test-publisher.dev': ['hackmyagent-verify=test-publisher'],
        },
      });

      expect(result).toMatchObject({
        verified: true,
        method: 'dns',
        domain: 'test-publisher.dev',
      });
    });

    it('verifies publisher with _hackmyagent subdomain TXT record', async () => {
      const result = await verifyPublisher('example-org', {
        mockDnsRecords: {
          '_hackmyagent.example-org.dev': ['publisher=example-org'],
        },
      });

      expect(result).toMatchObject({
        verified: true,
        method: 'dns',
        domain: 'example-org.dev',
      });
    });

    it('fails verification when TXT record has wrong publisher name', async () => {
      const result = await verifyPublisher('my-publisher', {
        mockDnsRecords: {
          'my-publisher.dev': ['hackmyagent-verify=wrong-name'],
        },
      });

      expect(result.verified).toBe(false);
      expect(result.method).toBe('none');
    });

    it('fails verification when no TXT records exist', async () => {
      const result = await verifyPublisher('unverified-publisher', {
        mockDnsRecords: {},
      });

      expect(result.verified).toBe(false);
      expect(result.method).toBe('none');
    });

    it('tries multiple domain patterns', async () => {
      // Should try: publisher.dev, publisher.com, publisher.io
      const result = await verifyPublisher('mycompany', {
        mockDnsRecords: {
          'mycompany.io': ['hackmyagent-verify=mycompany'],
        },
      });

      expect(result).toMatchObject({
        verified: true,
        method: 'dns',
        domain: 'mycompany.io',
      });
    });

    it('supports custom domain via registry lookup', async () => {
      const result = await verifyPublisher('opena2a', {
        registryDomains: {
          opena2a: 'opena2a.dev',
        },
        mockDnsRecords: {
          'opena2a.dev': ['hackmyagent-verify=opena2a'],
        },
      });

      expect(result).toMatchObject({
        verified: true,
        method: 'dns',
        domain: 'opena2a.dev',
      });
    });
  });

  describe('TXT record formats', () => {
    it('accepts hackmyagent-verify=publisher format', async () => {
      const result = await verifyPublisher('acme', {
        mockDnsRecords: {
          'acme.dev': ['hackmyagent-verify=acme'],
        },
      });

      expect(result.verified).toBe(true);
    });

    it('accepts hackmyagent-publisher=publisher format', async () => {
      const result = await verifyPublisher('acme', {
        mockDnsRecords: {
          'acme.dev': ['hackmyagent-publisher=acme'],
        },
      });

      expect(result.verified).toBe(true);
    });

    it('accepts opena2a-verify=publisher format (alias)', async () => {
      const result = await verifyPublisher('acme', {
        mockDnsRecords: {
          'acme.dev': ['opena2a-verify=acme'],
        },
      });

      expect(result.verified).toBe(true);
    });

    it('ignores unrelated TXT records', async () => {
      const result = await verifyPublisher('acme', {
        mockDnsRecords: {
          'acme.dev': [
            'v=spf1 include:_spf.google.com ~all',
            'google-site-verification=abc123',
            'hackmyagent-verify=acme', // This one should match
          ],
        },
      });

      expect(result.verified).toBe(true);
    });

    it('is case-insensitive for record keys', async () => {
      const result = await verifyPublisher('acme', {
        mockDnsRecords: {
          'acme.dev': ['HackMyAgent-Verify=acme'],
        },
      });

      expect(result.verified).toBe(true);
    });
  });

  describe('verification result details', () => {
    it('includes verification timestamp', async () => {
      const before = new Date();
      const result = await verifyPublisher('test', {
        mockDnsRecords: {
          'test.dev': ['hackmyagent-verify=test'],
        },
      });
      const after = new Date();

      expect(result.verifiedAt).toBeDefined();
      expect(result.verifiedAt!.getTime()).toBeGreaterThanOrEqual(before.getTime());
      expect(result.verifiedAt!.getTime()).toBeLessThanOrEqual(after.getTime());
    });

    it('includes the matched TXT record', async () => {
      const result = await verifyPublisher('test', {
        mockDnsRecords: {
          'test.dev': ['hackmyagent-verify=test'],
        },
      });

      expect(result.txtRecord).toBe('hackmyagent-verify=test');
    });

    it('returns failure reason when not verified', async () => {
      const result = await verifyPublisher('unknown', {
        mockDnsRecords: {},
      });

      expect(result.verified).toBe(false);
      expect(result.failureReason).toBeDefined();
      expect(result.failureReason).toContain('No valid TXT record found');
    });
  });
});
