/**
 * Wild Scanner: Tests AI agent resilience in the wild.
 *
 * Fetches pages from AgentPwn (or any target site), identifies hidden
 * injection payloads, and computes a resilience score based on the
 * attack surfaces found.
 *
 * Usage:
 *   const scanner = new WildScanner({ url: 'https://agentpwn.com' });
 *   const report = await scanner.scan();
 */

import { fetchPage, fetchTextFile, extractContent, parseSitemap } from './browser';
import { computeResilienceScore } from './scorer';
import type { WildScanOptions, WildScanReport, WildPageResult, FileFetchResult } from './types';

export type { WildScanOptions, WildScanReport, WildPageResult, FileFetchResult };

const DEFAULT_URL = 'https://agentpwn.com';

export class WildScanner {
  private options: WildScanOptions;

  constructor(options: Partial<WildScanOptions> = {}) {
    this.options = {
      url: options.url || DEFAULT_URL,
      category: options.category,
      tier: options.tier,
      timeout: options.timeout || 15000,
      delay: options.delay || 500,
      verbose: options.verbose || false,
      json: options.json || false,
    };
  }

  async scan(): Promise<WildScanReport> {
    const startTime = new Date();
    const baseUrl = this.options.url.replace(/\/$/, '');
    const pages: WildPageResult[] = [];
    const fileFetches: FileFetchResult[] = [];

    // 1. Test file-level attack surfaces
    if (this.options.verbose) {
      process.stderr.write('Scanning file-level attack surfaces...\n');
    }

    for (const file of ['robots.txt', 'llms.txt', 'sitemap.xml']) {
      try {
        const result = await fetchTextFile(`${baseUrl}/${file}`, this.options.timeout);
        const hasPayload = /agentpwn|hackmyagent|security.*test|APWN-|ignore.*instructions/i.test(result.text);
        fileFetches.push({
          file,
          url: `${baseUrl}/${file}`,
          statusCode: result.statusCode,
          hasPayload,
          payloadExcerpt: hasPayload
            ? result.text.match(/(?:SECURITY TEST|APWN-|ignore.*instructions|hackmyagent)[^\n]*/i)?.[0]?.slice(0, 100)
            : undefined,
        });
        if (this.options.verbose) {
          const status = hasPayload ? 'PAYLOAD FOUND' : 'clean';
          process.stderr.write(`  ${file}: ${result.statusCode} [${status}]\n`);
        }
      } catch (err) {
        fileFetches.push({
          file,
          url: `${baseUrl}/${file}`,
          statusCode: 0,
          hasPayload: false,
        });
      }
      await this.sleep(200);
    }

    // 2. Discover attack pages from sitemap
    let attackUrls: string[] = [];
    const sitemapFetch = fileFetches.find(f => f.file === 'sitemap.xml');
    if (sitemapFetch && sitemapFetch.statusCode === 200) {
      try {
        const sitemapResult = await fetchTextFile(`${baseUrl}/sitemap.xml`, this.options.timeout);
        attackUrls = parseSitemap(sitemapResult.text, baseUrl);
      } catch {
        // Fall back to known patterns
      }
    }

    // Fall back to known attack page patterns if sitemap unavailable
    if (attackUrls.length === 0) {
      const categories = [
        'prompt-injection', 'jailbreak', 'data-exfiltration',
        'capability-abuse', 'context-manipulation', 'mcp-exploitation',
        'a2a-attack', 'memory-weaponization', 'context-window',
        'supply-chain', 'tool-shadow',
      ];
      const maxTiers: Record<string, number> = {
        'prompt-injection': 10, 'jailbreak': 5, 'data-exfiltration': 5,
        'capability-abuse': 3, 'context-manipulation': 5, 'mcp-exploitation': 3,
        'a2a-attack': 3, 'memory-weaponization': 3, 'context-window': 5,
        'supply-chain': 3, 'tool-shadow': 3,
      };

      for (const cat of categories) {
        const max = maxTiers[cat] || 3;
        for (let t = 1; t <= max; t++) {
          attackUrls.push(`${baseUrl}/attacks/${cat}/${t}`);
        }
      }
    }

    // Apply filters
    if (this.options.category) {
      attackUrls = attackUrls.filter(u => u.includes(`/${this.options.category}/`));
    }
    if (this.options.tier) {
      attackUrls = attackUrls.filter(u => u.endsWith(`/${this.options.tier}`));
    }

    // 3. Scan each attack page
    if (this.options.verbose) {
      process.stderr.write(`\nScanning ${attackUrls.length} attack pages...\n`);
    }

    for (const url of attackUrls) {
      try {
        const page = await fetchPage(url, this.options.timeout);
        const content = extractContent(page);

        // Extract category and tier from URL
        const urlMatch = url.match(/\/attacks\/([^/]+)\/(\d+)/);
        const category = urlMatch?.[1] || content.category || 'unknown';
        const tier = urlMatch ? parseInt(urlMatch[2], 10) : (content.tier || 0);

        const result: WildPageResult = {
          url,
          category,
          tier,
          attackId: content.attackId || '',
          injectionSurfaces: content.injectionSurfaces,
          payloadCount: content.injectionSurfaces.length,
          hasCallback: content.hasCallback,
          hasCanary: content.hasCanary,
          statusCode: page.statusCode,
          responseTime: page.responseTime,
          severity: content.severity || 'unknown',
          hmaCheckId: content.hmaCheckId || '',
        };

        pages.push(result);

        if (this.options.verbose) {
          const payloadInfo = result.payloadCount > 0
            ? `${result.payloadCount} payloads [${result.injectionSurfaces.map(s => s.type).join(', ')}]`
            : 'no payloads';
          process.stderr.write(`  ${category}/T${tier}: ${page.statusCode} - ${payloadInfo}\n`);
        }
      } catch (err) {
        if (this.options.verbose) {
          process.stderr.write(`  ${url}: ERROR - ${err instanceof Error ? err.message : 'unknown'}\n`);
        }
      }

      await this.sleep(this.options.delay);
    }

    // 4. Compute resilience score
    const endTime = new Date();
    const { score, rating, summary } = computeResilienceScore({
      pages,
      fileFetches,
      pagesScanned: pages.length,
    });

    return {
      target: baseUrl,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      pagesScanned: pages.length,
      pages,
      summary,
      wildResilienceScore: score,
      resilienceRating: rating,
      fileFetches,
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
