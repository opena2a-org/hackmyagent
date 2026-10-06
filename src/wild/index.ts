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

import { fetchPage, fetchTextFile, extractContent, fileHasPayload, filePayloadLine, parseSitemap } from './browser';
import { computeResilienceScore } from './scorer';
import type { WildScanOptions, WildScanReport, WildPageResult, FileFetchResult } from './types';
import { escapePathForDisplay, escapeForDisplay } from '../ui/display-safe';
import { usageError } from '../checker/errors';

export type { WildScanOptions, WildScanReport, WildPageResult, FileFetchResult };

const DEFAULT_URL = 'https://agentpwn.com';

/** Tiers each attack category publishes, used when the target has no sitemap. */
const CATEGORY_MAX_TIER: Record<string, number> = {
  'prompt-injection': 10, 'jailbreak': 5, 'data-exfiltration': 5,
  'capability-abuse': 3, 'context-manipulation': 5, 'mcp-exploitation': 3,
  'a2a-attack': 3, 'memory-weaponization': 3, 'context-window': 5,
  'supply-chain': 3, 'tool-shadow': 3,
};

/** Highest tier any category publishes: the upper bound `--tier` accepts. */
export const WILD_MAX_TIER = Math.max(...Object.values(CATEGORY_MAX_TIER));

/** Largest delay a Node timer honours; above it `setTimeout` fires after 1 ms. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * #480: parse an integer `wild` flag, refusing anything that is not a whole
 * number in [min, max]. `parseInt` read `--tier abc` as NaN, which applied no
 * filter and ran every tier, and read `--tier 99999` / `--tier -5` as a filter
 * no page matches, which scored nothing 100/100 and exited 0: a typo turned a
 * failing gate green. `--timeout` and `--delay` fell back to their defaults on
 * a non-number the same way. Presence, not truthiness: `--tier ''` (a CI
 * template over an unset variable) is refused, not read as "no filter".
 */
export function parseWildIntegerOption(flag: string, raw: string | undefined, min: number, max: number): number | undefined {
  if (raw === undefined) return undefined;
  const text = raw.trim();
  const value = /^\d+$/.test(text) ? Number(text) : NaN;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw usageError`${flag} must be a whole number between ${min} and ${max} (got '${raw}')`;
  }
  return value;
}

/** `--timeout` bounds in milliseconds; 0 would abort every fetch before it starts. */
export const parseWildTimeout = (raw: string | undefined) => parseWildIntegerOption('--timeout', raw, 1, MAX_TIMER_MS);
/** `--delay` bounds in milliseconds; 0 means no pause between requests. */
export const parseWildDelay = (raw: string | undefined) => parseWildIntegerOption('--delay', raw, 0, MAX_TIMER_MS);
/** `--tier` bounds: the tiers the attack catalogue publishes. */
export const parseWildTier = (raw: string | undefined) => parseWildIntegerOption('--tier', raw, 1, WILD_MAX_TIER);

export class WildScanner {
  private options: WildScanOptions;

  constructor(options: Partial<WildScanOptions> = {}) {
    this.options = {
      url: options.url || DEFAULT_URL,
      category: options.category,
      tier: options.tier,
      timeout: options.timeout || 15000,
      delay: options.delay ?? 500,
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
        const hasPayload = fileHasPayload(result.text);
        fileFetches.push({
          file,
          url: `${baseUrl}/${file}`,
          statusCode: result.statusCode,
          hasPayload,
          payloadExcerpt: hasPayload ? filePayloadLine(result.text)?.slice(0, 100) : undefined,
        });
        if (this.options.verbose) {
          const status = hasPayload ? 'PAYLOAD FOUND' : 'clean';
          process.stderr.write(`  ${escapePathForDisplay(file)}: ${result.statusCode} [${status}]\n`);
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
      for (const [cat, max] of Object.entries(CATEGORY_MAX_TIER)) {
        for (let t = 1; t <= max; t++) {
          attackUrls.push(`${baseUrl}/attacks/${cat}/${t}`);
        }
      }
    }

    // Apply filters
    const pagesBeforeFilter = attackUrls.length;
    if (this.options.category) {
      attackUrls = attackUrls.filter(u => u.includes(`/${this.options.category}/`));
    }
    if (this.options.tier !== undefined) {
      attackUrls = attackUrls.filter(u => u.endsWith(`/${this.options.tier}`));
    }
    // #480: a filter that selects no page measured nothing. Scoring the empty
    // set printed 100/100 and exited 0, so `--category jailbreak --tier 7`
    // (jailbreak stops at tier 5) passed a gate it never ran.
    if (attackUrls.length === 0 && pagesBeforeFilter > 0) {
      const filters = [
        this.options.category ? `--category ${this.options.category}` : '',
        this.options.tier !== undefined ? `--tier ${this.options.tier}` : '',
      ].filter(Boolean).join(' ');
      throw new Error(
        `No attack page matches ${filters} (${pagesBeforeFilter} pages before filtering); nothing was scanned`,
      );
    }

    // 3. Scan each attack page
    if (this.options.verbose) {
      process.stderr.write(`\nScanning ${attackUrls.length} attack pages...\n`);
    }

    // Progress line for the non-verbose path (#253). The walk is ~48 fetches
    // with a courtesy delay between each, so a bare `wild` sat silent for
    // ~45s and read as a hang to a fresh user. Written to stderr so stdout
    // stays clean for `--json` and piping, and only on a TTY so CI logs are
    // not filled with carriage returns.
    const showProgress =
      !this.options.json && !this.options.verbose && process.stderr.isTTY;
    let scanned = 0;

    for (const url of attackUrls) {
      if (showProgress) {
        process.stderr.write(
          `\r  Scanning attack pages: ${scanned}/${attackUrls.length}`,
        );
      }
      scanned++;
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

    if (showProgress) {
      // Clear the progress line so it does not linger above the report.
      // Padded to overwrite the longest counter rendered above.
      process.stderr.write(`\r${' '.repeat(48)}\r`);
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
