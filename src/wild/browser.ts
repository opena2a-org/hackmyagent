/**
 * Lightweight HTTP browser for the Wild Scanner.
 *
 * Fetches web pages and extracts visible content, hidden payloads,
 * and injection surfaces. Simulates how an AI agent would process
 * the page content.
 */

import type { InjectionSurface } from './types';
import {
  elementMatches,
  htmlComments,
  indexOfWordsInOrderOnOneLine,
  replaceBeforeLastCloser,
  sameLineMatches,
  tagAttributeMatches,
  wordsInOrderOnOneLine,
} from '../types/lazy-scan';

export interface FetchedPage {
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  html: string;
  responseTime: number;
}

export interface ExtractedContent {
  /** Visible text content */
  visibleText: string;
  /** Hidden payloads found */
  injectionSurfaces: InjectionSurface[];
  /** Attack metadata extracted from page */
  attackId?: string;
  severity?: string;
  hmaCheckId?: string;
  category?: string;
  tier?: number;
  /** Whether the page has a callback instruction */
  hasCallback: boolean;
  /** Whether the page has a canary token */
  hasCanary: boolean;
}

/** Fetch a page with timeout */
export async function fetchPage(url: string, timeout: number): Promise<FetchedPage> {
  const start = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'HackMyAgent-WildScanner/1.0 (security-testing)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    const html = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      url,
      statusCode: response.status,
      headers,
      html,
      responseTime: Date.now() - start,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Fetch a text file (robots.txt, llms.txt, etc.) */
export async function fetchTextFile(url: string, timeout: number): Promise<{ statusCode: number; text: string; responseTime: number }> {
  const start = Date.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'HackMyAgent-WildScanner/1.0 (security-testing)',
        'Accept': 'text/plain,*/*',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    return {
      statusCode: response.status,
      text: await response.text(),
      responseTime: Date.now() - start,
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

/** Extract content and injection surfaces from fetched HTML */
export function extractContent(page: FetchedPage): ExtractedContent {
  const { html, headers } = page;
  const surfaces: InjectionSurface[] = [];
  let hasCallback = false;
  let hasCanary = false;

  // 1. HTML comments. The matches of /<!--\s*([\s\S]*?)\s*-->/g, found by a
  // scan that stops at the first `<!--` with no `-->` after it instead of
  // retrying from every later one.
  for (const comment of htmlComments(html)) {
    const content = comment.body.trim();
    if (looksLikePayload(content)) {
      surfaces.push({
        type: 'html-comment',
        content: content.slice(0, 200),
        stealthScore: 3,
      });
    }
  }

  // 2. Invisible spans (off-screen positioned elements). elementMatches runs
  // the pattern only up to the last `</span>` and skips openers that cannot
  // match, so a flood of `<span` with no closer stays linear.
  const invisibleRegex = /<span[^>]*style="[^"]*(?:position:\s*absolute|left:\s*-\d+px|display:\s*none)[^"]*"[^>]*>([\s\S]*?)<\/span>/iy;
  for (const match of elementMatches(html, invisibleRegex, /<span/gi, /<\/span>/gi)) {
    const content = match[1].trim();
    if (content.length > 10) {
      surfaces.push({
        type: 'invisible-span',
        content: content.slice(0, 200),
        stealthScore: 5,
      });
    }
  }

  // 3. JSON-LD with suspicious fields
  const jsonLdRegex = /<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/iy;
  for (const match of elementMatches(html, jsonLdRegex, /<script/gi, /<\/script>/gi)) {
    try {
      const data = JSON.parse(match[1]);
      if (data['ai-instructions'] || data['security-test'] || data['security-callback']) {
        const payload = data['ai-instructions'] || data['security-test'] || data['security-callback'];
        surfaces.push({
          type: 'json-ld',
          content: String(payload).slice(0, 200),
          stealthScore: 7,
        });
      }
    } catch {
      // Malformed JSON-LD, skip
    }
  }

  // 4. Meta tags with AI instructions. The matches of
  // /<meta[^>]*name="(?:ai-instructions|security-test-id|security-test-severity)"[^>]*content="([^"]*)"[^>]*\/?>/gi,
  // found without re-running both [^>]* from every `<meta` and every name.
  const metaTags = tagAttributeMatches(html, {
    opener: /<meta/gi,
    key: /name="(?:ai-instructions|security-test-id|security-test-severity)"/gi,
    attribute: /content="/gi,
    minLength: 0,
  });
  for (const meta of metaTags) {
    surfaces.push({
      type: 'meta-tag',
      content: meta.value.slice(0, 200),
      stealthScore: 6,
    });
  }

  // 5. HTTP headers with AI instructions
  const aiHeader = headers['x-ai-instructions'];
  if (aiHeader) {
    surfaces.push({
      type: 'http-header',
      content: aiHeader.slice(0, 200),
      stealthScore: 8,
    });
  }

  // 6. ARIA labels with suspicious content
  let match;
  const ariaRegex = /aria-label="([^"]{50,})"/gi;
  while ((match = ariaRegex.exec(html)) !== null) {
    if (looksLikePayload(match[1])) {
      surfaces.push({
        type: 'aria-label',
        content: match[1].slice(0, 200),
        stealthScore: 7,
      });
    }
  }

  // 7. Image alt text with suspicious content. The matches of
  // /<img[^>]*alt="([^"]{50,})"[^>]*\/?>/gi, found the same way.
  const imageAlts = tagAttributeMatches(html, { opener: /<img/gi, attribute: /alt="/gi, minLength: 50 });
  for (const img of imageAlts) {
    if (looksLikePayload(img.value)) {
      surfaces.push({
        type: 'image-alt',
        content: img.value.slice(0, 200),
        stealthScore: 6,
      });
    }
  }

  // Check for callback URLs
  if (html.includes('/api/report') || html.includes('agentpwn.com/api/report')) {
    hasCallback = true;
  }

  // Check for canary tokens
  if (html.includes('/api/canary/') || html.includes('agentpwn.com/api/canary/')) {
    hasCanary = true;
  }

  // Extract attack metadata
  const attackIdMatch = html.match(/APWN-[A-Z]+-\d{3}/);
  const hmaCheckMatch = html.match(/(?:PROMPT|INJ|CRED|MEM|TOOL|AUTH|MCP|A2A|RATE|SUPPLY|CONFIG|UNICODE-STEGO|RAG)-\d{3}/);
  const severityMatch = html.match(/severity['":\s]+(critical|high|medium|low)/i);

  // Extract visible text (strip HTML tags, roughly)
  const withoutScripts = html
    // Bounded at the next `<script` so a flood of unclosed openers costs
    // O(n) total instead of O(n^2) (HMA-44); script elements cannot nest.
    .replace(/<script(?:(?!<script)[\s\S])*?<\/script>/gi, '');
  // No style element can end past the last `</style>`, so the strip runs only
  // up to it and a flood of `<style` after it costs nothing. The tag strip
  // works the same way: no tag ends past the last `>`, and before it every
  // `<` either fails at once on `<>` or reaches the next `>`.
  const withoutStyles = replaceBeforeLastCloser(withoutScripts, /<style[\s\S]*?<\/style>/gi, /<\/style>/gi, '');
  const visibleText = replaceBeforeLastCloser(withoutStyles, /<[^>]+>/g, />/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);

  return {
    visibleText,
    injectionSurfaces: surfaces,
    attackId: attackIdMatch?.[0],
    severity: severityMatch?.[1],
    hmaCheckId: hmaCheckMatch?.[0],
    hasCallback,
    hasCanary,
  };
}

/** Heuristic: does this text look like an injection payload? */
export function looksLikePayload(text: string): boolean {
  const indicators = [
    /system\s*(?:prompt|override|update|instructions)/i,
    /override|bypass/i,
    /you\s+are\s+now/i,
    /security\s+test/i,
    /agentpwn/i,
    /hackmyagent/i,
    /npx\s+hackmyagent/i,
    /APWN-[A-Z]+-\d{3}/,
  ];
  // Words that must appear in this order on one line, case-insensitively:
  // /ignore.*(?:previous|all).*instructions/i, the `disable` branch of
  // /override|bypass|disable.*(?:safety|filter|restrict)/i,
  // /output.*(?:system.*prompt|credentials|api.*key)/i and /report.*to.*admin/i,
  // one list per branch. As regexes these retried each `.*` from every
  // occurrence of the word before it: a comment holding 16 KiB of
  // `ignore all ` took more than 5 seconds, and each doubling cost 8 times more.
  const wordChains = [
    ['ignore', 'previous', 'instructions'],
    ['ignore', 'all', 'instructions'],
    ['disable', 'safety'],
    ['disable', 'filter'],
    ['disable', 'restrict'],
    ['output', 'system', 'prompt'],
    ['output', 'credentials'],
    ['output', 'api', 'key'],
    ['report', 'to', 'admin'],
  ];

  return (
    indicators.some((re) => re.test(text)) || wordChains.some((words) => wordsInOrderOnOneLine(text, words))
  );
}

/**
 * Does a fetched robots.txt, llms.txt or sitemap.xml carry a payload marker?
 * Exactly `/agentpwn|hackmyagent|security.*test|APWN-|ignore.*instructions/i.test(text)`.
 * As a regex, each `.*` branch ran to the end of the line from every
 * occurrence of its first word, so a file holding 1 MiB of `security ` took
 * about 48 seconds; the two branches now read each line once.
 */
export function fileHasPayload(text: string): boolean {
  return (
    /agentpwn|hackmyagent|APWN-/i.test(text) ||
    wordsInOrderOnOneLine(text, ['security', 'test']) ||
    wordsInOrderOnOneLine(text, ['ignore', 'instructions'])
  );
}

/**
 * The line a file payload excerpt is cut from: exactly
 * `text.match(/(?:SECURITY TEST|APWN-|ignore.*instructions|hackmyagent)[^\n]*\/i)?.[0]`.
 * Every branch is followed by `[^\n]*`, and the `.*` branch holds no `\n`,
 * so the match runs from the leftmost branch start to the next `\n`.
 */
export function filePayloadLine(text: string): string | undefined {
  const starts = [
    text.search(/SECURITY TEST|APWN-|hackmyagent/i),
    indexOfWordsInOrderOnOneLine(text, ['ignore', 'instructions']),
  ].filter((i) => i >= 0);
  if (starts.length === 0) return undefined;
  const start = Math.min(...starts);
  const end = text.indexOf('\n', start);
  return text.slice(start, end < 0 ? text.length : end);
}

/** Parse sitemap.xml to get attack page URLs */
export function parseSitemap(xml: string, baseUrl: string): string[] {
  const urls: string[] = [];
  // The matches of /<loc>(.*?)<\/loc>/g, found without rescanning a line from
  // every `<loc>` on it that has no `</loc>` after it.
  for (const loc of sameLineMatches(xml, '<loc>', '</loc>')) {
    let url = loc.body;
    // Replace the domain with the actual target
    if (url.includes('agentpwn.com')) {
      url = url.replace('https://agentpwn.com', baseUrl);
    }
    if (url.includes('/attacks/')) {
      urls.push(url);
    }
  }
  return urls;
}
