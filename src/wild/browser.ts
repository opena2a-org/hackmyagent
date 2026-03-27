/**
 * Lightweight HTTP browser for the Wild Scanner.
 *
 * Fetches web pages and extracts visible content, hidden payloads,
 * and injection surfaces. Simulates how an AI agent would process
 * the page content.
 */

import type { InjectionSurface } from './types';

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

  // 1. HTML comments
  const commentRegex = /<!--\s*([\s\S]*?)\s*-->/g;
  let match;
  while ((match = commentRegex.exec(html)) !== null) {
    const content = match[1].trim();
    if (looksLikePayload(content)) {
      surfaces.push({
        type: 'html-comment',
        content: content.slice(0, 200),
        stealthScore: 3,
      });
    }
  }

  // 2. Invisible spans (off-screen positioned elements)
  const invisibleRegex = /<span[^>]*style="[^"]*(?:position:\s*absolute|left:\s*-\d+px|display:\s*none)[^"]*"[^>]*>([\s\S]*?)<\/span>/gi;
  while ((match = invisibleRegex.exec(html)) !== null) {
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
  const jsonLdRegex = /<script[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/gi;
  while ((match = jsonLdRegex.exec(html)) !== null) {
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

  // 4. Meta tags with AI instructions
  const metaRegex = /<meta[^>]*name="(?:ai-instructions|security-test-id|security-test-severity)"[^>]*content="([^"]*)"[^>]*\/?>/gi;
  while ((match = metaRegex.exec(html)) !== null) {
    surfaces.push({
      type: 'meta-tag',
      content: match[1].slice(0, 200),
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

  // 7. Image alt text with suspicious content
  const imgAltRegex = /<img[^>]*alt="([^"]{50,})"[^>]*\/?>/gi;
  while ((match = imgAltRegex.exec(html)) !== null) {
    if (looksLikePayload(match[1])) {
      surfaces.push({
        type: 'image-alt',
        content: match[1].slice(0, 200),
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
  const visibleText = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
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
function looksLikePayload(text: string): boolean {
  const indicators = [
    /ignore.*(?:previous|all).*instructions/i,
    /system\s*(?:prompt|override|update|instructions)/i,
    /override|bypass|disable.*(?:safety|filter|restrict)/i,
    /output.*(?:system.*prompt|credentials|api.*key)/i,
    /you\s+are\s+now/i,
    /security\s+test/i,
    /agentpwn/i,
    /hackmyagent/i,
    /npx\s+hackmyagent/i,
    /report.*to.*admin/i,
    /APWN-[A-Z]+-\d{3}/,
  ];

  return indicators.some((re) => re.test(text));
}

/** Parse sitemap.xml to get attack page URLs */
export function parseSitemap(xml: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const locRegex = /<loc>(.*?)<\/loc>/g;
  let match;
  while ((match = locRegex.exec(xml)) !== null) {
    let url = match[1];
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
