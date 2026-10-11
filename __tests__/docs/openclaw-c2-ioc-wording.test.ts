/**
 * #996 — the OpenClaw guide describes the ClawHavoc C2 indicator as what
 * SUPPLY-005 does: a text match of known C2 IP addresses in skill files.
 *
 * The guide's "IOCs checked" list read "Outbound connections to known C2
 * domains". SUPPLY-005 searches skill file content for the addresses in
 * CLAWHAVOC_C2_IPS with `content.includes(ip)`. It observes no connection,
 * and the list holds IP addresses, not domains.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const GUIDE = fs.readFileSync(path.join(ROOT, 'docs', 'use-cases', 'openclaw-security.md'), 'utf8');
const SCANNER = fs.readFileSync(path.join(ROOT, 'src', 'hardening', 'scanner.ts'), 'utf8');

/** The bullets under "IOCs checked:" in the ClawHavoc section. */
function iocBullets(): string[] {
  const section = /## Step 3: ClawHavoc IOC scanning\n([\s\S]*?)\n## /.exec(GUIDE);
  expect(section, 'no "Step 3: ClawHavoc IOC scanning" section').not.toBeNull();
  const list = /IOCs checked:\n\n((?:- .*\n(?: {2}.*\n)*)+)/.exec(section![1]);
  expect(list, 'no "IOCs checked:" list').not.toBeNull();
  return list![1].split(/\n(?=- )/).map(b => b.replace(/\s+/g, ' ').trim());
}

describe('#996 OpenClaw guide C2 indicator wording', () => {
  it('SUPPLY-005 matches C2 IP address literals in file content', () => {
    const ips = /const CLAWHAVOC_C2_IPS = \[([^\]]*)\]/.exec(SCANNER);
    expect(ips, 'CLAWHAVOC_C2_IPS not found in scanner.ts').not.toBeNull();
    const entries = [...ips![1].matchAll(/'([^']*)'/g)].map(m => m[1]);
    expect(entries.length).toBeGreaterThan(0);
    for (const ip of entries) expect(ip).toMatch(/^\d{1,3}(?:\.\d{1,3}){3}$/);
    expect(SCANNER).toMatch(/for \(const ip of CLAWHAVOC_C2_IPS\) \{\s*if \(content\.includes\(ip\)\)/);
  });

  it('no IOC bullet claims an observed connection or a domain list', () => {
    for (const bullet of iocBullets()) {
      expect(bullet).not.toMatch(/outbound connections? to/i);
      expect(bullet).not.toMatch(/C2 domains?/i);
    }
  });

  it('the C2 bullet names SUPPLY-005 and says file content is matched', () => {
    const c2 = iocBullets().filter(b => /\bC2\b|command-and-control/i.test(b));
    expect(c2).toHaveLength(1);
    expect(c2[0]).toContain('SUPPLY-005');
    expect(c2[0]).toMatch(/IP address/i);
    expect(c2[0]).toMatch(/text match/i);
    expect(c2[0]).toMatch(/does not observe/i);
  });
});
