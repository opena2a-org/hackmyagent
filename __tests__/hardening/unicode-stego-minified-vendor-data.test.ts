/**
 * #447: Django ships XRegExp as `admin/js/vendor/xregexp/xregexp.min.js`. Its
 * Unicode category and script tables are written in the source as escapes
 * (`\u200B-\u200F\u202A-\u202E\uFE00-\uFE0F`), and the minifier writes them
 * out as the characters themselves. UNICODE-STEGO-001 reported those range
 * endpoints as a CRITICAL invisible-codepoint payload.
 *
 * The fixtures below are built from escapes so this file carries no invisible
 * code point of its own.
 */
import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { HardeningScanner, isMinifiedUnicodeClassData } from '../../src/hardening/scanner';
import type { SecurityFinding } from '../../src/hardening/security-check';
import { tempDir } from '../helpers/temp-dir';

// Tables as XRegExp's unicode-categories, -properties and -scripts spell them.
const CF =
  '\xAD\u0600-\u0605\u061C\u06DD\u070F\u08E2\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB';
const DEFAULT_IGNORABLE =
  '\xAD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFF8';
const INHERITED =
  '\u0300-\u036F\u0485\u0486\u064B-\u0655\u0670\u0951-\u0954\u1AB0-\u1ABE\u1CD0-\u1CD2\u1CD4-\u1CE0\u1CE2-\u1CE8\u1CED\u1CF4\u1CF8\u1CF9\u1DC0-\u1DF9\u1DFB-\u1DFF\u200C\u200D\u20D0-\u20F0\u302A-\u302D\u3099\u309A\uFE00-\uFE0F\uFE20-\uFE2D';
const COMMON =
  '\\0-@\\[-`\\{-\xA9\xAB-\xB9\xBB-\xBF\xD7\xF7\u02B9-\u02DF\u02E5-\u02E9\u02EC-\u02FF\u0374\u037E\u0385\u0387\u0589\u0605\u060C\u061B\u061F\u0640\u06DD\u08E2\u0964\u0965\u0E3F\u0FD5-\u0FD8\u10FB\u16EB-\u16ED\u1735\u1736\u1802\u1803\u1805\u1CD3\u1CE1\u1CE9-\u1CEC\u1CEE-\u1CF3\u1CF5-\u1CF7\u2000-\u200B\u200E-\u2064\u2066-\u2070\u2074-\u207E';

/** One minified line in the shape XRegExp's bundle has, around the tables. */
function xregexpMin(extra = ''): string {
  const pad = 'function(e,t,n){"use strict";var r=e("./xregexp");t.exports=function(e){'.repeat(20);
  return (
    '!function(e){if("object"==typeof exports)module.exports=e();else{var t;t=window,t.XRegExp=e()}}(' +
    pad +
    'e.addUnicodeData([' +
    `{name:"Cf",alias:"Format",bmp:"${CF}",astral:"\\uD804\\uDCBD|\\uDB40[\\uDC01\\uDC20-\\uDC7F]"},` +
    `{name:"Default_Ignorable_Code_Point",bmp:"${DEFAULT_IGNORABLE}",astral:"\\uDB40[\\uDC00-\\uDFFF]"},` +
    `{name:"Inherited",bmp:"${INHERITED}",astral:"\\uDB40[\\uDD00-\\uDDEF]"},` +
    `{name:"Common",bmp:"${COMMON}"}` +
    '])' +
    extra +
    '}});\n'
  );
}

function project(files: Record<string, string>): string {
  const dir = tempDir('hma-stego-vendor-');
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'site', version: '1.0.0' }));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), body);
  }
  return dir;
}

async function stego(dir: string): Promise<SecurityFinding[]> {
  const result = await new HardeningScanner().scan({ targetDir: dir });
  return result.findings.filter((f) => f.checkId.startsWith('UNICODE-STEGO-') && !f.passed);
}

const VENDOR = 'static/admin/js/vendor/xregexp/xregexp.min.js';

describe('UNICODE-STEGO on minified vendored Unicode regex data (#447)', () => {
  it('raises no unicode-stego finding for an xregexp-style minified table', async () => {
    const dir = project({ [VENDOR]: xregexpMin() });
    const findings = await stego(dir);
    expect(findings.filter((f) => f.severity === 'critical')).toEqual([]);
    expect(findings.filter((f) => f.file === VENDOR)).toEqual([]);
  });

  it('still reports a variation-selector payload in a string of the same bundle', async () => {
    const payload = Array.from({ length: 24 }, (_, i) => String.fromCodePoint(0xFE00 + (i * 7) % 16)).join('');
    const dir = project({ [VENDOR]: xregexpMin(`;var p="ok${payload}"`) });
    const hit = (await stego(dir)).find((f) => f.checkId === 'UNICODE-STEGO-001' && f.file === VENDOR);
    expect(hit?.severity).toBe('critical');
  });

  it('still reports a payload appended to a table string', async () => {
    const payload = '\uFE03\uFE01\uFE0A\uFE00\uFE0E\uFE02';
    const dir = project({ [VENDOR]: xregexpMin().replace(DEFAULT_IGNORABLE, DEFAULT_IGNORABLE + payload) });
    const hit = (await stego(dir)).find((f) => f.checkId === 'UNICODE-STEGO-001' && f.file === VENDOR);
    expect(hit?.severity).toBe('critical');
  });

  it('still reports a bidi override in a comment of the bundle (Trojan Source)', async () => {
    const dir = project({ [VENDOR]: xregexpMin('/*\u202E } \u2066if (isAdmin)\u2069 \u2066 begin admins only */') });
    const hit = (await stego(dir)).find((f) => f.checkId === 'UNICODE-STEGO-001' && f.file === VENDOR);
    expect(hit?.severity).toBe('critical');
  });

  it('still reports plane-14 tag characters appended to a minified bundle', async () => {
    const tags = Array.from('payload', (c) => String.fromCodePoint(0xE0000 + c.charCodeAt(0))).join('');
    const dir = project({ [VENDOR]: xregexpMin(`;var t="x${tags}"`) });
    // The tags break the table reading, so the file is reported again, by
    // UNICODE-STEGO-001 (the table's own code points) ahead of -004.
    const hits = (await stego(dir)).filter((f) => f.file === VENDOR).map((f) => f.checkId);
    expect(hits).toContain('UNICODE-STEGO-001');
  });

  it('still reports the same table in a file that is not minified', async () => {
    const dir = project({ 'src/table.js': `module.exports = "${DEFAULT_IGNORABLE}";\n` });
    const hit = (await stego(dir)).find((f) => f.checkId === 'UNICODE-STEGO-001' && f.file === 'src/table.js');
    expect(hit?.severity).toBe('critical');
  });

  describe('isMinifiedUnicodeClassData', () => {
    it('accepts a sorted range table in a .min.js file', () => {
      expect(isMinifiedUnicodeClassData('x.min.js', `var a="${INHERITED}";`)).toBe(true);
      expect(isMinifiedUnicodeClassData('x.min.js', `var a="${COMMON}";`)).toBe(true);
    });

    it('rejects a file with no reported code point', () => {
      expect(isMinifiedUnicodeClassData('x.min.js', 'var a="\u0300-\u036F";')).toBe(false);
    });

    it('rejects a run with too few ranges or out of order', () => {
      expect(isMinifiedUnicodeClassData('x.min.js', 'var a="\u200B-\u200F";')).toBe(false);
      expect(isMinifiedUnicodeClassData('x.min.js', `var a="${INHERITED}\u200B";`)).toBe(false);
    });

    it('rejects a script that is neither named .min nor has a minified line', () => {
      expect(isMinifiedUnicodeClassData('x.js', `var a="${INHERITED}";\n`)).toBe(false);
      expect(isMinifiedUnicodeClassData('x.json', `"${INHERITED}${'a'.repeat(2000)}"`)).toBe(false);
    });
  });
});
