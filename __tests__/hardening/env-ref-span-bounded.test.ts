/**
 * #310 — the #308 span replace destroyed unrelated config data.
 *
 * `/\$\{[^{}]*\}/g` pairs any `${` with the NEXT `}` anywhere on the line. On a
 * minified one-line config — the normal shape for tool-written files — that
 * swallowed two unrelated keys and emitted invalid JSON, while the run reported
 * `fixed: true` at 98/100. The build it replaced was lossless there.
 *
 * Second harm at the same site: the loops are pattern-major, and detection read
 * the WORKING copy, so an earlier pattern's span replacement removed a later
 * pattern's credential from the line before that pattern was examined. The
 * second secret left the file and was never named.
 *
 * The three previous rounds each shipped a fix that was right in shape and
 * wrong in a detail the shape hid, and each time the detail was the case no
 * test covered. So these tests enumerate the WRAPPER DECISION's input space —
 * every combination of {opener present/absent} x {left padding} x {right
 * padding} x {closer present/absent/not-a-closer} — rather than the cases the
 * fix was designed around.
 *
 * Credential values are synthesised at runtime, never written as literals.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { HardeningScanner, replaceCredentialWithEnvRef } from '../../src/hardening/scanner';

const GH = `ghp_${'a'.repeat(36)}`;
const GH_RE = /ghp_[a-zA-Z0-9]{36}/g;
// Synthesised, never a literal: an AKIA-shaped literal in a committed file is
// exactly what GitHub push protection blocks.
const AKIA = `AKIA${'B'.repeat(16)}`;
const AKIA_RE = /AKIA[0-9A-Z]{16}/g;

const ref = (line: string) => replaceCredentialWithEnvRef(line, GH_RE, 'GITHUB_TOKEN');

describe('#310 bounded env-ref span replacement', () => {
  describe('the wrapper decision, across its whole input space', () => {
    // No opener: the credential stands alone, so only the credential moves.
    it('bare credential, no wrapper anywhere', () => {
      expect(ref(`{"token":"${GH}"}`)).toBe('{"token":"${GITHUB_TOKEN}"}');
    });

    // Opener + closer, no padding — the #301 exact-wrapper shape.
    it('exact wrapper is absorbed whole', () => {
      expect(ref(`{"token":"\${${GH}}"}`)).toBe('{"token":"${GITHUB_TOKEN}"}');
    });

    // The three padded shapes #308 exists for.
    it('left padding is absorbed', () => {
      expect(ref(`\${MY_${GH}}`)).toBe('${GITHUB_TOKEN}');
    });

    it('right padding is absorbed', () => {
      expect(ref(`\${${GH}_PROD}`)).toBe('${GITHUB_TOKEN}');
    });

    it('padding on both sides is absorbed', () => {
      expect(ref(`\${A_${GH}_B}`)).toBe('${GITHUB_TOKEN}');
    });

    // Opener, no closer anywhere on the line. Leaving the opener would emit
    // `${${GITHUB_TOKEN}` — the nesting this replacement exists to remove.
    it('unterminated span absorbs its opener', () => {
      expect(ref(`{"token": "\${${GH}`)).toBe('{"token": "${GITHUB_TOKEN}');
    });

    it('unterminated span with left padding absorbs its opener', () => {
      expect(ref(`{"token": "\${PREFIX_${GH}`)).toBe('{"token": "${GITHUB_TOKEN}');
    });

    // Opener present, but what follows the padding is NOT a closer. That `${`
    // is literal text that happens to precede a credential, not a reference,
    // so it is preserved. Nesting here is the lossless outcome; deleting to
    // the next `}` is what #310 is about.
    it('leaves a non-reference opener alone when a later } exists', () => {
      const out = ref(`{"a":"\${MY_${GH}","b":"KEEP"}`);
      expect(out).toBe('{"a":"${MY_${GITHUB_TOKEN}","b":"KEEP"}');
      expect(out).toContain('KEEP');
    });
  });

  describe('the destructive case #310 was filed for', () => {
    // The exact reproduction: a literal `${` earlier on the line, minified.
    it('does not pair an unrelated ${ with the credential\'s closer', () => {
      const line = `{"template":"\${","token":"${GH}","keep":"DO_NOT_LOSE_ME","port":8080}`;
      const out = ref(line);
      expect(out).toBe('{"template":"${","token":"${GITHUB_TOKEN}","keep":"DO_NOT_LOSE_ME","port":8080}');
      // The properties that actually matter, asserted directly rather than
      // inferred from the string: nothing lost, still parseable.
      const parsed = JSON.parse(out);
      expect(parsed.keep).toBe('DO_NOT_LOSE_ME');
      expect(parsed.port).toBe(8080);
      expect(parsed.template).toBe('${');
      expect(parsed.token).toBe('${GITHUB_TOKEN}');
    });

    it('does not cross a quote, comma or colon in any direction', () => {
      // Each of the three structural characters, on each side.
      expect(ref(`{"a":"\${","b":"${GH}"}`)).toContain('"a":"${"');
      expect(ref(`["\${",  "${GH}"]`)).toContain('"${"');
      expect(ref(`{"a":"x\${y","b":"${GH}","c":1}`)).toContain('"c":1');
    });
  });

  describe('multiple occurrences on one line', () => {
    it('replaces every occurrence without contaminating its neighbours', () => {
      const out = ref(`{"a":"${GH}","b":"\${${GH}}","c":"KEEP"}`);
      expect(out).toBe('{"a":"${GITHUB_TOKEN}","b":"${GITHUB_TOKEN}","c":"KEEP"}');
      expect(JSON.parse(out).c).toBe('KEEP');
    });

    it('leaves a legitimate reference on the same line untouched', () => {
      const out = ref(`{"db":"\${DATABASE_URL}","token":"\${${GH}}"}`);
      expect(JSON.parse(out).db).toBe('${DATABASE_URL}');
    });
  });
});

describe('#310 second harm: a fix must not hide another pattern\'s credential', () => {
  let dir: string;

  const scanWith = async (contents: string) => {
    dir = await mkdtemp(path.join(tmpdir(), 'hma-310-'));
    await writeFile(path.join(dir, 'config.json'), contents);
    const scanner = new HardeningScanner();
    const report = await scanner.scan({ targetDir: dir, autoFix: true });
    const after = await readFile(path.join(dir, 'config.json'), 'utf-8');
    const cred = report.findings.filter((f) => f.checkId === 'CRED-001');
    return { after, cred };
  };

  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  it('names BOTH credentials when one span holds two', async () => {
    // `credentialPatterns` runs AWS before GitHub. Absorbing the span for the
    // AWS match removes the GitHub token from the line, so with detection
    // reading the working copy the GitHub token was silently deleted: the user
    // rotates AWS and leaves the GitHub token live.
    const { after, cred } = await scanWith(`{"token": "\${${AKIA}_${GH}}"}\n`);

    // #374 — the `--fix` run also reports the copy it archived, which holds the
    // pre-fix line and fires the same check. This assertion is about the LIVE
    // file's finding, so the archived one is excluded by the flag rather than by
    // subtracting one from the expected count.
    const live = cred.filter((f) => !f.inOwnArchive);
    expect(live).toHaveLength(1);
    expect(live[0].message).toContain('AWS Access Key');
    expect(live[0].message).toContain('GitHub Token');
    // And neither secret survives in the file.
    expect(after).not.toContain(AKIA);
    expect(after).not.toContain(GH);
  });

  it('reports the same two credentials with or without --fix', async () => {
    // Detection must not depend on whether the fix ran. If it does, the fix
    // is deciding what gets reported, which is the defect above.
    const contents = `{"token": "\${${AKIA}_${GH}}"}\n`;
    const fixedRun = await scanWith(contents);
    await rm(dir, { recursive: true, force: true });

    dir = await mkdtemp(path.join(tmpdir(), 'hma-310-'));
    await writeFile(path.join(dir, 'config.json'), contents);
    const report = await new HardeningScanner().scan({ targetDir: dir, autoFix: false });
    const detectOnly = report.findings.filter((f) => f.checkId === 'CRED-001');

    expect(detectOnly).toHaveLength(1);
    // #374 — pick the LIVE finding explicitly. `cred[0]` happened to be it
    // (adopted archive findings are appended last), but relying on that makes
    // this assertion depend on append order rather than on which file it means.
    const fixedLive = fixedRun.cred.filter((f) => !f.inOwnArchive);
    expect(detectOnly[0].message).toBe(fixedLive[0].message);
  });

  it('does not destroy data or emit invalid JSON end to end', async () => {
    const { after, cred } = await scanWith(
      `{"template":"\${","token":"${GH}","keep":"DO_NOT_LOSE_ME","port":8080}\n`,
    );
    const parsed = JSON.parse(after);
    expect(parsed.keep).toBe('DO_NOT_LOSE_ME');
    expect(parsed.port).toBe(8080);
    // #374 — the live file's finding, not whichever the array happens to hold
    // first; the archived copy is never `fixed`.
    expect(cred.filter((f) => !f.inOwnArchive)[0].fixed).toBe(true);
  });
});
