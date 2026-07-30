/**
 * #324 — end to end: a directory name carrying a control character must not
 * break the rendered report.
 *
 * The unit tests in `__tests__/ui/display-safe.test.ts` pin the escaping
 * function. This pins the thing the user actually sees, through the real CLI, on
 * a real tree — which is where the defect was found and where a future renderer
 * that forgets to escape would reappear.
 *
 * Two lines were broken by one newline in a directory name:
 *
 *   the location header   `2026-01-01-000000` / `EVIL-SECOND-LINE/config.json:2`
 *   the fix citation      `Fix: rm -rf '/…/2026-01-01-000000`   <- ends mid-quote
 *
 * The emitted command was never wrong: `shellQuote` is total, and executing the
 * argument removes the right directory. Only the DISPLAY was truncated, which is
 * why the `--json` half of this file asserts the bytes are still exact.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const CLI = path.resolve(__dirname, '../../dist/cli.js');
const FAKE_GH_TOKEN = `ghp_${'a'.repeat(36)}`;
const STAMP_WITH_NEWLINE = '2026-01-01-000000\nEVIL-SECOND-LINE';

let dir: string;

function runSecure(args: string[]): string {
  try {
    return execFileSync(process.execPath, [CLI, 'secure', dir, ...args], {
      encoding: 'utf8',
      timeout: 180_000,
      env: { ...process.env, NO_COLOR: '1' },
    });
  } catch (e: unknown) {
    // `secure` exits 1 on findings, which is the case under test.
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

beforeAll(() => {
  if (!existsSync(CLI)) throw new Error('dist/cli.js missing — run npm run build');
  dir = mkdtempSync(path.join(tmpdir(), 'hma-324-'));
  writeFileSync(path.join(dir, 'package.json'), '{"name":"p","version":"1.0.0"}\n');
  // A REAL archive: the manifest lists the file, so the citation is the
  // destructive `rm -rf` one (#319). That is the line whose truncation matters
  // most, because it is the one the user is meant to paste.
  const archive = path.join(dir, '.hackmyagent-backup', STAMP_WITH_NEWLINE);
  mkdirSync(archive, { recursive: true });
  writeFileSync(
    path.join(archive, '.manifest.json'),
    JSON.stringify({ version: 2, existingFiles: ['config.json'], absentAtBackup: [], createdFiles: [] }),
  );
  writeFileSync(
    path.join(archive, 'config.json'),
    `${JSON.stringify({ github: FAKE_GH_TOKEN }, null, 2)}\n`,
  );
}, 300_000);

afterAll(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe('#324 rendering a path that contains a control character', () => {
  it('renders the whole fix command on one line, with the quote closed', () => {
    const out = runSecure([]);
    const fixLine = out.split('\n').find((l) => l.includes('rm -rf'));

    // Non-vacuity: the destructive citation must be present. If the finding did
    // not fire, or provenance was not proven, there is no line to assert about.
    expect(fixLine, 'no rm -rf citation was rendered; this test measures nothing')
      .toBeDefined();
    expect(
      fixLine,
      'the fix line does not name the archive directory, so it is not the line under test',
    ).toContain('2026-01-01-000000');
    expect(
      fixLine,
      'the rendered command ends mid-quote — pasting it leaves the shell at a '
      + 'continuation prompt',
    ).toMatch(/'$/);
    expect(fixLine, 'the escaped newline is not visible in the rendered path')
      .toContain('\\nEVIL-SECOND-LINE');
  });

  /**
   * EVERY line that names the path, not the first one found.
   *
   * The first version of this test looked at one line and passed while a third
   * consumer of the same path — the Verdict summary — was still emitting it raw.
   * A report has several places that name a file, and one unescaped site is the
   * whole defect, so the assertion has to be universal.
   */
  it('does not split any line that names the path', () => {
    const out = runSecure([]);
    const lines = out.split('\n');
    const naming = lines.filter((l) => l.includes('EVIL-SECOND-LINE'));

    // Non-vacuity: the path has to appear somewhere, or nothing is under test.
    expect(naming.length, 'no rendered line names the archive path').toBeGreaterThan(0);

    for (const line of naming) {
      expect(
        line,
        `a rendered line names the path with a raw newline, so the line above it was `
        + `split: ${JSON.stringify(line)}`,
      ).toContain('\\nEVIL-SECOND-LINE');
    }
    // A newline from the path would leave `EVIL-SECOND-LINE` starting a line of
    // its own, with none of the report's own indentation or box prefix.
    for (const line of lines) {
      expect(
        line.startsWith('EVIL-SECOND-LINE'),
        `the path's newline became a line break: ${JSON.stringify(line)}`,
      ).toBe(false);
    }
  });

  it('emits no raw ESC, CR or other control byte from the scanned tree', () => {
    const out = runSecure([]);
    // Newline and tab are the tool's own layout, so they cannot be judged here —
    // an injected newline is what the previous test covers, by asserting no line
    // splits. Everything else below 0x20 could only have come from a path.
    const offenders = [...out].filter((ch) => {
      const c = ch.codePointAt(0) ?? 0;
      return c < 0x20 && c !== 0x0a && c !== 0x09;
    });
    expect(offenders.length, 'a raw control character from the scanned tree reached the terminal')
      .toBe(0);
  });

  it('keeps the exact bytes in --json, so machine consumers are unaffected', () => {
    // The escaping is a DISPLAY concern. A consumer parsing `--json` needs the
    // real path, and the real command.
    const j = JSON.parse(runSecure(['--json'])) as {
      findings: { checkId: string; file?: string; fix?: string }[];
    };
    const finding = j.findings.find((f) => f.checkId === 'CRED-001');
    expect(finding, 'no CRED-001 in the JSON output').toBeDefined();
    expect(finding!.file, 'the JSON path was escaped; it must carry the real bytes')
      .toContain('\n');
    expect(finding!.fix, 'the JSON fix command was escaped; it must be runnable verbatim')
      .toContain('\n');
  });
});
