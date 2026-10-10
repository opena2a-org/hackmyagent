/**
 * The README's `attack` section embeds a recording of a red-team run against a
 * live DVAA agent. The recording was made in June against an older build and
 * its caption was never checked again: the build had since changed the report
 * (`Attacks: 28 total | ...` became `Attacks: 28 sent | 28 answered | ...`),
 * the tape only ran from one machine's checkout, and nothing in the repository
 * held the output the caption's numbers came from.
 *
 * The recording now has a text version, docs/vhs/attack-dvaa-capture.txt, taken
 * from the same build against the same DVAA image. The rules below hold the
 * caption to that capture, so a re-render that changes the report has to change
 * the caption with it.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(__dirname, '../..');
const README = readFileSync(path.join(ROOT, 'README.md'), 'utf8');
const GIF = 'docs/vhs/attack-dvaa.gif';
const TAPE = 'docs/vhs/attack-dvaa.tape';
const CAPTURE = 'docs/vhs/attack-dvaa-capture.txt';

function read(rel: string): string {
  const file = path.join(ROOT, rel);
  expect(existsSync(file), `${rel} is missing`).toBe(true);
  return readFileSync(file, 'utf8');
}

/** The alt text of the README image that embeds `src`. */
function altText(src: string): string {
  const m = new RegExp(`!\\[([^\\]]*)\\]\\(${src.replace(/[.]/g, '\\.')}\\)`).exec(README);
  expect(m, `README does not embed ${src}`).not.toBeNull();
  return m![1];
}

/** The paragraph directly after the image that embeds `src`. */
function paragraphAfter(src: string): string {
  const at = README.indexOf(`](${src})`);
  expect(at).toBeGreaterThan(-1);
  const rest = README.slice(at).split('\n\n');
  return rest[1] ?? '';
}

/** The report the capture holds, from the command line to the exit line. */
function report(): string {
  const capture = read(CAPTURE);
  const start = capture.indexOf('\n$ hackmyagent attack ');
  expect(start, `${CAPTURE} holds no command line`).toBeGreaterThan(-1);
  return capture.slice(start + 1);
}

describe('README attack recording', () => {
  it('the caption states the risk score and attack counts the captured report prints', () => {
    const alt = altText(GIF);
    const out = report();

    const score = /Risk Score: (\d+\/100 \([A-Z]+\))/.exec(out);
    expect(score, 'no Risk Score line in the capture').not.toBeNull();
    expect(alt).toContain(`Risk Score: ${score![1]}`);

    const attacks = /Attacks: (\d+) sent \| (\d+) answered \| (\d+) successful \| (\d+) blocked/.exec(out);
    expect(attacks, 'no Attacks line in the capture').not.toBeNull();
    const [, sent, answered, successful, blocked] = attacks!;
    expect(alt).toContain(`${sent} sent, ${answered} answered, ${successful} successful, ${blocked} blocked`);
  });

  it('the caption states the number of categories the captured report lists', () => {
    const out = report();
    const list = out.slice(out.indexOf('\nCategories:\n') + 1).split('\n\n')[0];
    // `[-]` when an attack in the category succeeded, `[+]` when none did.
    const rows = list.split('\n').filter((l) => /^ {2}\[[-+]\] /.test(l));
    expect(rows.length).toBeGreaterThan(0);
    expect(altText(GIF)).toContain(`${rows.length} categories`);
    if (rows.every((r) => /: (\d+)\/\1 successful$/.test(r))) {
      expect(altText(GIF)).toMatch(/every attack in each one successful/);
    }
  });

  it('the caption and the capture name the same version, and the README dates the recording', () => {
    const version = /Tool: +hackmyagent (\d+\.\d+\.\d+)/.exec(read(CAPTURE));
    expect(version, `${CAPTURE} does not name the version it ran`).not.toBeNull();
    expect(altText(GIF)).toContain(`hackmyagent ${version![1]}`);
    const provenance = paragraphAfter(GIF);
    expect(provenance).toContain(`hackmyagent ${version![1]}`);
    expect(provenance).toMatch(/\b20\d\d-\d\d-\d\d\b/);
    expect(provenance).toContain(CAPTURE);
  });

  it('the README, the tape and the capture run the same command against the same DVAA image', () => {
    const typed = /^Type "(hackmyagent attack [^"|]+?)(?: \| head -\d+)?"$/m.exec(read(TAPE));
    expect(typed, `${TAPE} types no hackmyagent attack command`).not.toBeNull();
    const command = typed![1];
    expect(README).toContain(command);
    expect(report().split('\n')[0]).toBe(`$ ${command}`);

    const image = /opena2a\/dvaa:\d+\.\d+\.\d+/.exec(README);
    expect(image, 'README names no DVAA image').not.toBeNull();
    expect(read(CAPTURE)).toContain(image![0]);
    expect(read(TAPE)).toContain(image![0]);
  });

  it('the tape renders the embedded GIF from the repository root', () => {
    const tape = read(TAPE);
    expect(tape).toMatch(new RegExp(`^Output ${GIF.replace(/[.]/g, '\\.')}$`, 'm'));
    // A setup line that changes into one machine's checkout cannot be re-rendered elsewhere.
    expect(tape).not.toMatch(/^Type "[^"]*\bcd [~/]/m);
    expect(tape).toMatch(/OPENA2A_TELEMETRY=off/);
  });
});
