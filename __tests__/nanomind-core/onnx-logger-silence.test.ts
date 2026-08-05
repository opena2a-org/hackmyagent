/**
 * onnxruntime's native logger must not write into a security report.
 *
 * `onnxruntime-node` logs from native code, straight to stderr, in ANSI
 * colour. Nothing in HackMyAgent's rendering layer sits between it and the
 * terminal, and `NO_COLOR` does not reach it. Its default severity is WARNING,
 * and on Linux creating a session makes it enumerate PCI devices — so on any
 * host whose `/sys/devices` topology it cannot parse it prints
 *
 *   ESC[0;93m… [W:onnxruntime:onnxruntime-node, device_discovery.cc:133
 *   GetPciBusId] Skipping pci_bus_id for PCI path at "…"ESC[m
 *
 * into the middle of a scan, about a condition the reader cannot act on.
 *
 * That is how it was found: six failures in `report-render-safety.test.ts` on
 * `ubuntu-latest`, all `expected 2 to be +0`, while macOS ran the same 226
 * files green. What ties them together, measured from the two job logs:
 * ubuntu emitted nine of these warning lines and macOS emitted none; every one
 * of the nine carried exactly two control bytes, both ESC, which is the count
 * those failures reported; and eight of the nine fall inside the window in
 * which that suite was executing.
 *
 * WHAT THIS TEST CAN AND CANNOT DO. It reads the source and proves the
 * severity is CONFIGURED, at every session-creation site, including ones added
 * later. It does NOT prove onnxruntime honours it — a mock would prove even
 * less, since a fake that records an option tells you nothing about the native
 * logger that ignores it. The behavioural proof is the `ubuntu-latest` job in
 * `test-matrix.yml`, which runs the real library on the real hardware; the
 * warning does not occur on macOS at all, so it cannot be measured here.
 *
 * This is the source half of that pair, in the same spirit as
 * `render-source-gate.test.ts`: cheap, total over the file, and it fails when a
 * new unconfigured site is WRITTEN rather than when one is run.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

const SRC = path.join(__dirname, '..', '..', 'src');

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...tsFiles(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

/** Every `InferenceSession.create(...)` call in `src/`, as written. */
function sessionCreateCalls(): Array<{ file: string; call: string }> {
  const calls: Array<{ file: string; call: string }> = [];
  for (const file of tsFiles(SRC)) {
    const text = readFileSync(file, 'utf8');
    const marker = 'InferenceSession.create(';
    let from = 0;
    for (;;) {
      const at = text.indexOf(marker, from);
      if (at === -1) break;
      // Walk to the matching close paren so a multi-line options object is
      // captured whole — a regex to the end of the line would read the first
      // line of one and call the option missing.
      let depth = 0;
      let end = at + marker.length - 1;
      for (; end < text.length; end += 1) {
        if (text[end] === '(') depth += 1;
        else if (text[end] === ')') {
          depth -= 1;
          if (depth === 0) break;
        }
      }
      calls.push({ file: path.relative(SRC, file), call: text.slice(at, end + 1) });
      from = end + 1;
    }
  }
  return calls;
}

describe('onnxruntime is not allowed to log into a report', () => {
  it('finds the session-creation sites at all', () => {
    // Non-vacuity, first and on its own. Every assertion below is over this
    // list, and a list that stops being produced — the module renamed, the
    // call reshaped, the walker throwing on a directory that is not there —
    // passes all of them silently while the warning comes back.
    const calls = sessionCreateCalls();
    expect(
      calls.length,
      'no InferenceSession.create call was found in src/, so the assertions '
      + 'below are checking an empty list. If the ONNX session is now created '
      + 'somewhere else, point this gate at it rather than deleting it.',
    ).toBeGreaterThan(0);
  });

  it('sets an explicit log severity on every session it creates', () => {
    const offenders = sessionCreateCalls().filter((c) => !c.call.includes('logSeverityLevel'));
    expect(
      offenders.map((o) => `${o.file}: ${o.call.replace(/\s+/g, ' ').slice(0, 120)}`),
      'a session is created without logSeverityLevel, so onnxruntime keeps its '
      + 'WARNING default and its native logger can write raw ANSI into a scan',
    ).toEqual([]);
  });

  it('sets the severity to ERROR or quieter, not merely to something', () => {
    // `logSeverityLevel: 2` is WARNING — present, explicit, and exactly the
    // default that caused this. Asserting only on the key's presence would
    // accept it, so the value is read. 3 = ERROR, 4 = FATAL.
    for (const { file, call } of sessionCreateCalls()) {
      const m = call.match(/logSeverityLevel\s*:\s*([A-Za-z0-9_.]+)/);
      expect(m, `${file}: logSeverityLevel is not a readable literal or constant`).toBeTruthy();
      const raw = m![1];
      const resolved = /^\d+$/.test(raw)
        ? Number(raw)
        // A named constant: read its declaration out of the source rather than
        // trusting the name, so renaming it to a quiet-sounding 2 still fails.
        : Number(
          (readFileSync(path.join(SRC, file), 'utf8')
            .match(new RegExp(`${raw.split('.').pop()}\\s*=\\s*(\\d+)`)) ?? [])[1],
        );
      expect(
        resolved,
        `${file}: logSeverityLevel resolves to ${resolved}, which is WARNING or `
        + 'louder — the level that put an ANSI-coloured PCI warning inside a report',
      ).toBeGreaterThanOrEqual(3);
    }
  });

  it('quietens the environment-level logger too, before the session is created', () => {
    // Which of the two governs device discovery is not documented, and the
    // enumeration happens during `create`. Setting only the session option
    // would be a coin flip.
    const files = tsFiles(SRC).filter((f) => readFileSync(f, 'utf8').includes('InferenceSession.create('));
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      const envSet = text.search(/\benv\b[^\n]*\blogLevel\b\s*=/);
      expect(
        envSet,
        `${path.relative(SRC, file)}: the environment-level onnxruntime logLevel is `
        + 'never set, so device enumeration can still log at WARNING',
      ).toBeGreaterThan(-1);
      expect(
        envSet,
        `${path.relative(SRC, file)}: logLevel is set AFTER the session is created, `
        + 'which is too late — creating the session is what triggers the enumeration',
      ).toBeLessThan(text.indexOf('InferenceSession.create('));
    }
  });
});
