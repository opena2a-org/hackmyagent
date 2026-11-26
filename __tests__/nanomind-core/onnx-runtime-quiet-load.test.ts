/**
 * Loading onnxruntime-node must not print into a scan.
 *
 * On Linux arm64 under Apple silicon virtualization the library prints
 * `onnxruntime cpuid_info warning: Unknown CPU vendor` to stderr while it is
 * being loaded, before `env.logLevel` or a session's `logSeverityLevel` can
 * apply, so `secure` and `check` printed it into their reports. The scan now
 * loads the library in a child process first and does not load it in-process
 * when that load printed anything naming onnxruntime.
 *
 * The child-process check is exercised here against modules that do and do
 * not write such a line while they are required, written with
 * `fs.writeSync(2, …)` as the native library writes straight to the file
 * descriptor. The real warning needs that virtualized host and cannot be
 * produced here.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { moduleLoadsQuietly, onnxRuntimeLoadsQuietly } from '../../src/nanomind-core/inference/onnx-runtime';

const CLASSIFIER = path.join(__dirname, '..', '..', 'src', 'nanomind-core', 'inference', 'tme-classifier.ts');

function moduleWriting(body: string): string {
  const file = path.join(tempDir('hma-ort-quiet-'), 'module.cjs');
  writeFileSync(file, `const fs = require('node:fs');\n${body}\nmodule.exports = {};\n`);
  return file;
}

describe('onnxruntime is loaded into a scan only where loading it prints nothing', () => {
  it('reports a module that prints the cpuid warning while it loads', () => {
    const noisy = moduleWriting(
      "fs.writeSync(2, 'onnxruntime cpuid_info warning: Unknown CPU vendor. cpuinfo_vendor value: 0\\n');",
    );
    expect(moduleLoadsQuietly(noisy)).toBe(false);
  });

  it('reports the same warning written to stdout', () => {
    const noisy = moduleWriting(
      "fs.writeSync(1, 'onnxruntime cpuid_info warning: Unknown CPU vendor. cpuinfo_vendor value: 0\\n');",
    );
    expect(moduleLoadsQuietly(noisy)).toBe(false);
  });

  it('accepts a module that loads silently', () => {
    // Non-vacuity for the two cases above: a check that always answered no
    // would pass both of them.
    expect(moduleLoadsQuietly(moduleWriting(''))).toBe(true);
  });

  it('does not print the child load into the calling process', () => {
    // The child's output is captured, never passed through; the answer is all
    // that comes back.
    const noisy = moduleWriting("fs.writeSync(2, 'onnxruntime cpuid_info warning: test\\n');");
    const writes: string[] = [];
    const original = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: unknown, ...rest: unknown[]) => {
      writes.push(String(chunk));
      return (original as (...a: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stderr.write;
    try {
      moduleLoadsQuietly(noisy);
    } finally {
      process.stderr.write = original;
    }
    expect(writes.join('')).not.toContain('cpuid_info');
  });

  it('does not probe outside Linux, where the library does not detect the CPU that way', () => {
    if (process.platform === 'linux') return;
    expect(onnxRuntimeLoadsQuietly()).toBe(true);
  });

  it('checks before the classifier first loads the library', () => {
    const source = readFileSync(CLASSIFIER, 'utf8');
    const start = source.indexOf('private async loadOnnx()');
    expect(start, 'loadOnnx was not found in tme-classifier.ts').toBeGreaterThan(-1);
    const body = source.slice(start);
    const check = body.indexOf('onnxRuntimeLoadsQuietly()');
    const load = body.indexOf('loadOnnxRuntime()');
    expect(check, 'loadOnnx does not call onnxRuntimeLoadsQuietly').toBeGreaterThan(-1);
    expect(load).toBeGreaterThan(-1);
    expect(check).toBeLessThan(load);
  });
});
