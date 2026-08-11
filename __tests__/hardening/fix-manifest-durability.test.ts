/**
 * #499 — the rollback manifest is persisted BEFORE the semantic pass runs.
 *
 * `recordCreatedFiles` writes the hashed record of what a `--fix` generated.
 * `rollback` reads that record to decide which files HMA created and may
 * therefore remove. Between "the fix is on disk" and "the manifest says so"
 * there is a window in which an interrupt — Ctrl-C, SIGTERM, OOM, a crash —
 * leaves a generated file on disk with `createdFiles: []` recorded, and
 * `rollback` then prints `[+] Rollback complete` having restored nothing. A
 * safety mechanism reporting success over a tree it did not restore is worse
 * than one that fails loudly.
 *
 * That window is ~45ms when the manifest write follows the fix directly. #499's
 * first cut moved the NanoMind semantic pass — a model load plus a whole
 * compile set — in front of it, measured at ~3.4s on a THREE-file fixture and
 * scaling with the tree. The defect was not the window's existence, which
 * predates this; it was widening it by two orders of magnitude while the
 * relocation's own comment claimed that moving the call "must not change what a
 * failure costs".
 *
 * This pins the ordering directly rather than by timing, which would be flaky.
 * `semanticPass` is a public `ScanOptions` hook, so the test injects one that
 * inspects the manifest at the exact moment the pass would run.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { HardeningScanner } from '../../src/hardening/scanner';

const roots: string[] = [];

afterAll(() => {
  for (const r of roots) {
    try { fs.rmSync(r, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

/** A tree with no `.gitignore`, so `--fix` has something to generate. */
function fixableTree(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-499-manifest-'));
  roots.push(dir);
  fs.mkdirSync(path.join(dir, 'src'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'src', 'util.js'), 'function add(a,b){return a+b;}\nmodule.exports={add};\n');
  fs.writeFileSync(path.join(dir, 'package.json'), '{"name":"m","version":"1.0.0"}\n');
  return dir;
}

/** Every `.manifest.json` under the backup dir, newest first. */
function manifests(dir: string): any[] {
  const backup = path.join(dir, '.hackmyagent-backup');
  if (!fs.existsSync(backup)) return [];
  return fs.readdirSync(backup)
    .map((d) => path.join(backup, d, '.manifest.json'))
    .filter((p) => fs.existsSync(p))
    .map((p) => {
      try { return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch { return null; }
    })
    .filter(Boolean);
}

describe('#499 the rollback manifest survives an interrupt during the semantic pass', () => {
  it('createdFiles is already persisted when the semantic pass is invoked', async () => {
    const dir = fixableTree();
    let seenAtPassTime: string[] | null = null;
    let passRan = false;

    const scanner = new HardeningScanner();
    await scanner.scan({
      targetDir: dir,
      autoFix: true,
      cliName: 'hackmyagent',
      semanticPass: async () => {
        passRan = true;
        // Read the manifest from DISK at exactly the moment the semantic pass
        // gets control. This is the state an interrupt here would leave behind.
        const created = manifests(dir).flatMap((m) => (m.createdFiles ?? []).map((c: any) => c.path));
        seenAtPassTime = created;
        return undefined;
      },
    });

    // Guard the guard: if the hook never ran, `seenAtPassTime` stays null and
    // every assertion below would be vacuously satisfiable.
    expect(passRan).toBe(true);

    // The fix must actually have generated something, or the test proves
    // nothing about durability.
    const finalCreated = manifests(dir).flatMap((m) => (m.createdFiles ?? []).map((c: any) => c.path));
    expect(finalCreated.length).toBeGreaterThan(0);

    // The record the interrupt would leave must already be the complete one.
    expect(seenAtPassTime).not.toBeNull();
    expect([...(seenAtPassTime as unknown as string[])].sort()).toEqual([...finalCreated].sort());
  }, 240_000);
});
