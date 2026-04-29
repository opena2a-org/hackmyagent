import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'fs';
import { join, resolve } from 'path';
import {
  getTaxonomyMap,
  TAXONOMY_EXEMPT_CHECKIDS,
} from '../../src/hardening/taxonomy';

/**
 * Issue #138 — Every static-check finding HMA emits must carry a non-null
 * `attackClass`. Findings without one are invisible to the threat-matrix
 * counters, OASB attack-class indexing, and NanoMind training labels.
 *
 * This regression walks the source tree, extracts every `checkId: '...'`
 * literal in production code (excluding tests and the canonical taxonomy
 * file itself), and asserts each ID either has an entry in `TAXONOMY_MAP`
 * OR sets `attackClass:` inline within the same emission object.
 *
 * Operational/meta IDs (`FIX-ERROR`, `FIX-SUMMARY`, `SCAN-001`) are
 * exempted via `TAXONOMY_EXEMPT_CHECKIDS` because they report scanner
 * status, not security threats.
 *
 * Why this is a deterministic CI test (no spawn, no corpus):
 *   - Spawn-only / corpus-gated tests no-op silently in CI when their
 *     guards short-circuit. Issue #136 caught the same anti-pattern.
 *   - Source-text walk runs everywhere identically; failures are explicit.
 */

const SRC_ROOT = resolve(__dirname, '../../src');
const SKIP_DIRS = new Set(['__tests__', 'node_modules', 'dist', '.git']);
const SKIP_FILES = new Set([
  // The taxonomy file itself contains keys like `'CRED-001': 'RETROACTIVE-PRIV'`,
  // which are mappings, not emission sites.
  resolve(__dirname, '../../src/hardening/taxonomy.ts'),
]);

const CHECKID_RE = /checkId:\s*['"]([A-Z][A-Z0-9-]+)['"]/g;

interface Emission {
  checkId: string;
  file: string;
  line: number;
  hasInlineAttackClass: boolean;
}

/** Walk a directory tree, returning every .ts file path. */
function walkTs(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const p = join(dir, entry);
    const st = statSync(p);
    if (st.isDirectory()) {
      out.push(...walkTs(p));
    } else if (st.isFile() && entry.endsWith('.ts') && !entry.endsWith('.d.ts')) {
      if (!SKIP_FILES.has(p)) out.push(p);
    }
  }
  return out;
}

/**
 * For an emission found at `lines[startIdx]` (the `checkId: '...'` line),
 * scan forward up to 80 lines and return true if `attackClass:` appears
 * before the object literal terminates. The terminator heuristic — a line
 * whose trimmed end is `});` or `},` at object depth — matches both
 * `findings.push({ ... })` and `findings.push({ ... }, ...)` shapes.
 */
function findInlineAttackClass(lines: string[], startIdx: number): boolean {
  for (let j = startIdx; j < Math.min(startIdx + 80, lines.length); j++) {
    if (/attackClass:\s*['"][A-Z]/.test(lines[j])) return true;
    if (j > startIdx + 3) {
      const trimmed = lines[j].trimEnd();
      if (trimmed.endsWith('});') || trimmed.endsWith('},')) break;
    }
  }
  return false;
}

function collectEmissions(): Emission[] {
  const emissions: Emission[] = [];
  const semanticDir = resolve(SRC_ROOT, 'semantic');
  for (const file of walkTs(SRC_ROOT)) {
    const text = readFileSync(file, 'utf8');
    const lines = text.split('\n');
    // Match `checkId: '...'` (SecurityFinding shape) AND, only inside
    // `src/semantic/**`, `id: 'SEM-...'` (SemanticFinding shape — converted
    // to SecurityFinding.checkId by `toSecurityFinding`).
    const inSemantic = file.startsWith(semanticDir);
    for (let i = 0; i < lines.length; i++) {
      let id: string | undefined;
      const m1 = lines[i].match(/checkId:\s*['"]([A-Z][A-Z0-9-]+)['"]/);
      if (m1) {
        id = m1[1];
      } else if (inSemantic) {
        const m2 = lines[i].match(/\bid:\s*['"](SEM-[A-Z0-9-]+)['"]/);
        if (m2) id = m2[1];
      }
      if (!id) continue;
      emissions.push({
        checkId: id,
        file,
        line: i + 1,
        hasInlineAttackClass: findInlineAttackClass(lines, i),
      });
    }
    void CHECKID_RE;
  }
  return emissions;
}

describe('taxonomy coverage (#138)', () => {
  const taxonomy = getTaxonomyMap();
  const emissions = collectEmissions();

  it('production source emits at least one checkId', () => {
    expect(emissions.length).toBeGreaterThan(50);
  });

  it('every emitted checkId has TAXONOMY_MAP entry or inline attackClass', () => {
    const unmapped: Array<{ checkId: string; file: string; line: number }> = [];
    const seenCheckIds = new Set<string>();
    const inlineCheckIds = new Set<string>();

    for (const e of emissions) {
      if (TAXONOMY_EXEMPT_CHECKIDS.has(e.checkId)) continue;
      seenCheckIds.add(e.checkId);
      if (e.hasInlineAttackClass) inlineCheckIds.add(e.checkId);
    }

    for (const checkId of seenCheckIds) {
      const hasMap = checkId in taxonomy;
      const hasInline = inlineCheckIds.has(checkId);
      if (!hasMap && !hasInline) {
        const sites = emissions.filter((e) => e.checkId === checkId).slice(0, 2);
        for (const s of sites) {
          unmapped.push({
            checkId,
            file: s.file.replace(SRC_ROOT, 'src'),
            line: s.line,
          });
        }
      }
    }

    if (unmapped.length > 0) {
      const detail = unmapped
        .map((u) => `  - ${u.checkId}  ${u.file}:${u.line}`)
        .join('\n');
      throw new Error(
        `\n${unmapped.length} emission(s) lack attackClass.\n` +
          `Each checkId must either be in TAXONOMY_MAP (src/hardening/taxonomy.ts) ` +
          `OR set \`attackClass: '...'\` inline at the emission site.\n` +
          `If the ID is operational/meta (not a security threat), add it to ` +
          `TAXONOMY_EXEMPT_CHECKIDS.\n\n${detail}\n`,
      );
    }
  });

  it('every TAXONOMY_MAP value is non-empty', () => {
    for (const [checkId, attackClass] of Object.entries(taxonomy)) {
      expect(attackClass, `${checkId} must map to a non-empty attack class`).toBeTruthy();
      expect(attackClass.length, `${checkId} attack class must be non-empty`).toBeGreaterThan(0);
    }
  });

  it('SKILL-022 maps to SKILL-EXFIL (issue #138 headline case)', () => {
    expect(taxonomy['SKILL-022']).toBe('SKILL-EXFIL');
  });

  it('TAXONOMY_EXEMPT_CHECKIDS only lists operational/meta IDs', () => {
    for (const id of TAXONOMY_EXEMPT_CHECKIDS) {
      // Exempt IDs must NOT be in TAXONOMY_MAP — exemption and mapping are
      // mutually exclusive (an exempt ID has no attack class by design).
      expect(id in taxonomy, `${id} is exempt; remove from TAXONOMY_MAP`).toBe(false);
    }
  });
});
