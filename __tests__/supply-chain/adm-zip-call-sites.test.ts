/**
 * QGF-254 — `adm-zip` reaches no first-party call site, and this is what says so.
 *
 * `adm-zip` is in this tree for exactly one reason: `onnxruntime-node@1.27.0`
 * declares it. Nothing under `src/` imports it, requires it, dynamically
 * imports it or calls any of its extraction entry points, and the open advisory
 * `GHSA-vwc7-r8mq-g2x9` is recorded as known-open on that basis — see
 * `docs/security/adm-zip-ghsa-vwc7-r8mq-g2x9.md`, whose verdict depends on this
 * zero being true and staying true.
 *
 * A zero is worth nothing on its own: a walk that reaches no files reports the
 * same zero as a clean tree. So this suite prints the size of the set it walked
 * in the name of the passing case, asserts that set is not empty, and is paired
 * with a planted-import case that proves the same walk fails, naming the module
 * and the line, when a call site really is there.
 *
 * The shapes below are written as expressions with escaped delimiters on
 * purpose: spelled as plain text they would match THIS file and the suite would
 * report itself as the call site it is looking for.
 */
import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const SOURCE_EXTENSIONS = ['.ts', '.tsx', '.js', '.mjs', '.cjs', '.jsx'];

/**
 * Installed and generated trees, and every dotted directory.
 *
 * `node_modules/adm-zip` obviously contains the package; the question this
 * suite asks is whether OUR code reaches it, so an installed copy is not part
 * of the walked set. `dist/` is `src/` compiled, so counting it would double
 * every finding and report a build artifact as a source call site.
 */
const SKIPPED_DIRECTORIES = ['node_modules', 'dist', 'build', 'coverage'];

interface CallSite {
  file: string;
  line: number;
  what: string;
  text: string;
}

/** Every way a caller can reach the package or the API the advisory names. */
const CALL_SITE_SHAPES: ReadonlyArray<{ what: string; expression: RegExp }> = [
  { what: 'a static import of the package', expression: /\bimport\b[^\n]*\bfrom\s*['"`]adm-zip['"`]/ },
  { what: 'a CommonJS require of the package', expression: /\brequire\s*\(\s*['"`]adm-zip['"`]\s*\)/ },
  { what: 'a dynamic import of the package', expression: /\bimport\s*\(\s*['"`]adm-zip['"`]\s*\)/ },
  { what: 'a construction of its archive type', expression: /\bnew\s+AdmZip\s*\(/ },
  { what: 'its extract-everything call', expression: /\bextractAllTo\s*\(/ },
  { what: 'its extract-one-entry call', expression: /\bextractEntryTo\s*\(/ },
  { what: 'its entry-listing call', expression: /\bgetEntries\s*\(/ },
];

function sourceFiles(root: string): string[] {
  const found: string[] = [];
  const visit = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.charAt(0) === '.' || SKIPPED_DIRECTORIES.indexOf(entry.name) !== -1) continue;
        visit(full);
      } else if (entry.isFile() && SOURCE_EXTENSIONS.indexOf(path.extname(entry.name)) !== -1) {
        found.push(full);
      }
    }
  };
  visit(root);
  return found;
}

function scan(root: string): { filesWalked: number; hits: CallSite[] } {
  const files = sourceFiles(root);
  const hits: CallSite[] = [];
  for (const file of files) {
    const relative = path.relative(root, file).split(path.sep).join('/');
    fs.readFileSync(file, 'utf8')
      .split('\n')
      .forEach((text, index) => {
        for (const shape of CALL_SITE_SHAPES) {
          if (!shape.expression.test(text)) continue;
          hits.push({ file: relative, line: index + 1, what: shape.what, text: text.trim() });
        }
      });
  }
  return { filesWalked: files.length, hits };
}

/**
 * THE ASSERTION, as a function, so the planted case below runs this and not a
 * lookalike of it. A red-proof that re-derives its own check proves the
 * detector works and says nothing about the gate.
 */
function assertNoCallSites(root: string): number {
  const { filesWalked, hits } = scan(root);
  const named = hits.map((h) => `  ${h.file}:${h.line}: ${h.what}: ${h.text}`);
  expect(
    named,
    `adm-zip reaches first-party code at:\n${named.join('\n')}\n` +
      `${filesWalked} source files walked. The record in ` +
      `docs/security/adm-zip-ghsa-vwc7-r8mq-g2x9.md says this cannot happen, so either the ` +
      `call site goes or that record does.`,
  ).toEqual([]);
  return filesWalked;
}

// Measured at collection so the count can go in the leaf name: a walk that
// reached nothing is then visible in the PASSING output, which is the whole
// difference between this and a vacuous zero.
const WALKED = scan(REPO_ROOT).filesWalked;

const plantedRoots: string[] = [];
afterAll(() => {
  for (const root of plantedRoots) fs.rmSync(root, { recursive: true, force: true });
});

describe('the adm-zip advisory reaches no first-party call site', () => {
  it(`QGF-254.AC1 no source file in the tree reaches adm-zip (${WALKED} files walked)`, () => {
    // Printed as well as named: a reporter that elides leaf names still shows
    // the size of the set this walked.
    console.log(`QGF-254.AC1 walked ${WALKED} source files under ${REPO_ROOT}`);
    expect(WALKED, 'the walk reached no files, so its zero means nothing').toBeGreaterThan(0);
    expect(assertNoCallSites(REPO_ROOT)).toBe(WALKED);
  });

  it('QGF-254.AC1 every shape it looks for is a real expression, and none of them matches this file', () => {
    // If a shape were spelled as plain text here, this suite would be its own
    // first finding — which is how a self-scanning gate quietly gets deleted.
    expect(CALL_SITE_SHAPES).toHaveLength(7);
    const self = scan(path.dirname(__filename));
    expect(self.hits, 'the shapes match their own definitions').toEqual([]);
  });

  it('QGF-254.AC2 the same walk fails on a planted import, naming the module and the line', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qgf254-adm-zip-planted-'));
    plantedRoots.push(root);
    // A copy of the tree AS THIS WALK SEES IT: every directory it descends
    // into, every file it reads, and nothing else. Copying the whole checkout
    // would drag an installed `node_modules` — which does contain adm-zip —
    // into a case about first-party reach.
    fs.cpSync(REPO_ROOT, root, {
      recursive: true,
      filter: (from: string) => {
        const base = path.basename(from);
        if (from === REPO_ROOT) return true;
        if (fs.statSync(from).isDirectory()) {
          return base.charAt(0) !== '.' && SKIPPED_DIRECTORIES.indexOf(base) === -1;
        }
        return SOURCE_EXTENSIONS.indexOf(path.extname(base)) !== -1;
      },
    });
    expect(scan(root).filesWalked, 'the scratch copy is not the walked tree').toBe(WALKED);

    // Built from a quote held in a variable so the planted line, which IS one
    // of the shapes, does not sit in this file as text the walk above can see.
    const quote = String.fromCharCode(39);
    const planted = `import AdmZip from ${quote}adm-zip${quote};`;
    const victim = path.join(root, 'src', 'hardening', 'contain.ts');
    const before = fs.readFileSync(victim, 'utf8');
    const lines = before.split('\n');
    // After the last import of the module, so it reads like a real one.
    const at = lines.reduce((last, line, i) => (/^import /.test(line) ? i : last), 0) + 1;
    lines.splice(at, 0, planted);
    fs.writeFileSync(victim, lines.join('\n'));
    expect(fs.readFileSync(victim, 'utf8')).not.toBe(before); // the plant applied

    let message = '';
    expect(() => {
      try {
        assertNoCallSites(root);
      } catch (err) {
        message = (err as Error).message;
        throw err;
      }
    }, 'the planted import was not caught').toThrow();

    expect(message).toContain(`src/hardening/contain.ts:${at + 1}`);
    expect(message).toContain('a static import of the package');
    expect(scan(root).hits).toHaveLength(1);
  });
});
