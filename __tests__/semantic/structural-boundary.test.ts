/**
 * The structural layer and the NanoMind layer share no import edge.
 *
 * `src/semantic/structural/` is deterministic rule code. It is reviewed as
 * rule code, on its own evidence, because it shares no code with the NanoMind
 * layer (`src/nanomind-core/` and the LLM analyst in `src/semantic/llm/`):
 * measured at the time this file was written, 0 imports cross that line in
 * either direction. The separation is a property of the import graph, so a
 * single added helper import erases it without any reviewer noticing. That is
 * the edge this file checks on every run.
 *
 * Three pins:
 *
 * 1. No file under `src/semantic/structural/` imports from the NanoMind layer.
 * 2. No file under the NanoMind layer imports from `src/semantic/structural/`.
 * 3. Neither NanoMind false-positive regression suite pins a `SEM-` id, so the
 *    model layer's gates never hold a structural check's output in place.
 *
 * Imports are read with the TypeScript compiler's pre-processor, so comments
 * and string contents do not count, and every shape counts: `import`,
 * `import type`, `export … from`, side-effect imports, `import()` and
 * `require()`. tsconfig.json declares no `paths` or `baseUrl`, so only a
 * relative specifier can reach another directory of `src/`. The plant cells
 * at the bottom prove the reader sees each shape.
 *
 * Direct edges only. The package barrel (`src/index.ts`) reaches both layers,
 * so the reverse transitive closure is not empty by construction and is not
 * what this file pins.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

const REPO = path.resolve(__dirname, '..', '..');
const SRC = path.join(REPO, 'src');
const STRUCTURAL = [path.join(SRC, 'semantic', 'structural')];
const NANOMIND_LAYER = [path.join(SRC, 'nanomind-core'), path.join(SRC, 'semantic', 'llm')];
const NANOMIND_GATE_SUITES = [
  path.join(REPO, '__tests__', 'nanomind-core', 'benign-fp-regression.test.ts'),
  path.join(REPO, '__tests__', 'nanomind-core', 'scanner-fp-regression.test.ts'),
];

interface Edge {
  file: string;
  specifier: string;
}

function tsFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) tsFiles(full, acc);
    else if (entry.name.endsWith('.ts')) acc.push(full);
  }
  return acc;
}

function isWithin(target: string, dir: string): boolean {
  return target === dir || target.startsWith(dir + path.sep);
}

/** Every import in `text` (as if it were `file`) that resolves into one of `dirs`. */
function crossingEdges(file: string, text: string, dirs: string[]): Edge[] {
  const { importedFiles } = ts.preProcessFile(text, true, true);
  const out: Edge[] = [];
  for (const { fileName: specifier } of importedFiles) {
    if (!specifier.startsWith('.')) continue;
    const target = path.resolve(path.dirname(file), specifier).replace(/\.(?:js|ts)$/, '');
    if (dirs.some((dir) => isWithin(target, dir))) out.push({ file, specifier });
  }
  return out;
}

function edgesFrom(fromDirs: string[], toDirs: string[]): Edge[] {
  return fromDirs
    .flatMap((dir) => tsFiles(dir))
    .flatMap((file) => crossingEdges(file, readFileSync(file, 'utf8'), toDirs));
}

function semIdCount(text: string): number {
  return (text.match(/SEM-/g) ?? []).length;
}

function boundaryMessage(edges: Edge[]): string {
  const listed = edges.map((e) => `  ${path.relative(REPO, e.file)} imports '${e.specifier}'`).join('\n');
  return [
    'An import now crosses between src/semantic/structural/ and the NanoMind layer',
    '(src/nanomind-core/, src/semantic/llm/):',
    listed,
    'The structural layer is reviewed as rule code only while it shares no code with',
    'the NanoMind layer. This edge moves it under the NanoMind layer\'s review and',
    'release gates. Stop and have the change reviewed on that basis before keeping',
    'the import, or move the shared code into a module outside both layers.',
  ].join('\n');
}

describe('src/semantic/structural/ and the NanoMind layer share no import edge', () => {
  it('reads a non-empty file set on both sides', () => {
    // An empty walk would pass every assertion below.
    expect(STRUCTURAL.flatMap((dir) => tsFiles(dir)).length).toBeGreaterThan(0);
    for (const dir of NANOMIND_LAYER) expect(tsFiles(dir).length).toBeGreaterThan(0);
  });

  it('no file under src/semantic/structural/ imports from the NanoMind layer', () => {
    const edges = edgesFrom(STRUCTURAL, NANOMIND_LAYER);
    expect(edges, boundaryMessage(edges)).toEqual([]);
  });

  it('no file under the NanoMind layer imports from src/semantic/structural/', () => {
    const edges = edgesFrom(NANOMIND_LAYER, STRUCTURAL);
    expect(edges, boundaryMessage(edges)).toEqual([]);
  });
});

describe('no NanoMind false-positive regression suite pins a SEM- id', () => {
  for (const suite of NANOMIND_GATE_SUITES) {
    it(`${path.basename(suite)} names no SEM- id`, () => {
      expect(existsSync(suite), `${path.relative(REPO, suite)} is missing; this pin reads it`).toBe(true);
      const count = semIdCount(readFileSync(suite, 'utf8'));
      expect(
        count,
        `${path.relative(REPO, suite)} names a SEM- id ${count} time(s). A NanoMind regression ` +
          'suite that pins a structural check holds that check under the NanoMind layer\'s ' +
          'release gates. Stop and have the change reviewed on that basis first.',
      ).toBe(0);
    });
  }
});

describe('plants: the edge reader sees every import shape', () => {
  const structuralFile = path.join(SRC, 'semantic', 'structural', 'planted.ts');
  const nanomindFile = path.join(SRC, 'nanomind-core', 'analyzers', 'planted.ts');
  const llmFile = path.join(SRC, 'semantic', 'llm', 'planted.ts');

  const outward: Array<[string, string]> = [
    ['named import', "import { compile } from '../../nanomind-core/compiler/semantic-compiler';"],
    ['type-only import', "import type { Budget } from '../llm/budget';"],
    ['re-export', "export { analyze } from '../../nanomind-core/analyzers';"],
    ['side-effect import', "import '../llm';"],
    ['dynamic import', "const m = await import('../../nanomind-core/orchestrate');"],
    ['require', "const c = require('../llm/client');"],
    ['.js suffix', "import { x } from '../../nanomind-core/types.js';"],
    ['directory import', "import * as nm from '../../nanomind-core';"],
  ];
  for (const [shape, line] of outward) {
    it(`structural -> NanoMind layer, ${shape}: reported`, () => {
      const edges = crossingEdges(structuralFile, line, NANOMIND_LAYER);
      expect(edges).toHaveLength(1);
      expect(boundaryMessage(edges)).toContain('src/semantic/structural/planted.ts imports');
    });
  }

  it('NanoMind core -> structural: reported', () => {
    const line = "import { McpConfigAnalyzer } from '../../semantic/structural/mcp-config';";
    expect(crossingEdges(nanomindFile, line, STRUCTURAL)).toHaveLength(1);
  });

  it('LLM analyst -> structural: reported', () => {
    expect(crossingEdges(llmFile, "export * from '../structural';", STRUCTURAL)).toHaveLength(1);
  });

  it('an import that stays outside the other layer is not reported', () => {
    const text = [
      "import type { SemanticFinding } from '../types';",
      "import { fs } from '../../hardening/tracked-fs';",
      "import { spawnSync } from 'node:child_process';",
      // Shares the directory name as a prefix only.
      "import { y } from '../../nanomind-core-extra/y';",
    ].join('\n');
    expect(crossingEdges(structuralFile, text, NANOMIND_LAYER)).toEqual([]);
  });

  it('a comment or a string naming the other layer is not an import', () => {
    const text = [
      "// import { compile } from '../../nanomind-core/compiler/semantic-compiler';",
      "/* require('../llm/client') */",
      "const doc = 'see ../../nanomind-core/README.md';",
    ].join('\n');
    expect(crossingEdges(structuralFile, text, NANOMIND_LAYER)).toEqual([]);
  });

  it('a SEM- id in a regression suite is counted', () => {
    expect(semIdCount("expect(ids).not.toContain('SEM-MCP-001');")).toBe(1);
  });
});
