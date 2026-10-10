// A scan's findings and score do not depend on the operator's home directory.
//
// The bundled neural classifier (`TMENeuralClassifier`) used to load
// `nanomind-tme.bin` from `~/.opena2a/nanomind/models`, or from a sibling
// training checkout, whenever one was there. No release pins that file, so the
// weights a scan ran were whatever the operator had left in their home
// directory. An older file there labelled two corpus SOUL fixtures malicious;
// that label kept a confident benign reading from switching the
// prompt-hardening checks off, so AST-PROMPT-001, -003 and -004 appeared and
// both scores read 65 on that machine and 69 everywhere else.
//
// Every layer below runs under an empty HOME and under a HOME holding a
// synthetic model at that path. Every weight in it is zero except the
// classifier bias, so any input reads `injection` at ~0.9996: if a scan reads
// it at all, the verdict moves.
//
//  1. The classifier loads nothing from HOME, and still loads a directory it
//     is given, which shows the synthetic model is a working one.
//  2. Compile and prompt analysis of a committed SOUL fixture, in process and
//     offline. The pinned classifier is replaced by a fixed confident-benign
//     reading. The two HOMEs must give the same intent and the same findings,
//     and the synthetic model, handed over explicitly, must change both.
//  3. `secure --json` on the corpus SOUL fixtures and the committed fixture,
//     where the corpus is checked out (it is not in this repository): equal
//     exit status, score and finding tuples.

import { describe, it, expect, beforeAll, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { tempDir } from '../helpers/temp-dir';
import { assertDistFreshIfPresent } from '../helpers/dist-freshness';

// Tier 1 stands in for the pinned classifier's confident benign reading of a
// hardened SOUL, without downloading it. Everything else in the module is real.
vi.mock('../../src/nanomind-core/inference/tme-classifier', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/nanomind-core/inference/tme-classifier')>()),
  getTMEClassifier: () => ({
    classifyAsync: async () => ({
      intentClass: 'benign',
      attackClass: 'none',
      confidence: 0.95,
      topClasses: [],
    }),
  }),
}));

import { TMENeuralClassifier } from '../../src/nanomind-core/inference/tme-neural';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { analyzePrompt } from '../../src/nanomind-core/analyzers/prompt-analyzer';
import type { NeuralVerdictSource } from '../../src/nanomind-core/types';

const REPO_ROOT = join(__dirname, '..', '..');
const CLI = join(REPO_ROOT, 'dist', 'cli.js');
const SOUL_FIXTURE = join(REPO_ROOT, '__tests__', 'fixtures', 'home-independence');
const CORPUS_SOUL = join(process.env.OPENA2A_CORPUS_PATH ?? join(homedir(), '.opena2a', 'corpus'), 'soul');
const CORPUS_FIXTURES = [
  join(CORPUS_SOUL, 'benign', 'hardened-soul'),
  join(CORPUS_SOUL, 'buggy', 'partial-controls-soul'),
  join(CORPUS_SOUL, 'malicious', 'permissive-overrides-soul'),
];

/**
 * Writes a `nanomind-tme.bin` and `tokenizer.json` the classifier can load.
 * All zero-valued tensors share one zero region, so the file is ~256 KB.
 */
function writeSyntheticTier0Model(dir: string): void {
  mkdirSync(dir, { recursive: true });
  const zeroBytes = 512 * 128 * 4;
  const meta: Record<string, { shape: number[]; offset: number; size: number }> = {};
  const zero = (key: string, shape: number[]) => {
    meta[key] = { shape, offset: 0, size: shape.reduce((a, b) => a * b, 1) * 4 };
  };
  zero('embedding.weight', [2, 128]);
  for (let layer = 0; layer < 8; layer++) {
    zero(`layers.${layer}.in_proj.weight`, [512, 128]);
    zero(`layers.${layer}.in_proj.bias`, [512]);
    zero(`layers.${layer}.out_proj.weight`, [128, 256]);
    zero(`layers.${layer}.out_proj.bias`, [128]);
    zero(`layers.${layer}.norm.weight`, [128]);
    zero(`layers.${layer}.norm.bias`, [128]);
  }
  zero('final_norm.weight', [128]);
  zero('final_norm.bias', [128]);
  zero('classifier.weight', [9, 128]);
  meta['classifier.bias'] = { shape: [9], offset: zeroBytes, size: 9 * 4 };
  const bias = new Float32Array(9);
  bias[1] = 10; // 'injection'
  const header = Buffer.from(JSON.stringify(meta), 'utf-8');
  const headerLen = Buffer.alloc(4);
  headerLen.writeUInt32LE(header.length, 0);
  writeFileSync(
    join(dir, 'nanomind-tme.bin'),
    Buffer.concat([headerLen, header, Buffer.alloc(zeroBytes), Buffer.from(bias.buffer)]),
  );
  writeFileSync(join(dir, 'tokenizer.json'), '{}');
}

const emptyHome = tempDir('hma-home-empty-');
const populatedHome = tempDir('hma-home-populated-');
const populatedModelDir = join(populatedHome, '.opena2a', 'nanomind', 'models');
writeSyntheticTier0Model(populatedModelDir);

async function withHome<T>(home: string, fn: () => T | Promise<T>): Promise<T> {
  const saved = process.env.HOME;
  process.env.HOME = home;
  try {
    return await fn();
  } finally {
    if (saved === undefined) delete process.env.HOME;
    else process.env.HOME = saved;
  }
}

describe('the bundled neural classifier reads no model from HOME', () => {
  it('loads nothing under a HOME that holds a model at ~/.opena2a/nanomind/models', async () => {
    expect(await withHome(populatedHome, () => new TMENeuralClassifier().load())).toBe(false);
    expect(await withHome(emptyHome, () => new TMENeuralClassifier().load())).toBe(false);
  });

  it('loads the same synthetic model when it is handed the directory', () => {
    const explicit = new TMENeuralClassifier(populatedModelDir);
    expect(explicit.load()).toBe(true);
    const verdict = explicit.classify('Answer questions about orders.');
    expect(verdict.intentClass).toBe('malicious');
    expect(verdict.attackClass).toBe('injection');
    expect(verdict.confidence).toBeGreaterThan(0.99);
  });
});

describe('compile and prompt analysis are the same under an empty and a populated HOME', () => {
  const content = readFileSync(join(SOUL_FIXTURE, 'SOUL.md'), 'utf-8');

  async function analyze(neuralClassifier?: NeuralVerdictSource) {
    const compiler = new SemanticCompiler({ useNanoMind: true, neuralClassifier });
    const { ast } = await compiler.compile(content, join(SOUL_FIXTURE, 'SOUL.md'));
    const findings = analyzePrompt(ast, a => compiler.verifyAST(a), undefined, content)
      .filter(f => !f.passed)
      .map(f => `${f.checkId}|${f.severity}|${f.line ?? ''}`)
      .sort();
    return { intent: ast.intentClassification, confidence: ast.intentConfidence, findings };
  }

  it('gives equal intent and findings, and the HOME model would have changed both', async () => {
    const underEmpty = await withHome(emptyHome, () => analyze());
    const underPopulated = await withHome(populatedHome, () => analyze());
    expect(underPopulated).toEqual(underEmpty);
    expect(underEmpty.intent).toBe('benign');

    // Non-vacuity: the same model, when it is used, labels the fixture
    // malicious and the prompt-hardening checks come back. Equality above is
    // therefore the HOME not being read, not the model having no effect.
    const withModel = await analyze(new TMENeuralClassifier(populatedModelDir));
    expect(withModel.intent).toBe('malicious');
    expect(withModel.findings.some(f => f.startsWith('AST-PROMPT-'))).toBe(true);
    expect(withModel.findings).not.toEqual(underEmpty.findings);
  });
});

// Layer 3 runs where the corpus is checked out. Each HOME downloads nothing of
// its own: the empty HOME's first scan fetches the pinned classifier, and that
// cache is copied into the populated HOME, so the two differ only by the
// synthetic model.
const corpusPresent = existsSync(CLI) && CORPUS_FIXTURES.every(f => existsSync(f));

interface ScanReading {
  status: number | null;
  score: number;
  findings: string[];
}

function scan(target: string, home: string): ScanReading {
  const r = spawnSync(process.execPath, [CLI, 'secure', target, '--json'], {
    encoding: 'utf8',
    env: { ...process.env, HOME: home, OPENA2A_CORPUS_DETERMINISTIC: '1' },
    maxBuffer: 16 * 1024 * 1024,
    timeout: 170_000,
  });
  expect(r.stdout, `no JSON from secure ${target}: ${r.stderr}`).toBeTruthy();
  const data = JSON.parse(r.stdout);
  const findings = ((data.allFindings ?? data.findings ?? []) as Array<{
    checkId: string;
    severity: string;
    passed?: boolean;
    file?: string;
    line?: number;
  }>)
    .filter(f => f.passed === false)
    .map(f => `${f.checkId}|${f.severity}|${f.file ?? ''}|${f.line ?? ''}`)
    .sort();
  return { status: r.status, score: data.score, findings };
}

function seedPinnedCache(): boolean {
  const from = join(emptyHome, '.nanomind', 'models');
  const to = join(populatedHome, '.nanomind', 'models');
  if (!existsSync(to) && existsSync(from)) cpSync(from, to, { recursive: true });
  return existsSync(to);
}

describe.runIf(corpusPresent)('secure reads the same under an empty and a populated HOME (local-only)', { timeout: 400_000 }, () => {
  beforeAll(assertDistFreshIfPresent);

  for (const target of [...CORPUS_FIXTURES, SOUL_FIXTURE]) {
    it(`same exit status, score and findings: ${target.split('/').slice(-2).join('/')}`, ctx => {
      const underEmpty = scan(target, emptyHome);
      if (!seedPinnedCache()) {
        // Without the pinned cache the populated HOME would go to the network
        // on its own, and the two runs would differ by that, not by HOME.
        ctx.skip();
      }
      const underPopulated = scan(target, populatedHome);
      expect(underPopulated).toEqual(underEmpty);
    });
  }
});
