import { describe, it, expect } from 'vitest';
import {
  isCorpusPath,
  isTestPath,
  isExamplePath,
  isIntegrityManifestPath,
} from '../../src/hardening/path-context';

describe('path-context', () => {
  describe('isCorpusPath', () => {
    it('matches training/corpus/**', () => {
      expect(isCorpusPath('training/corpus/pretrain/000001.json')).toBe(true);
      expect(isCorpusPath('nested/training/corpus/sft/x.json')).toBe(true);
    });
    it('matches training/datasets/** and training/data/**', () => {
      expect(isCorpusPath('training/datasets/raw/x.json')).toBe(true);
      expect(isCorpusPath('training/dataset/raw/x.json')).toBe(true);
      expect(isCorpusPath('training/data/raw/x.json')).toBe(true);
    });
    it('matches dataset binary extensions anywhere', () => {
      expect(isCorpusPath('models/weights.safetensors')).toBe(true);
      expect(isCorpusPath('data/shard-000.parquet')).toBe(true);
      expect(isCorpusPath('data/shard-000.arrow')).toBe(true);
      expect(isCorpusPath('data/shard-000.tfrecord')).toBe(true);
    });
    it('does NOT match bare top-level corpus/ or datasets/ (attacker-named)', () => {
      // Bypass: attacker ships a backdoored repo with top-level corpus/
      // that is not actually an ML training directory.
      expect(isCorpusPath('corpus/x.json')).toBe(false);
      expect(isCorpusPath('datasets/x.json')).toBe(false);
      expect(isCorpusPath('dataset/x.json')).toBe(false);
    });
    it('does NOT match inside node_modules or vendored deps', () => {
      expect(isCorpusPath('node_modules/evil/training/corpus/x.json')).toBe(false);
      expect(isCorpusPath('vendor/evil/training/corpus/x.json')).toBe(false);
      expect(isCorpusPath('bower_components/evil/training/corpus/x.json')).toBe(false);
    });
    it('is case-insensitive', () => {
      expect(isCorpusPath('Training/Corpus/x.json')).toBe(true);
      expect(isCorpusPath('TRAINING/CORPUS/x.json')).toBe(true);
    });
    it('does not match unrelated paths', () => {
      expect(isCorpusPath('src/scanner.ts')).toBe(false);
      expect(isCorpusPath('README.md')).toBe(false);
      expect(isCorpusPath('examples/input.json')).toBe(false);
    });
    it('normalizes windows separators', () => {
      expect(isCorpusPath('training\\corpus\\pretrain\\x.json')).toBe(true);
    });
  });

  describe('isTestPath', () => {
    it('matches first-segment __tests__', () => {
      expect(isTestPath('__tests__/scanner.test.ts')).toBe(true);
      expect(isTestPath('__tests__/integration/x.ts')).toBe(true);
    });
    it('matches *.test and *.spec file extensions', () => {
      expect(isTestPath('src/mcp/e2e.test.ts')).toBe(true);
      expect(isTestPath('src/mcp/wrapper.test.ts')).toBe(true);
      expect(isTestPath('lib/foo.spec.ts')).toBe(true);
      expect(isTestPath('lib/foo.spec.js')).toBe(true);
      expect(isTestPath('lib/foo.spec.jsx')).toBe(true);
      expect(isTestPath('lib/foo.test.py')).toBe(true);
      expect(isTestPath('lib/foo_test.go')).toBe(true);
      expect(isTestPath('lib/foo_test.py')).toBe(true);
    });
    it('does NOT match generic tests/, test/, fixtures/, spec/ directories', () => {
      // Bypass: attacker places production code in a `tests/` directory
      // or in an `@tests/` scoped package, inheriting exemption.
      expect(isTestPath('tests/integration/auth.ts')).toBe(false);
      expect(isTestPath('test/unit/x.ts')).toBe(false);
      expect(isTestPath('fixtures/bad-mcp.json')).toBe(false);
      expect(isTestPath('spec/x.ts')).toBe(false);
    });
    it('does NOT match middle-of-path __tests__ under node_modules', () => {
      expect(isTestPath('node_modules/foo/__tests__/x.test.ts')).toBe(false);
      expect(isTestPath('node_modules/@tests/foo/leak.ts')).toBe(false);
      expect(isTestPath('vendor/evil/__tests__/x.test.ts')).toBe(false);
    });
    it('does NOT match nested __tests__ (only first segment)', () => {
      // If the exemption was just `/(^|\/)__tests__\//`, a file at
      // `packages/foo/__tests__/x.ts` would exempt — which is actually
      // a legitimate monorepo case BUT also gives attackers a
      // first-party-looking middle path to plant secrets. Narrow to
      // first-segment only; monorepo packages must use the
      // .test.ts/.spec.ts extension convention.
      expect(isTestPath('packages/foo/__tests__/x.ts')).toBe(false);
      expect(isTestPath('packages/foo/__tests__/x.test.ts')).toBe(true); // extension wins
    });
    it('is case-insensitive', () => {
      expect(isTestPath('__Tests__/scanner.Test.ts')).toBe(true);
      expect(isTestPath('src/Foo.Spec.ts')).toBe(true);
    });
    it('does not match production paths', () => {
      expect(isTestPath('src/scanner.ts')).toBe(false);
      expect(isTestPath('src/env.ts')).toBe(false);
      expect(isTestPath('lib/production.ts')).toBe(false);
    });
    it('normalizes windows separators', () => {
      expect(isTestPath('src\\mcp\\e2e.test.ts')).toBe(true);
    });
  });

  describe('isExamplePath', () => {
    it('matches examples/ and example/ directories', () => {
      expect(isExamplePath('examples/secure-agent-card/agent-card.json')).toBe(true);
      expect(isExamplePath('example/agent.json')).toBe(true);
    });
    it('matches templates/ and template/ directories', () => {
      expect(isExamplePath('templates/agent-card.json')).toBe(true);
      expect(isExamplePath('template/x.json')).toBe(true);
    });
    it('matches samples/ directories', () => {
      expect(isExamplePath('samples/agent-card.json')).toBe(true);
      expect(isExamplePath('sample/x.json')).toBe(true);
    });
    it('does NOT match docs/ (real projects ship production configs there)', () => {
      expect(isExamplePath('docs/config/prod.json')).toBe(false);
      expect(isExamplePath('doc/agent.json')).toBe(false);
    });
    it('does NOT match fixtures/ (often holds real test-data configs)', () => {
      expect(isExamplePath('fixtures/agent-card.json')).toBe(false);
      expect(isExamplePath('fixture/x.json')).toBe(false);
    });
    it('does NOT match inside node_modules', () => {
      expect(isExamplePath('node_modules/evil/examples/bad.json')).toBe(false);
      expect(isExamplePath('vendor/evil/examples/bad.json')).toBe(false);
    });
    it('is case-insensitive', () => {
      expect(isExamplePath('Examples/x.json')).toBe(true);
      expect(isExamplePath('TEMPLATES/x.json')).toBe(true);
    });
    it('does not match production paths', () => {
      expect(isExamplePath('src/scanner.ts')).toBe(false);
      expect(isExamplePath('config/agent.json')).toBe(false);
    });
  });

  describe('isIntegrityManifestPath', () => {
    it('matches *-models.json and *-manifest.json by basename', () => {
      expect(isIntegrityManifestPath('nanomind-models.json')).toBe(true);
      expect(isIntegrityManifestPath('release-manifest.json')).toBe(true);
      expect(isIntegrityManifestPath('packages/foo/integrity-manifest.json')).toBe(true);
    });
    it('matches bare manifest.json and models.json', () => {
      expect(isIntegrityManifestPath('manifest.json')).toBe(true);
      expect(isIntegrityManifestPath('models.json')).toBe(true);
      expect(isIntegrityManifestPath('src/dist/manifest.json')).toBe(true);
    });
    it('does NOT match unrelated *.json files', () => {
      expect(isIntegrityManifestPath('package.json')).toBe(false);
      expect(isIntegrityManifestPath('tsconfig.json')).toBe(false);
      expect(isIntegrityManifestPath('config/database.json')).toBe(false);
      expect(isIntegrityManifestPath('package-lock.json')).toBe(false);
    });
    it('does NOT match inside node_modules', () => {
      expect(isIntegrityManifestPath('node_modules/evil/nanomind-models.json')).toBe(false);
      expect(isIntegrityManifestPath('vendor/evil/manifest.json')).toBe(false);
    });
    it('is case-insensitive', () => {
      expect(isIntegrityManifestPath('Nanomind-Models.JSON')).toBe(true);
      expect(isIntegrityManifestPath('MANIFEST.json')).toBe(true);
    });
  });
});
