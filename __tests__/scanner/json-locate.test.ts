/**
 * #379 — a structured permission grant is cited from the parse, not from a
 * text search. `lineOfJsonValue` follows the path `walkConfigForGrants`
 * recorded; these tests pin that it lands on exactly that value, that any
 * disagreement yields no line rather than a different one, and that its cost is
 * measured on 200KB and 4MB configs through both callers.
 */
import { describe, it, expect } from 'vitest';
import { performance } from 'node:perf_hooks';
import { lineOfJsonValue } from '../../src/scanner/json-locate';
import { findPermissionGrant, parseAiConfig, walkConfigForGrants, proseAllowEntry } from '../../src/scanner/permission-grant';

describe('lineOfJsonValue follows structure', () => {
  it('compares keys decoded, as the parser saw them', () => {
    const text = '{\n  "perm\\u0069ssions": {\n    "\\u0061llow": [\n      "Bash(*)"\n    ]\n  }\n}';
    expect(lineOfJsonValue(text, ['permissions', 'allow', 0], 'Bash(*)')).toBe(4);
  });

  it('descends into the LAST duplicate key, as JSON.parse keeps it', () => {
    const text = '{\n"allow": ["Bash(npm test)"],\n"allow": [\n"Bash(*)"\n]\n}';
    expect((JSON.parse(text) as { allow: string[] }).allow[0]).toBe('Bash(*)');
    expect(lineOfJsonValue(text, ['allow', 0], 'Bash(*)')).toBe(4);
    // The first duplicate is not what the parser kept, so it is never cited.
    expect(lineOfJsonValue(text, ['allow', 0], 'Bash(npm test)')).toBeUndefined();
  });

  it('never lands on a deny entry holding the same text', () => {
    const text = '{\n  "deny": [\n    "Bash(*)"\n  ],\n  "allow": [\n    "Bash(*)"\n  ]\n}';
    expect(lineOfJsonValue(text, ['allow', 0], 'Bash(*)')).toBe(6);
  });

  it('skips JSONC comments, including ones that look like structure', () => {
    const text = [
      '{',
      '  // "allow": ["Bash(*)"],',
      '  /* "allow": [',
      '     "Bash(*)" ] } */',
      '  "allow": [ // { [ "',
      '    "Bash(npm test)", /* ] */',
      '    "Bash(*)",',
      '  ],',
      '}',
    ].join('\n');
    expect(lineOfJsonValue(text, ['allow', 1], 'Bash(*)')).toBe(7);
  });

  it('is not moved by braces, brackets or quotes inside strings', () => {
    const text = '{\n  "note": "} ] { [ \\" // /*",\n  "allow": [\n    "Bash(*)"\n  ]\n}';
    expect(lineOfJsonValue(text, ['allow', 0], 'Bash(*)')).toBe(4);
  });

  it('handles a byte order mark and CRLF line endings', () => {
    const text = '﻿{\r\n  "allow": [\r\n    "Bash(*)"\r\n  ]\r\n}';
    expect(lineOfJsonValue(text, ['allow', 0], 'Bash(*)')).toBe(3);
  });

  it('follows index paths into nested arrays', () => {
    const text = '{\n  "allow": [\n    "Read(src/**)",\n    [\n      "x",\n      "Bash(*)"\n    ]\n  ]\n}';
    expect(lineOfJsonValue(text, ['allow', 1, 1], 'Bash(*)')).toBe(6);
  });

  it('cites a boolean grant', () => {
    const text = '{\n  "skipPermissions": false,\n  "nested": {\n    "skipPermissions": true\n  }\n}';
    expect(lineOfJsonValue(text, ['nested', 'skipPermissions'], true)).toBe(4);
    expect(lineOfJsonValue(text, ['skipPermissions'], true)).toBeUndefined();
  });

  it.each([
    ['a path that does not resolve', '{"allow": ["Bash(*)"]}', ['deny', 0]],
    ['an index past the end', '{"allow": ["Bash(*)"]}', ['allow', 1]],
    ['a key where an index is expected', '{"allow": {"0": "Bash(*)"}}', ['allow', 0]],
    ['an unterminated string', '{"allow": ["Bash(*)]}', ['allow', 0]],
    ['a value that is not the judged one', '{"allow": ["Bash(npm test)"]}', ['allow', 0]],
  ])('returns undefined for %s, never a guess', (_name, text, p) => {
    expect(lineOfJsonValue(text as string, p as Array<string | number>, 'Bash(*)')).toBeUndefined();
  });
});

describe('lineOfJsonValue agrees with the parser on generated documents', () => {
  /** Deterministic PRNG so a failure reproduces. */
  function rng(seed: number): () => number {
    let s = seed >>> 0;
    return () => {
      s = (s + 0x6d2b79f5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  /**
   * Serialise a random document with random layout, recording the line of
   * every string leaf by construction. Duplicate keys are emitted on purpose;
   * a later duplicate overwrites the earlier record, as JSON.parse does.
   */
  function generate(seed: number) {
    const r = rng(seed);
    const pick = <T>(xs: T[]) => xs[Math.floor(r() * xs.length)];
    let out = '';
    let line = 1;
    const leaves = new Map<string, { path: Array<string | number>; value: string; line: number }>();
    const emit = (t: string) => { out += t; for (const ch of t) if (ch === '\n') line++; };
    const gap = () => emit(pick(['', ' ', '\n', '\n    ', '\t', ' // c { [ "\n', ' /* ] } \n */ ']));
    const KEYS = ['allow', 'deny', 'permissions', 'a', '\\u0061llow', 'x y', 'ask'];
    const decode = (k: string) => JSON.parse(`"${k}"`) as string;

    const value = (depth: number, p: Array<string | number>): void => {
      const kind = depth > 4 ? 'string'
        : depth < 2 ? pick(['object', 'array'])
        : pick(['string', 'string', 'object', 'array', 'literal']);
      if (kind === 'string') {
        // JSON source spellings: escaped quotes, structure and comment
        // openers inside strings, and a \u escape.
        const v = pick(['Bash(*)', 'Read(src/**)', 'q}\\"]', 'a\\"b', '//x', '/*', 'B\\u0061sh(*)']);
        const decoded = JSON.parse(`"${v}"`) as string;
        leaves.set(JSON.stringify(p), { path: [...p], value: decoded, line });
        emit(`"${v}"`);
      } else if (kind === 'literal') {
        emit(pick(['true', 'false', 'null', '12', '-3.5e2']));
      } else if (kind === 'object') {
        emit('{');
        const n = 1 + Math.floor(r() * 5);
        for (let i = 0; i < n; i++) {
          gap();
          const k = pick(KEYS);
          const dk = decode(k);
          // A duplicate key replaces the earlier subtree entirely.
          const prefix = JSON.stringify([...p, dk]).slice(0, -1);
          for (const id of [...leaves.keys()]) if (id.startsWith(prefix)) leaves.delete(id);
          emit(`"${k}"`); gap(); emit(':'); gap();
          value(depth + 1, [...p, dk]);
          gap();
          if (i < n - 1 || r() < 0.3) emit(','); // trailing comma sometimes
        }
        gap(); emit('}');
      } else {
        emit('[');
        const n = 1 + Math.floor(r() * 5);
        for (let i = 0; i < n; i++) {
          gap(); value(depth + 1, [...p, i]); gap();
          if (i < n - 1 || r() < 0.3) emit(',');
        }
        gap(); emit(']');
      }
    };
    emit('{'); gap(); emit('"root"'); emit(':'); gap(); value(0, ['root']); gap(); emit('}');
    return { text: out, leaves: [...leaves.values()] };
  }

  it('lands on the recorded line of every string leaf in 500 generated documents', () => {
    let checked = 0;
    const wrong: string[] = [];
    for (let seed = 1; seed <= 500; seed++) {
      const { text, leaves } = generate(seed);
      for (const leaf of leaves) {
        checked++;
        const got = lineOfJsonValue(text, leaf.path, leaf.value);
        if (got !== leaf.line) wrong.push(`seed ${seed} ${JSON.stringify(leaf.path)}: expected ${leaf.line}, got ${got}`);
      }
    }
    expect(checked, 'the generator produced too few leaves to mean anything').toBeGreaterThan(5000);
    expect(wrong.slice(0, 5)).toEqual([]);
  });
});

describe('the citation costs are measured, not argued (#379 criteria 1 and 2)', () => {
  /** A settings file of about `bytes`, with the only grant as its LAST allow entry. */
  function bigSettings(bytes: number, oneLine: boolean): string {
    const nl = oneLine ? '' : '\n';
    const deny: string[] = [];
    const allow: string[] = [];
    let size = 0;
    for (let i = 0; size < bytes / 2; i++) {
      const d = `"Bash(*)"`; // identical text in the deny list: the hazard
      const a = `"Bash(npm run task-${i})"`;
      deny.push(d); allow.push(a);
      size += d.length + a.length + 8;
    }
    allow.push('"Bash(*)"');
    return `{${nl}"permissions": {${nl}"deny": [${nl}${deny.join(`,${nl}`)}${nl}],${nl}"allow": [${nl}${allow.join(`,${nl}`)}${nl}]${nl}}${nl}}`;
  }

  function best(fn: () => void, runs = 3): number {
    let min = Infinity;
    for (let i = 0; i < runs; i++) {
      const t = performance.now();
      fn();
      min = Math.min(min, performance.now() - t);
    }
    return min;
  }

  it.each([
    ['200KB, one entry per line', 200_000, false],
    ['200KB, one line', 200_000, true],
    ['4MB, one entry per line', 4_000_000, false],
    ['4MB, one line', 4_000_000, true],
  ])('%s: detect and secure both cite the allow entry, in time linear with a JSON.parse', (_n, bytes, oneLine) => {
    const text = bigSettings(bytes as number, oneLine as boolean);
    const expectedLine = oneLine ? 1 : text.split('\n').length - 3;

    // detect's caller.
    const grant = findPermissionGrant(text, '.claude/settings.json');
    expect(grant?.line).toBe(expectedLine);

    // secure's caller (CLAUDE-002): parse, walk, locate.
    const walked = walkConfigForGrants(parseAiConfig(text, 'settings.json'), proseAllowEntry);
    expect(walked?.at).toBeDefined();
    expect(lineOfJsonValue(text, walked!.at!.path, walked!.at!.value)).toBe(expectedLine);

    // The locator alone, against the parse it follows. Measured on the same
    // text in the same process, so machine load moves both. Attempt 2 was
    // 180x its baseline (52.5s against 0.29s); linear work sits within a
    // small constant of JSON.parse.
    const parse = best(() => JSON.parse(text));
    const locate = best(() => lineOfJsonValue(text, walked!.at!.path, walked!.at!.value));
    expect(locate, `locate ${locate.toFixed(1)}ms vs JSON.parse ${parse.toFixed(1)}ms`).toBeLessThan(Math.max(25 * parse, 50));
  }, 120_000);

  it('stays linear when every level of a deep path is wide (O(length x depth))', () => {
    // 12 levels, each carrying a wide sibling before the key the path follows.
    const wide = `"pad": [${Array.from({ length: 20_000 }, (_, i) => `"v${i}"`).join(',')}]`;
    let inner = '{"allow": ["Bash(*)"]}';
    const path: Array<string | number> = [];
    for (let i = 0; i < 12; i++) { inner = `{${wide}, "k${i}": ${inner}}`; path.unshift(`k${i}`); }
    path.push('allow', 0);
    const parse = best(() => JSON.parse(inner));
    const locate = best(() => lineOfJsonValue(inner, path, 'Bash(*)'));
    expect(lineOfJsonValue(inner, path, 'Bash(*)')).toBe(1);
    expect(locate, `locate ${locate.toFixed(1)}ms vs JSON.parse ${parse.toFixed(1)}ms`).toBeLessThan(Math.max(25 * 13 * parse, 100));
  }, 60_000);
});
