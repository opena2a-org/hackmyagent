/**
 * Source Code Preprocessor
 *
 * The config-oriented detectors in the semantic compiler
 * (`extractDataAccessPatterns`, `mapRiskSurfaces`) were designed for
 * skills, agent configs, and system prompts, where the entire content is
 * semantically meaningful. Running them against source code produces
 * reflexive false positives: any file whose *purpose* is to scan for
 * attack patterns (a credential regex, an `eval(` pattern, a typosquatting
 * detector) contains the exact strings those detectors look for.
 *
 * This preprocessor produces a "stripped view" of source code with
 * comments, import statements, and string literals replaced by whitespace.
 * The stripped view preserves byte offsets so any index-based analysis
 * downstream keeps working. The original content is left untouched for
 * callers that need it (evidence extraction, capability parsing, etc.).
 *
 * What survives the strip:
 *   - Identifiers (variable, function, and type names)
 *   - Control flow and operators
 *   - Struct tags and field names (outside of string literals)
 *
 * What is removed:
 *   - `//`, `#`, `--` line comments
 *   - `/* ... *\/`, `"""..."""`, `'''...'''` block comments
 *   - `"..."`, `'...'`, `` `...` ``, `r"..."`, etc. string literals
 *   - `import (...)` blocks and `import "..."` / `from X import Y` lines
 *
 * The net effect: code that references credential/eval/RCE patterns
 * defensively (scanners, allowlists, documentation strings) no longer
 * trips reflexive regex matches, while code that actually *does* those
 * things (e.g. `exec(userInput)` where `exec` is a symbol call, not a
 * string) still surfaces.
 *
 * Security note: stripping string literals trades off a narrow detection
 * case — a hardcoded secret embedded in a string literal whose *exact*
 * bytes match an AWS/Anthropic/GitHub key format — for eliminating the
 * dominant false positive mode on source code. Canonical API key formats
 * are still detected upstream of this path: `classifyArtifactType` routes
 * files matching `sk-ant-`, `AKIA...`, `ghp_...`, or PEM headers into the
 * `credential_file` artifact type before source code preprocessing runs,
 * so those cases are preserved.
 */

import type { ArtifactType } from '../types.js';

// ============================================================================
// Language Detection
// ============================================================================

export type SourceLanguage =
  | 'go'
  | 'typescript'
  | 'javascript'
  | 'python'
  | 'rust'
  | 'java'
  | 'ruby'
  | 'unknown';

/** Detect source language from a file path. Returns 'unknown' for unsupported extensions. */
export function detectSourceLanguage(path?: string): SourceLanguage {
  if (!path) return 'unknown';
  const lower = path.toLowerCase();
  if (lower.endsWith('.go')) return 'go';
  if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'typescript';
  if (
    lower.endsWith('.js') ||
    lower.endsWith('.jsx') ||
    lower.endsWith('.mjs') ||
    lower.endsWith('.cjs')
  ) {
    return 'javascript';
  }
  if (lower.endsWith('.py') || lower.endsWith('.pyi')) return 'python';
  if (lower.endsWith('.rs')) return 'rust';
  if (lower.endsWith('.java')) return 'java';
  if (lower.endsWith('.rb')) return 'ruby';
  return 'unknown';
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Build an analysis view of content for use with config-oriented detectors.
 *
 * For source_code artifacts, strips comments, imports, and string literals.
 * For all other artifact types, returns the original content unchanged.
 *
 * The stripped view preserves byte offsets: removed bytes are replaced with
 * spaces (or newlines inside multi-line regions), so any downstream code
 * that uses absolute indices remains valid.
 */
export function buildAnalysisView(
  content: string,
  artifactType: ArtifactType,
  path?: string,
): string {
  if (artifactType !== 'source_code') {
    return content;
  }
  const language = detectSourceLanguage(path);
  if (language === 'unknown') {
    return content;
  }
  return stripSourceCode(content, language);
}

/**
 * Strip comments, imports, and string literals from source code.
 * Exposed for tests. Callers should usually use `buildAnalysisView`.
 */
export function stripSourceCode(content: string, language: SourceLanguage): string {
  switch (language) {
    case 'go':
      return stripGo(content);
    case 'typescript':
    case 'javascript':
      return stripJsLike(content);
    case 'python':
      return stripPython(content);
    case 'rust':
      return stripRust(content);
    case 'java':
      return stripJava(content);
    case 'ruby':
      return stripRuby(content);
    default:
      return content;
  }
}

// ============================================================================
// Language-specific strippers
// ============================================================================
//
// Each stripper walks the content once and produces a same-length buffer
// where comments, imports, and string literals are replaced with spaces
// (newlines preserved so line numbers are stable).
//
// These are hand-rolled tokenizers. They are not language-complete parsers,
// but they are strict enough for our purpose: stripping signal that the
// config-oriented regex detectors should not see. A cosmetic miscount (e.g.
// an unterminated string) may leave a trailing region un-stripped, which is
// acceptable (worst case, we leave an FP in place; we never silence a real
// finding outside source code files).

function blank(n: number, newlines: number): string {
  if (newlines === 0) return ' '.repeat(n);
  return ' '.repeat(n - newlines) + '\n'.repeat(newlines);
}

function countNewlines(s: string): number {
  let count = 0;
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 10) count++;
  return count;
}

// ----- Go -----

function stripGo(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  // Track start-of-line for import detection
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];

    // Line comment
    if (ch === '/' && next === '/') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    // Block comment
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    // Interpreted string literal
    if (ch === '"') {
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === '"' || c === '\n') {
          i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Raw string literal
    if (ch === '`') {
      const start = i;
      i++;
      const end = src.indexOf('`', i);
      i = end === -1 ? n : end + 1;
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Rune literal (skip to avoid confusing quoting)
    if (ch === "'") {
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === "'" || c === '\n') {
          i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Import block / import statement at start of a line
    if (ch === 'i' && isImportAtLineStart(src, i, 'go')) {
      const consumed = consumeGoImport(src, i);
      out.push(blank(consumed - i, countNewlines(src.slice(i, consumed))));
      i = consumed;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

function isImportAtLineStart(src: string, i: number, lang: 'go' | 'rust' | 'java'): boolean {
  // Check that `import` keyword starts this line (allowing leading whitespace)
  let j = i - 1;
  while (j >= 0 && (src[j] === ' ' || src[j] === '\t')) j--;
  if (j >= 0 && src[j] !== '\n') return false;
  // Check keyword
  const keyword = lang === 'java' ? 'import ' : 'import';
  if (src.slice(i, i + keyword.length) !== keyword) return false;
  // After `import`, must be whitespace or `(` (Go) or `{` / identifier (rust)
  const after = src[i + keyword.length];
  return after === ' ' || after === '\t' || after === '(' || after === '\n';
}

function consumeGoImport(src: string, i: number): number {
  // `import` keyword, optional space, then either `(...)` block or `"..."` single
  let j = i + 'import'.length;
  while (j < src.length && (src[j] === ' ' || src[j] === '\t')) j++;
  if (src[j] === '(') {
    const end = src.indexOf(')', j);
    return end === -1 ? src.length : end + 1;
  }
  // Single-line: consume to end of line
  const end = src.indexOf('\n', j);
  return end === -1 ? src.length : end;
}

// ----- JavaScript / TypeScript -----

function stripJsLike(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];

    // Line comment
    if (ch === '/' && next === '/') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    // Block comment
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    // String literals
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === quote || c === '\n') {
          if (c === quote) i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Template literal
    if (ch === '`') {
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        // Nested ${...} interpolation — leave contents visible; rewind
        if (c === '$' && src[i + 1] === '{') {
          // Find matching brace
          let depth = 1;
          let k = i + 2;
          while (k < n && depth > 0) {
            if (src[k] === '{') depth++;
            else if (src[k] === '}') depth--;
            if (depth > 0) k++;
          }
          // Blank only the literal portion up to `${`
          const segmentEnd = i;
          out.push(blank(segmentEnd - start, countNewlines(src.slice(start, segmentEnd))));
          // Preserve interpolation content verbatim for analysis
          out.push(src.slice(i, k + 1));
          i = k + 1;
          // Continue template from after `}`
          while (i < n) {
            const c2 = src[i];
            if (c2 === '\\' && i + 1 < n) {
              i += 2;
              continue;
            }
            if (c2 === '`') {
              i++;
              return out.concat(stripJsLike(src.slice(i))).join('');
            }
            if (c2 === '$' && src[i + 1] === '{') break;
            i++;
          }
          // If we fall out naturally (no more interpolation, no closing backtick)
          continue;
        }
        if (c === '`') {
          i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Import statement at start of line
    if (ch === 'i' && isImportAtJsLineStart(src, i)) {
      const end = consumeJsImport(src, i);
      out.push(blank(end - i, countNewlines(src.slice(i, end))));
      i = end;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

function isImportAtJsLineStart(src: string, i: number): boolean {
  let j = i - 1;
  while (j >= 0 && (src[j] === ' ' || src[j] === '\t')) j--;
  if (j >= 0 && src[j] !== '\n') return false;
  if (src.slice(i, i + 7) === 'import ' || src.slice(i, i + 7) === 'import{') return true;
  if (src.slice(i, i + 7) === 'import*') return true;
  return false;
}

function consumeJsImport(src: string, i: number): number {
  // Consume until the terminating semicolon or newline where the statement ends
  // (accounting for multi-line import blocks with braces)
  let j = i;
  let brace = 0;
  while (j < src.length) {
    const c = src[j];
    if (c === '{') brace++;
    else if (c === '}') brace--;
    else if (c === ';' && brace === 0) return j + 1;
    else if (c === '\n' && brace === 0) {
      // If next non-space char is not a continuation, end here
      let k = j + 1;
      while (k < src.length && (src[k] === ' ' || src[k] === '\t')) k++;
      if (k === src.length || src[k] !== 'f' /* from */) {
        // Heuristic: end of import
        return j;
      }
    }
    j++;
  }
  return j;
}

// ----- Python -----

function stripPython(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];

    // Comment
    if (ch === '#') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    // Triple-quoted string
    if (
      (ch === '"' || ch === "'") &&
      src[i + 1] === ch &&
      src[i + 2] === ch
    ) {
      const triple = ch + ch + ch;
      const start = i;
      i += 3;
      const end = src.indexOf(triple, i);
      i = end === -1 ? n : end + 3;
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Regular string (allow prefix like r, b, f)
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === quote || c === '\n') {
          if (c === quote) i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // Import statement at start of line
    if ((ch === 'i' || ch === 'f') && isImportAtPyLineStart(src, i)) {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

function isImportAtPyLineStart(src: string, i: number): boolean {
  let j = i - 1;
  while (j >= 0 && (src[j] === ' ' || src[j] === '\t')) j--;
  if (j >= 0 && src[j] !== '\n') return false;
  if (src.slice(i, i + 7) === 'import ') return true;
  if (src.slice(i, i + 5) === 'from ') return true;
  return false;
}

// ----- Rust -----

function stripRust(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];

    if (ch === '/' && next === '/') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === '"') {
          i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // `use crate::foo;` and `extern crate foo;`
    if ((ch === 'u' || ch === 'e') && isRustUseAtLineStart(src, i)) {
      const end = src.indexOf(';', i);
      const stop = end === -1 ? n : end + 1;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

function isRustUseAtLineStart(src: string, i: number): boolean {
  let j = i - 1;
  while (j >= 0 && (src[j] === ' ' || src[j] === '\t')) j--;
  if (j >= 0 && src[j] !== '\n') return false;
  return src.slice(i, i + 4) === 'use ' || src.slice(i, i + 13) === 'extern crate ';
}

// ----- Java -----

function stripJava(src: string): string {
  // Java syntax overlaps heavily with the JS-like stripper for comments and strings;
  // imports start with `import `. Reuse JS-like with a small tweak.
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];

    if (ch === '/' && next === '/') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    if (ch === '"') {
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === '"' || c === '\n') {
          if (c === '"') i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    if (ch === 'i' && isImportAtLineStart(src, i, 'java')) {
      const end = src.indexOf(';', i);
      const stop = end === -1 ? n : end + 1;
      out.push(blank(stop - i, countNewlines(src.slice(i, stop))));
      i = stop;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

// ----- Ruby -----

function stripRuby(src: string): string {
  const out: string[] = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const ch = src[i];

    if (ch === '#') {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const quote = ch;
      const start = i;
      i++;
      while (i < n) {
        const c = src[i];
        if (c === '\\' && i + 1 < n) {
          i += 2;
          continue;
        }
        if (c === quote || c === '\n') {
          if (c === quote) i++;
          break;
        }
        i++;
      }
      out.push(blank(i - start, countNewlines(src.slice(start, i))));
      continue;
    }
    // `require`, `require_relative`, `load` at start of line
    if (ch === 'r' && isRubyRequireAtLineStart(src, i)) {
      const end = src.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      out.push(blank(stop - i, 0));
      i = stop;
      continue;
    }
    out.push(ch);
    i++;
  }
  return out.join('');
}

function isRubyRequireAtLineStart(src: string, i: number): boolean {
  let j = i - 1;
  while (j >= 0 && (src[j] === ' ' || src[j] === '\t')) j--;
  if (j >= 0 && src[j] !== '\n') return false;
  return (
    src.slice(i, i + 8) === 'require ' ||
    src.slice(i, i + 17) === 'require_relative ' ||
    src.slice(i, i + 5) === 'load '
  );
}
