/**
 * Regression tests for the RAG-002 and MEM-006 context gates shipped 2026-04-22.
 *
 * Two false positives were surfaced during the agentpwn VEIL SEO pre-push gate
 * (2026-04-21) and filed as hackmyagent#108 and hackmyagent#109:
 *
 *  - RAG-002 fired on a TypeScript data catalog whose `description` field
 *    mentioned "retrieve context" inside a plain string literal.
 *  - MEM-006 fired on a DVAA adversarial test harness whose job is to remain
 *    unsanitized — sanitizing it would defeat the purpose.
 *
 * [CSR-011] classified both fixes as (a) preserved-detection FP-suppress.
 * Each test pair is a positive (malicious shape still fires at HIGH) and a
 * negative (benign shape produces no HIGH/CRITICAL). Do not loosen the
 * positives — they are the detection lock.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { HardeningScanner } from '../../src/hardening/scanner';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';

describe('scanner RAG-002 / MEM-006 context gates (hma#108, hma#109)', () => {
  let scanner: HardeningScanner;
  let tempDir: string;

  beforeEach(async () => {
    scanner = new HardeningScanner();
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'hackmyagent-rag-mem-context-'));
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  // ==========================================================================
  // RAG-002: No RAG content sanitization
  // ==========================================================================

  describe('RAG-002 context gate (hma#108)', () => {
    it('does NOT fire on a TypeScript tool-catalog data array', async () => {
      // Verbatim shape from agentpwn/src/lib/tools-content.ts:266 (the FP).
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      const catalog = `
export const TOOLS_CONTENT = [
  {
    slug: "mcp-memory-server",
    name: "Memory/Knowledge Graph MCP Server",
    category: "mcp-server",
    description: "Persistent memory for AI agents through MCP. Store and retrieve context across conversations using knowledge graphs.",
    longDescription: "Memory MCP servers give AI agents persistent context across conversations. They store facts, relationships, and learned preferences in knowledge graphs that the agent can query. This enables agents to remember user preferences, project context, and prior decisions.",
    features: [
      "Key-value fact storage with metadata",
      "Cross-session context retrieval",
    ],
  },
];
`;
      await fs.writeFile(path.join(srcDir, 'tools-content.ts'), catalog);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(
        rag002,
        `RAG-002 must not fire on catalog string literals. Got: ${rag002.map((f) => f.message).join(', ')}`,
      ).toHaveLength(0);
    });

    it('STILL fires on a real retriever call that assembles a prompt', async () => {
      // Adversarial-review lock: detection must survive the FP suppression.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      // The scanner matches per-line: the retrieval keyword and a
      // context/prompt/augment keyword must co-occur on the same line for the
      // rule to fire. Surrounding 7 lines must contain no suppression
      // keywords (sanitize/validate/filter/escape), so keep this fixture free
      // of those tokens.
      const ragCode = `
import { retriever } from "./retriever";

export async function answer(question) {
  const context = await retriever.retrieve(question);
  const prompt = "Use this context:\\n" + context;
  return llm(prompt);
}
`;
      await fs.writeFile(path.join(srcDir, 'rag.ts'), ragCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(rag002.length, 'RAG-002 must still fire on unsanitized retrieval pipelines').toBeGreaterThan(0);
      expect(rag002[0].severity).toBe('high');
    });

    it('STILL fires on a Python f-string that embeds retrieved content in a prompt', async () => {
      // Adversarial-review lock: Python RAG code uses f-strings, not
      // template literals. The gate must accept `prompt = f"..."` as a
      // prompt-assembly shape.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      const pyCode = `
from retriever import retriever

def answer(question):
    retrieved = retriever.invoke(question)
    prompt = f"Use this context: {retrieved}"
    return llm(prompt)
`;
      await fs.writeFile(path.join(srcDir, 'rag.py'), pyCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(
        rag002.length,
        'RAG-002 must still fire on Python f-string prompt assembly',
      ).toBeGreaterThan(0);
    });

    it('STILL fires when a template literal inside a config object embeds a retrieval call', async () => {
      // Adversarial-review lock: `{ prompt: \`...${retrieve(q)}\` }` is a
      // real RAG pattern. The data-string gate must not suppress it.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      const code = `
export const config = {
  prompt: \`Answer using this context: \${retrieve(query)}\`,
};
`;
      await fs.writeFile(path.join(srcDir, 'config.ts'), code);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(
        rag002.length,
        'RAG-002 must fire on template-literal prompt embedding a retrieve() call',
      ).toBeGreaterThan(0);
    });

    it('does NOT fire on a JSDoc block that happens to mention retrieval concepts', async () => {
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      const doc = `
/**
 * Shared types for the RAG subsystem.
 *
 * The retrieve-augmented pipeline pulls context from a vector store,
 * augments the prompt with it, and passes the result to the LLM.
 */
export interface RagConfig {
  topK: number;
}
`;
      await fs.writeFile(path.join(srcDir, 'types.ts'), doc);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(rag002).toHaveLength(0);
    });

    it('does NOT fire on catalog data with parenthetical + internal single-quote (Phase 4.5 lock)', async () => {
      // Adversarial re-review surfaced a bypass: the original `[^"']*`
      // data-string body rejected lines with internal single quotes, so
      // `longDescription: "Use 'retrieve' to get context (see docs)."`
      // fell through to the hasFunctionCall escape hatch and fired. Data
      // shape must recognize both quote styles with the OPPOSITE quote
      // allowed inside.
      const srcDir = path.join(tempDir, 'src');
      await fs.mkdir(srcDir, { recursive: true });
      const catalog = `
export const CATALOG = [
  {
    slug: "foo",
    description: "Prompt injection (via code comments) during retrieve context.",
    longDescription: "Use 'retrieve' to build a prompt and context (see docs for details).",
  },
];
`;
      await fs.writeFile(path.join(srcDir, 'catalog.ts'), catalog);

      const result = await scanner.scan({ targetDir: tempDir });
      const rag002 = result.findings.filter((f) => f.checkId === 'RAG-002' && !f.passed);
      expect(
        rag002,
        `RAG-002 must not fire on catalog data with parens or internal quotes. Got: ${rag002.map((f) => f.message).join(', ')}`,
      ).toHaveLength(0);
    });
  });

  // ==========================================================================
  // MEM-006: Memory store without input sanitization
  // ==========================================================================

  describe('MEM-006 path gate (hma#109)', () => {
    it('does NOT fire on a *-test.mjs DVAA-style harness', async () => {
      // Verbatim shape from agentpwn/scripts/dvaa-test.mjs:142 (the FP).
      const scriptsDir = path.join(tempDir, 'scripts');
      await fs.mkdir(scriptsDir, { recursive: true });
      const harness = `
// DVAA adversarial harness — deliberately unsanitized.
function extractAgentVisibleContent(html) {
  const parts = [];
  const comments = html.match(/<!--([\\s\\S]*?)-->/g) || [];
  for (const c of comments) {
    parts.push({ type: 'html-comment', content: c.replace(/<!--|-->/g, '').trim() });
  }
  return parts;
}
export { extractAgentVisibleContent };
`;
      await fs.writeFile(path.join(scriptsDir, 'dvaa-test.mjs'), harness);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006,
        `MEM-006 must not fire on *-test.mjs adversarial harnesses. Got: ${mem006.map((f) => f.message).join(', ')}`,
      ).toHaveLength(0);
    });

    it('does NOT fire on files inside a dvaa/ directory (exact component match)', async () => {
      const dvaaDir = path.join(tempDir, 'dvaa', 'fixtures');
      await fs.mkdir(dvaaDir, { recursive: true });
      const fixture = `
export function persistParsedHtml(memory, parts) {
  for (const p of parts) {
    memory.push({ type: p.type, content: p.content });
  }
}
`;
      await fs.writeFile(path.join(dvaaDir, 'memory-harness.mjs'), fixture);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(mem006).toHaveLength(0);
    });

    it.each([
      ['honeypot'],
      ['trap-fixtures'],
      ['adversarial-fixtures'],
      ['vulnerable-by-design'],
    ])('does NOT fire on files inside a %s/ directory', async (dirName) => {
      // Adversarial-review coverage: verify every named adversarial dir
      // actually triggers the skip — the original commit only covered dvaa/.
      const advDir = path.join(tempDir, dirName, 'fixtures');
      await fs.mkdir(advDir, { recursive: true });
      const fixture = `
export function persistParsedHtml(memory, parts) {
  for (const p of parts) {
    memory.push({ type: p.type, content: p.content });
  }
}
`;
      await fs.writeFile(path.join(advDir, 'memory-harness.mjs'), fixture);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(mem006).toHaveLength(0);
    });

    it('STILL fires on a file whose header says "// DVAA" but path is unremarkable (content-marker evasion guard)', async () => {
      // Adversarial-review lock: scanned code is untrusted per the project
      // trust hierarchy. An author (or compromised dep) adding `// DVAA`
      // atop a production file must NOT silently turn off the scanner.
      const libDir = path.join(tempDir, 'lib');
      await fs.mkdir(libDir, { recursive: true });
      const fixture = `
// DVAA - this comment must not disable the check on a production path.
export function store(memory, input) {
  memory.push({ text: input.text, content: input.content });
}
`;
      await fs.writeFile(path.join(libDir, 'memory.mjs'), fixture);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006.length,
        'Content marker in scanned code must not disable the scanner',
      ).toBeGreaterThan(0);
    });

    it('STILL fires on files inside a trap-router/ directory (exact-component guard)', async () => {
      // Adversarial-review lock: the ADVERSARIAL_DIR_RE must not match
      // production directory names like `trap-router/`, `trap-focus/`,
      // `adversarial-reports/`. Only exact component matches of named
      // fixture directories (`dvaa`, `honeypot`, `trap-fixtures`, etc.) skip.
      const routerDir = path.join(tempDir, 'trap-router', 'src');
      await fs.mkdir(routerDir, { recursive: true });
      const prodCode = `
export function remember(memory, request) {
  memory.push({ content: request.body });
}
`;
      await fs.writeFile(path.join(routerDir, 'memory.js'), prodCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006.length,
        'MEM-006 must fire on trap-router/ (prefix collision, not an adversarial directory)',
      ).toBeGreaterThan(0);
    });

    it('STILL fires on a real memory store in production code', async () => {
      // Adversarial-review lock: detection must survive the FP suppression.
      const libDir = path.join(tempDir, 'lib');
      await fs.mkdir(libDir, { recursive: true });
      const prodCode = `
import { db } from "./db";

export async function rememberUserMessage(userId, text) {
  // No sanitization. User-controlled text persisted to memory layer.
  await db.insert({ text: text, userId: userId });
}
`;
      await fs.writeFile(path.join(libDir, 'memory.js'), prodCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(mem006.length, 'MEM-006 must still fire on unsanitized production memory stores').toBeGreaterThan(0);
      expect(mem006[0].severity).toBe('high');
    });

    it('STILL fires on a file whose name starts with "trap" but is not in a trap/ directory', async () => {
      // Adversarial-review lock: the ADVERSARIAL_DIR_RE only matches
      // directory-component names. A file called "trap-handler.ts" in a
      // normal lib/ tree must not silently escape detection — directory
      // context is what establishes intent, not filename prefix alone.
      const libDir = path.join(tempDir, 'lib');
      await fs.mkdir(libDir, { recursive: true });
      const suspicious = `
export function storeUserInput(mem, evt) {
  mem.push({ content: evt.message });
}
`;
      await fs.writeFile(path.join(libDir, 'trapezoid-stats.js'), suspicious);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006.length,
        'MEM-006 must fire on non-test, non-adversarial-dir files even if filename has a trap-ish prefix',
      ).toBeGreaterThan(0);
    });

    it('does NOT fire on a local render/result array push (opena2a cli-ui FP)', async () => {
      // Regression: `lines.push({ text, tone })` / `out.push({ text })` build a
      // local terminal-render array — not a memory/persistence sink. The store
      // pattern's `push` verb FP'd these as MEM-006 HIGH in opena2a cli-ui
      // (action-gradient-block.ts, check-rich-block.ts). `push` now requires a
      // persistence-semantic receiver; a local accumulator must stay silent.
      const uiDir = path.join(tempDir, 'src');
      await fs.mkdir(uiDir, { recursive: true });
      const renderBuilder = `
export function buildBlock(steps) {
  const lines = [];
  for (const step of steps) {
    const row = step.label + ": " + step.value;
    lines.push({ text: row, tone: "default" });
  }
  const out = [];
  out.push({ text: lines.map((l) => l.text).join("  "), tone: "default" });
  return { lines, out };
}
`;
      await fs.writeFile(path.join(uiDir, 'render-block.ts'), renderBuilder);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006,
        `MEM-006 must not fire on local render-array pushes. Got: ${mem006.map((f) => `${f.file}:${f.line}`).join(', ')}`,
      ).toHaveLength(0);
    });

    it('STILL fires on a conversation-memory array push (preserved detection)', async () => {
      // The receiver gate must not weaken real detection: pushing unsanitized
      // user text onto a conversation/memory array is the exact poisoning sink.
      const libDir = path.join(tempDir, 'lib');
      await fs.mkdir(libDir, { recursive: true });
      const prodCode = `
export function remember(conversationMemory, userInput) {
  conversationMemory.push({ text: userInput.text, content: userInput.content });
}
`;
      await fs.writeFile(path.join(libDir, 'history.js'), prodCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006.length,
        'MEM-006 must still fire on unsanitized conversation-memory pushes',
      ).toBeGreaterThan(0);
    });

    it.each([
      ['userMemory'],
      ['agentMemory'],
      ['vectorStore'],
      ['userHistory'],
      ['userMessages'],
      ['session.messages'],
      ['user_memory'],
      ['chat_history'],
      ['vectorDBStore'],
    ])('STILL fires on a camelCase / dotted / snake_case persistence receiver: %s.push (adversarial-review lock)', async (receiver) => {
      // Phase 4.5 lock: a start-anchored receiver regex missed camelCase
      // *suffix* names (agentMemory, vectorStore). The token-split gate must
      // catch the keyword as a camelCase hump or a dotted segment, not just a
      // prefix — these are realistic agent-memory sinks, not fringe.
      const libDir = path.join(tempDir, 'lib');
      await fs.mkdir(libDir, { recursive: true });
      const prodCode = `
export function remember(${receiver.split('.')[0]}, userInput) {
  ${receiver}.push({ text: userInput.text, content: userInput.content });
}
`;
      await fs.writeFile(path.join(libDir, 'mem-sink.js'), prodCode);

      const result = await scanner.scan({ targetDir: tempDir });
      const mem006 = result.findings.filter((f) => f.checkId === 'MEM-006' && !f.passed);
      expect(
        mem006.length,
        `MEM-006 must fire on ${receiver}.push (camelCase/dotted persistence receiver)`,
      ).toBeGreaterThan(0);
    });
  });
});
