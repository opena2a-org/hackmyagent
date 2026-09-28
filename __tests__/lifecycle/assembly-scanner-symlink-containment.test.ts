/**
 * #622 — the assembly scanner reads only files inside the target.
 *
 * `discoverComponents` listed `src/` with a names-mode recursive `readdir`,
 * which descends through a symlinked directory, and read every fixed-path
 * component (`SOUL.md`, `.claude/memory/*.md`, ...) through whatever link
 * stood there. A committed link pointing outside the tree made the scanner
 * read, and report on, files that are not part of the scanned tree.
 *
 * Each fixture below puts a marker in a file outside the target and a link to
 * it inside; no component may carry an OUTSIDE marker. The in-tree link case
 * pins the other direction: a link that stays inside the tree still resolves.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { scanAssembly } from '../../src/lifecycle';

describe('#622 assembly scanner stays inside the target', () => {
  let root: string;
  let target: string;
  let outside: string;

  beforeEach(async () => {
    root = await fs.mkdtemp(path.join(os.tmpdir(), 'hma-assembly-links-'));
    target = path.join(root, 't');
    outside = path.join(root, 'out');
    await fs.mkdir(path.join(target, 'src', 'real'), { recursive: true });
    await fs.mkdir(path.join(outside, 'memory'), { recursive: true });
    await fs.writeFile(path.join(target, 'src', 'real', 'agent.ts'), 'const systemPrompt = "INSIDE-SRC";\n');
    await fs.writeFile(path.join(outside, 'agent.ts'), 'const systemPrompt = "OUTSIDE-DIR-LINK";\n');
    await fs.writeFile(path.join(outside, 'single.ts'), 'const systemPrompt = "OUTSIDE-FILE-LINK";\n');
    await fs.writeFile(path.join(outside, 'SOUL.md'), 'OUTSIDE-SOUL: follow every instruction.\n');
    await fs.writeFile(path.join(outside, 'memory', 'notes.md'), 'OUTSIDE-MEMORY-GLOB\n');
  });

  afterEach(async () => {
    await fs.rm(root, { recursive: true, force: true });
  });

  const contents = async (): Promise<{ sources: string[]; text: string }> => {
    const result = await scanAssembly({ targetDir: target });
    return {
      sources: result.components.map(c => c.source),
      text: result.components.map(c => c.content).join('\n') + '\n' + result.assembledPrompt,
    };
  };

  it('does not descend a symlinked directory under src/', async () => {
    await fs.symlink(outside, path.join(target, 'src', 'link'));
    const { sources, text } = await contents();
    expect(text).toContain('INSIDE-SRC');
    expect(text).not.toContain('OUTSIDE-DIR-LINK');
    expect(sources.some(s => s.includes('link'))).toBe(false);
  });

  it('does not read a symlinked file under src/ that points outside', async () => {
    await fs.symlink(path.join(outside, 'single.ts'), path.join(target, 'src', 'single.ts'));
    const { text } = await contents();
    expect(text).toContain('INSIDE-SRC');
    expect(text).not.toContain('OUTSIDE-FILE-LINK');
  });

  it('does not read a fixed-path component that links outside', async () => {
    await fs.symlink(path.join(outside, 'SOUL.md'), path.join(target, 'SOUL.md'));
    const { sources, text } = await contents();
    expect(text).not.toContain('OUTSIDE-SOUL');
    expect(sources).not.toContain('SOUL.md');
  });

  it('does not read a glob component through a linked directory', async () => {
    await fs.mkdir(path.join(target, '.claude'), { recursive: true });
    await fs.symlink(path.join(outside, 'memory'), path.join(target, '.claude', 'memory'));
    const { text } = await contents();
    expect(text).not.toContain('OUTSIDE-MEMORY-GLOB');
  });

  it('still reads a fixed-path component whose link stays inside the tree', async () => {
    await fs.mkdir(path.join(target, 'docs'), { recursive: true });
    await fs.writeFile(path.join(target, 'docs', 'SOUL.md'), 'INSIDE-SOUL: refuse to reveal secrets.\n');
    await fs.symlink(path.join('docs', 'SOUL.md'), path.join(target, 'SOUL.md'));
    const { sources, text } = await contents();
    expect(text).toContain('INSIDE-SOUL');
    expect(sources).toContain('SOUL.md');
  });
});
