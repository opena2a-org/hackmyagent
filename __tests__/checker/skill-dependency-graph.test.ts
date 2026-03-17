import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  parseSkillFrontmatter,
  buildDependencyGraph,
  detectCircularDeps,
  detectPhantomDeps,
  detectUnpinnedDeps,
  analyzeSkillDependencies,
} from '../../src/checker/skill-dependency-graph';

// Helper to create temp dirs with SKILL.md files
function createTempSkillDir(skills: Record<string, string>): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-dep-test-'));

  for (const [name, content] of Object.entries(skills)) {
    const skillDir = path.join(tmpDir, name);
    fs.mkdirSync(skillDir, { recursive: true });
    fs.writeFileSync(path.join(skillDir, 'SKILL.md'), content);
  }

  return tmpDir;
}

function cleanupDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe('parseSkillFrontmatter', () => {
  it('parses name, version, dependencies, and tools from frontmatter', () => {
    const content = `---
name: my-skill
version: 1.0.0
dependencies:
  - dep-a@1.0.0
  - dep-b@2.0.0
tools:
  - read_file
  - write_file
---

# My Skill

Description here.
`;

    const result = parseSkillFrontmatter(content, '/test/SKILL.md');

    expect(result.name).toBe('my-skill');
    expect(result.version).toBe('1.0.0');
    expect(result.dependencies).toEqual(['dep-a@1.0.0', 'dep-b@2.0.0']);
    expect(result.tools).toEqual(['read_file', 'write_file']);
    expect(result.filePath).toBe('/test/SKILL.md');
  });

  it('parses inline list format', () => {
    const content = `---
name: inline-skill
dependencies: [dep-a, dep-b@1.0.0]
tools: [search, execute]
---
`;

    const result = parseSkillFrontmatter(content);

    expect(result.name).toBe('inline-skill');
    expect(result.dependencies).toEqual(['dep-a', 'dep-b@1.0.0']);
    expect(result.tools).toEqual(['search', 'execute']);
  });

  it('handles missing frontmatter gracefully', () => {
    const content = `# No Frontmatter Skill

Just content here.
`;

    const result = parseSkillFrontmatter(content);

    expect(result.name).toBe('No Frontmatter Skill');
    expect(result.dependencies).toEqual([]);
    expect(result.tools).toEqual([]);
  });

  it('handles empty dependencies and tools', () => {
    const content = `---
name: empty-skill
version: 0.1.0
---
`;

    const result = parseSkillFrontmatter(content);

    expect(result.name).toBe('empty-skill');
    expect(result.version).toBe('0.1.0');
    expect(result.dependencies).toEqual([]);
    expect(result.tools).toEqual([]);
  });

  it('strips quotes from values', () => {
    const content = `---
name: "quoted-skill"
version: '2.0.0'
dependencies:
  - "dep-a@1.0.0"
  - 'dep-b'
---
`;

    const result = parseSkillFrontmatter(content);

    expect(result.name).toBe('quoted-skill');
    expect(result.version).toBe('2.0.0');
    expect(result.dependencies).toEqual(['dep-a@1.0.0', 'dep-b']);
  });
});

describe('buildDependencyGraph', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) cleanupDir(tmpDir);
  });

  it('builds graph from multiple SKILL.md files', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
version: 1.0.0
dependencies:
  - skill-b@1.0.0
---
`,
      'skill-b': `---
name: skill-b
version: 1.0.0
dependencies: []
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);

    expect(graph.nodes.size).toBe(2);
    expect(graph.nodes.has('skill-a')).toBe(true);
    expect(graph.nodes.has('skill-b')).toBe(true);
    expect(graph.edges.get('skill-a')?.has('skill-b')).toBe(true);
    expect(graph.edges.get('skill-b')?.size).toBe(0);
  });

  it('handles empty directory', () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-dep-test-'));
    const graph = buildDependencyGraph(tmpDir);
    expect(graph.nodes.size).toBe(0);
  });

  it('uses directory name as fallback when no name in frontmatter', () => {
    tmpDir = createTempSkillDir({
      'unnamed-skill': `---
version: 1.0.0
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    expect(graph.nodes.has('unnamed-skill')).toBe(true);
  });
});

describe('detectCircularDeps', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) cleanupDir(tmpDir);
  });

  it('detects simple circular dependency (A -> B -> A)', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b
---
`,
      'skill-b': `---
name: skill-b
dependencies:
  - skill-a
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectCircularDeps(graph);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe('SKILL-015');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].description).toContain('Circular dependency');
  });

  it('detects complex circular dependency (A -> B -> C -> A)', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b
---
`,
      'skill-b': `---
name: skill-b
dependencies:
  - skill-c
---
`,
      'skill-c': `---
name: skill-c
dependencies:
  - skill-a
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectCircularDeps(graph);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].id).toBe('SKILL-015');
  });

  it('returns empty when no circular dependencies exist', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b
---
`,
      'skill-b': `---
name: skill-b
dependencies: []
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectCircularDeps(graph);

    expect(findings).toEqual([]);
  });
});

describe('detectPhantomDeps', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) cleanupDir(tmpDir);
  });

  it('detects phantom dependency (referenced but not found)', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - nonexistent-skill
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectPhantomDeps(graph);

    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe('SKILL-016');
    expect(findings[0].description).toContain('nonexistent-skill');
    expect(findings[0].description).toContain('not found');
  });

  it('returns empty when all dependencies are resolved', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b@1.0.0
---
`,
      'skill-b': `---
name: skill-b
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectPhantomDeps(graph);

    expect(findings).toEqual([]);
  });
});

describe('detectUnpinnedDeps', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) cleanupDir(tmpDir);
  });

  it('detects unpinned dependency version', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - dep-without-version
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectUnpinnedDeps(graph);

    expect(findings.length).toBe(1);
    expect(findings[0].id).toBe('SKILL-017');
    expect(findings[0].description).toContain('dep-without-version');
    expect(findings[0].description).toContain('without a pinned version');
  });

  it('does not flag pinned dependencies', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - dep-a@1.0.0
  - dep-b@2.3.1
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectUnpinnedDeps(graph);

    expect(findings).toEqual([]);
  });

  it('flags mix of pinned and unpinned', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - pinned-dep@1.0.0
  - unpinned-dep
---
`,
    });

    const graph = buildDependencyGraph(tmpDir);
    const findings = detectUnpinnedDeps(graph);

    expect(findings.length).toBe(1);
    expect(findings[0].description).toContain('unpinned-dep');
  });
});

describe('analyzeSkillDependencies', () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) cleanupDir(tmpDir);
  });

  it('combines all checks and returns combined findings', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b
  - phantom-skill
---
`,
      'skill-b': `---
name: skill-b
dependencies:
  - skill-a
---
`,
    });

    const findings = analyzeSkillDependencies(tmpDir);

    const ids = findings.map((f) => f.id);
    // Should have circular dep (SKILL-015), phantom dep (SKILL-016), and unpinned (SKILL-017)
    expect(ids).toContain('SKILL-015');
    expect(ids).toContain('SKILL-016');
    expect(ids).toContain('SKILL-017');
  });

  it('returns empty for directory with no SKILL.md files', () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'skill-dep-test-'));
    const findings = analyzeSkillDependencies(tmpDir);
    expect(findings).toEqual([]);
  });

  it('returns empty for well-formed skills with no issues', () => {
    tmpDir = createTempSkillDir({
      'skill-a': `---
name: skill-a
dependencies:
  - skill-b@1.0.0
---
`,
      'skill-b': `---
name: skill-b
dependencies: []
---
`,
    });

    const findings = analyzeSkillDependencies(tmpDir);
    expect(findings).toEqual([]);
  });
});
