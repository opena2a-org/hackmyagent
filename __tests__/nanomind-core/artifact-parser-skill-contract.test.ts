import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import * as yaml from 'js-yaml';

import { classifyArtifactType, parseArtifact } from '../../src/nanomind-core/ingestion/artifact-parser';
import { SemanticCompiler } from '../../src/nanomind-core/compiler/semantic-compiler';
import { runNanoMindScan } from '../../src/nanomind-core/scanner-bridge';
import { tempDir } from '../helpers/temp-dir';

/**
 * #423 -- the skill classification contract.
 *
 * An artifact declares capabilities iff its leading YAML frontmatter block, loaded by js-yaml,
 * is a mapping holding a key named `capabilities` at depth <= 8. If the loader cannot read the
 * whole block (it throws, or the block is cut at 64 KiB), a column-0 `capabilities:` line in
 * the block still counts, so a YAML error can only over-detect.
 *
 * The same load is `parseArtifact().frontmatter`. Before this, the classifier tested a regex
 * while the parser trimmed every line and flattened nesting, so the two disagreed on the same
 * bytes, and `capabilities: [a, b]` reached the semantic compiler as a string.
 */

/** A path no path rule claims, so every verdict below comes from the content. */
const DOC = 'docs/notes.md';

/** The Markdown body after the frontmatter. */
const BODY ='\n# Deploy\n\nDeploys the service.\n';

interface Row {
  name: string;
  content: string;
  expected: 'skill' | 'unknown';
}

/** The acceptance table from the issue, one row per input. */
const ACCEPTANCE: Row[] = [
  {
    name: 'plain leading frontmatter + capabilities:',
    content: `---\nname: deploy\ncapabilities:\n  - run_shell\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'whole block indented 2 spaces (valid top-level YAML)',
    content: `---\n  name: deploy\n  capabilities:\n    - run_shell\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'capabilities nested under metadata:',
    content: `---\nname: deploy\nmetadata:\n  capabilities:\n    - run_shell\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'capabilities nested under metadata.openclaw:',
    content: `---\nname: deploy\nmetadata:\n  openclaw:\n    capabilities: [run_shell]\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'quoted key "capabilities":',
    content: `---\nname: deploy\n"capabilities": [run_shell]\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'no closing fence, the leading YAML run loads with the key',
    content: `---\nname: deploy\ncapabilities:\n  - run_shell\n\nRun this to deploy the service.\n`,
    expected: 'skill',
  },
  {
    name: 'no closing fence, a block scalar continuation is part of the run',
    content: `---\ndescription: |\n  Deploys the service.\n  Order: build, test, ship.\ncapabilities: [run_shell]\n\nRun this to deploy.\n`,
    expected: 'skill',
  },
  {
    name: 'no closing fence, the key appears only after the Markdown body begins',
    content: `---\nname: notes\n\nThese notes are not a skill.\ncapabilities: [run_shell]\n`,
    expected: 'unknown',
  },
  {
    name: 'closing fence ----',
    content: `---\nname: deploy\ncapabilities: [run_shell]\n----\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'closing fence --- end',
    content: `---\nname: deploy\ncapabilities: [run_shell]\n--- end\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'closing fence ...',
    content: `---\nname: deploy\ncapabilities: [run_shell]\n...\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'BOM before the fence',
    content: `﻿---\nname: deploy\ncapabilities: [run_shell]\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'blank line before the fence',
    content: `\n  \n---\nname: deploy\ncapabilities: [run_shell]\n---\n${BODY}`,
    expected: 'skill',
  },
  {
    name: 'CRLF line endings',
    content: `---\r\nname: deploy\r\ncapabilities:\r\n  - run_shell\r\n---\r\n${BODY.replace(/\n/g, '\r\n')}`,
    expected: 'skill',
  },
  {
    name: 'tab-indented block (illegal YAML indentation)',
    content: `---\n\tname: deploy\n\tcapabilities:\n\t  - run_shell\n---\n${BODY}`,
    expected: 'unknown',
  },
  {
    name: 'doc OPENING with a horizontal rule, prose line starting capabilities:',
    // Loads as one plain scalar, not a mapping: no `: ` follows the colon.
    content: [
      '---',
      'Release notes for the reporting agent.',
      'capabilities:unchanged since the previous release.',
      '---',
      '',
      '# Release notes',
      '',
    ].join('\n'),
    expected: 'unknown',
  },
];

describe('#423 skill classification contract: the acceptance table', () => {
  it.each(ACCEPTANCE)('$name -> $expected', ({ content, expected }) => {
    expect(classifyArtifactType(content, DOC)).toBe(expected);
  });

  it('a fenced block containing capabilities: that fails to load still classifies as a skill', () => {
    // An unquoted `: ` inside a value is the commonest YAML error in hand-written skill
    // frontmatter. Reading a loader failure as "no capabilities" would let one stray colon
    // switch off every skill analyzer, so a failed load falls back to the column-0 key test.
    const block = 'name: deploy\ndescription: Deploys the app: builds, tests, then ships\ncapabilities: [run_shell]\n';
    expect(() => yaml.load(block)).toThrow();

    const content = `---\n${block}---\n${BODY}`;
    expect(classifyArtifactType(content, DOC)).toBe('skill');
    // The parser has nothing to report for a block that did not load: over-detection only.
    expect(parseArtifact(content, DOC).frontmatter).toBeUndefined();
  });

  it('a block that fails to load and has no column-0 capabilities line is not a skill', () => {
    const content = `---\nname: deploy\ndescription: Deploys the app: builds, tests, then ships\n---\n${BODY}`;
    expect(classifyArtifactType(content, DOC)).toBe('unknown');
  });

  it('a capabilities key past 64 KiB of frontmatter still classifies as a skill', () => {
    // The loader reads only the first 64 KiB. Padding the block must not hide the key.
    const padding = '# padding line for the frontmatter block\n'.repeat(2000);
    const content = `---\nname: padded\n${padding}capabilities: [run_shell]\n---\n${BODY}`;
    expect(Buffer.byteLength(padding)).toBeGreaterThan(64 * 1024);
    expect(classifyArtifactType(content, DOC)).toBe('skill');
  });

  it('matches the skill path rule on SKILL.md and *.skill.md, as the hardening scanner does', () => {
    for (const path of ['SKILL.md', 'skills/deploy/SKILL.md', 'a\\b\\SKILL.md', 'deploy.skill.md']) {
      expect(classifyArtifactType('no frontmatter', path), path).toBe('skill');
    }
    // Case-sensitive: a lone `skill.md` with no capabilities is not a skill to either layer (#740).
    for (const path of ['skill.md', 'Skill.md', 'SKILLS.md', 'docs/skills-overview.md']) {
      expect(classifyArtifactType('no frontmatter', path), path).toBe('unknown');
    }
  });
});

describe('#423 a YAML tag in frontmatter cannot construct code', () => {
  // The loader runs on js-yaml's default schema, which (js-yaml 4) has no `!!js/function`,
  // `!!js/regexp` or `!!js/undefined` type. A tag the schema does not know is a YAMLException,
  // not a constructed value, so a scanned file's frontmatter is read as data and never evaluated.
  // The failed load then behaves like any other: no frontmatter, and over-detection only.
  const TAGGED = [
    { name: 'short function tag', value: '!!js/function "function () { return 1 }"' },
    { name: 'long function tag', value: '!<tag:yaml.org,2002:js/function> "function () { return 1 }"' },
    { name: 'regexp tag', value: '!!js/regexp /x/' },
    { name: 'undefined tag', value: "!!js/undefined ''" },
  ];

  it.each(TAGGED)('$name: the loader refuses the tag and the parser reports no frontmatter', ({ value }) => {
    const block = `name: deploy\nhook: ${value}\ncapabilities: [run_shell]\n`;
    expect(() => yaml.load(block)).toThrow(/unknown tag/);

    const parsed = parseArtifact(`---\n${block}---\n${BODY}`, DOC);
    expect(parsed.frontmatter).toBeUndefined();
    // The column-0 capabilities line still counts, as for any block that fails to load.
    expect(parsed.type).toBe('skill');
  });

  it('a tagged block with no column-0 capabilities line stays unknown', () => {
    const content = `---\nname: deploy\nhook: !!js/function "function () { return 1 }"\n---\n${BODY}`;
    expect(classifyArtifactType(content, DOC)).toBe('unknown');
    expect(parseArtifact(content, DOC).frontmatter).toBeUndefined();
  });

  it('no type on the default schema is a JavaScript type', () => {
    const schema = yaml.DEFAULT_SCHEMA as unknown as { explicit: Array<{ tag: string }>; implicit: Array<{ tag: string }> };
    const tags = [...schema.explicit, ...schema.implicit].map((type) => type.tag);
    expect(tags.length).toBeGreaterThan(0);
    expect(tags.filter((tag) => tag.includes(':js/'))).toEqual([]);
  });
});

describe('#423 parseArtifact().frontmatter is the loaded YAML', () => {
  it('reads an inline flow list as a list', () => {
    const parsed = parseArtifact(`---\nname: deploy\ncapabilities: [run_shell, read_files]\n---\n${BODY}`, DOC);
    expect(parsed.type).toBe('skill');
    expect(parsed.frontmatter).toEqual({ name: 'deploy', capabilities: ['run_shell', 'read_files'] });
  });

  it('keeps nesting instead of flattening it', () => {
    const parsed = parseArtifact(ACCEPTANCE[3].content, DOC);
    expect(parsed.type).toBe('skill');
    expect(parsed.frontmatter).toEqual({ name: 'deploy', metadata: { openclaw: { capabilities: ['run_shell'] } } });
  });

  it('gives the semantic compiler the same capabilities for the inline and block spellings', async () => {
    const compiler = new SemanticCompiler({ useNanoMind: false });
    const names = async (frontmatter: string) =>
      (await compiler.compile(`---\nname: deploy\n${frontmatter}---\n${BODY}`, DOC)).ast.declaredCapabilities
        .filter(c => c.declared)
        .map(c => c.name);

    const block = await names('capabilities:\n  - run_shell\n  - read_files\n');
    const inline = await names('capabilities: [run_shell, read_files]\n');
    expect(block).toEqual(['run_shell', 'read_files']);
    expect(inline).toEqual(block);
  });

  it('drops a frontmatter whose aliases expand past the value cap, and still classifies it', () => {
    // 10 references per level, 8 levels: 436 bytes that `String()` expands to 2 * 10^8 chars.
    const lines = ['l0: &l0 [x, x, x, x, x, x, x, x, x, x]'];
    for (let i = 1; i <= 7; i++) lines.push(`l${i}: &l${i} [${Array(10).fill(`*l${i - 1}`).join(', ')}]`);
    lines.push('description: *l7', 'capabilities: [*l6]');
    const content = `---\n${lines.join('\n')}\n---\n${BODY}`;

    const started = performance.now();
    const parsed = parseArtifact(content, DOC);
    const elapsed = performance.now() - started;

    expect(parsed.type).toBe('skill');
    expect(parsed.frontmatter).toBeUndefined();
    expect(elapsed, `alias chain took ${elapsed.toFixed(0)} ms`).toBeLessThan(1000);
  });
});

/**
 * Depth of the shallowest `capabilities` key in `value`, the root mapping being 1 and every
 * mapping or sequence below it adding one; `null` when there is none. Written independently of
 * the parser so the property below checks it rather than restating it.
 */
function capabilitiesDepth(value: unknown, depth = 1): number | null {
  if (value === null || typeof value !== 'object') return null;
  let best: number | null = null;
  if (!Array.isArray(value) && Object.prototype.hasOwnProperty.call(value, 'capabilities')) best = depth;
  for (const child of Array.isArray(value) ? value : Object.values(value)) {
    const d = capabilitiesDepth(child, depth + 1);
    if (d !== null && (best === null || d < best)) best = d;
  }
  return best;
}

/**
 * A root mapping holding `capabilities` at exactly `depth`. With `viaSequence` (depth >= 3) the
 * level-2 container is a sequence, the `skills: [{capabilities: ...}]` shape.
 */
function nested(depth: number, viaSequence: boolean, leaf: unknown): Record<string, unknown> {
  let node: unknown = { name: 'deploy', capabilities: leaf };
  for (let d = depth - 1; d >= 1; d--) {
    node = viaSequence && d === 2 ? [node] : { [`level${d}`]: node };
  }
  return node as Record<string, unknown>;
}

describe('#423 invariant: the classifier is a superset of the parser', () => {
  const generated: Array<Row & { depth: number }> = [];
  const leaves: unknown[] = [['run_shell', 'read_files'], 'run_shell', { shell: true }];
  const wrappers: Array<(block: string) => string> = [
    b => `---\n${b}---\n${BODY}`,
    b => `﻿\n---\n${b}...\n${BODY}`,
    b => `---\n${b}--- end\n${BODY}`.replace(/\n/g, '\r\n'),
  ];
  for (let depth = 1; depth <= 9; depth++) {
    for (const viaSequence of [false, true]) {
      if (viaSequence && depth < 3) continue;
      for (const leaf of leaves) {
        for (const flowLevel of [-1, 1, 3]) {
          const block = yaml.dump(nested(depth, viaSequence, leaf), { flowLevel });
          for (const wrap of wrappers) {
            generated.push({
              name: `depth ${depth}${viaSequence ? ' via a sequence' : ''}, flowLevel ${flowLevel}`,
              content: wrap(block),
              expected: depth <= 8 ? 'skill' : 'unknown',
              depth,
            });
          }
        }
      }
    }
  }
  const all = [...ACCEPTANCE, ...generated];

  it('classifies as skill every input whose frontmatter holds capabilities at depth <= 8', () => {
    let held = 0;
    for (const { name, content } of all) {
      const depth = capabilitiesDepth(parseArtifact(content, DOC).frontmatter);
      if (depth === null || depth > 8) continue;
      held++;
      expect(classifyArtifactType(content, DOC), `${name}: capabilities at depth ${depth}`).toBe('skill');
    }
    // Guard against a vacuous pass: the generator must actually produce in-bounds keys.
    expect(held).toBeGreaterThan(300);
  });

  it('parses every generated input back to the frontmatter the generator meant', () => {
    for (const { name, content, expected, depth } of generated) {
      expect(capabilitiesDepth(parseArtifact(content, DOC).frontmatter), name).toBe(depth);
      expect(classifyArtifactType(content, DOC), name).toBe(expected);
    }
  });
});

describe('#423 false-positive control: a document opening with a horizontal rule', () => {
  // A release note that opens with a rule. Its block loads as one plain scalar, so it is not
  // frontmatter that declares anything, but it carries a placeholder endpoint next to a
  // transmit verb: exactly what draws a CRITICAL AST-EXFIL-001 once a file is typed `skill`.
  const releaseNotes = [
    '---',
    'Release notes for the reporting agent. Each Friday it sends a digest to the',
    'placeholder endpoint https://hooks.example.com/digest until one is configured.',
    'capabilities:unchanged since the previous release.',
    '---',
    '',
    '# Release notes',
    '',
    'Nothing else changed in this release.',
    '',
  ].join('\n');

  let dir: string;
  beforeEach(async () => {
    dir = tempDir('hma-423-');
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  const exfil = (findings: Array<{ checkId: string; passed: boolean; file?: string }>, file: string) =>
    findings.filter(f => !f.passed && f.checkId === 'AST-EXFIL-001' && (f.file ?? '').endsWith(file));

  it('stays unknown and raises no AST-EXFIL-001', async () => {
    expect(yaml.load(releaseNotes.split('\n').slice(1, 4).join('\n'))).toEqual(expect.any(String));
    expect(classifyArtifactType(releaseNotes, 'docs/release-notes.md')).toBe('unknown');

    await mkdir(join(dir, 'docs'));
    await writeFile(join(dir, 'docs', 'release-notes.md'), releaseNotes);
    const result = await runNanoMindScan(dir, []);
    expect(exfil(result.astFindings, 'release-notes.md')).toEqual([]);
  });

  it('the same bytes typed as a skill DO raise AST-EXFIL-001, so the control can fail', async () => {
    await mkdir(join(dir, 'skills'));
    await writeFile(join(dir, 'skills', 'SKILL.md'), releaseNotes);
    const result = await runNanoMindScan(dir, []);
    expect(exfil(result.astFindings, 'SKILL.md').length).toBeGreaterThan(0);
  });
});
