/**
 * `detect` names the governance state it measured: a project whose governance
 * file was read and scored has governance gaps, not "no governance".
 *
 * Before this, every project whose agents were not governed got one title and
 * one why text. On a project holding a `.cursorrules` the meter showed the
 * file's score, the detail line named the file and what it was missing, and
 * the lines around it said the opposite:
 *
 *   HIGH  2 AI agents without governance
 *   These agents can take actions in your project but have no rules ...
 *   Cursor   installed  ungoverned (.cursorrules)
 *
 * WHAT THIS PINS:
 *   1. a project with a scored governance file prints no `without
 *      governance`, no `have no rules` and no `ungoverned`; its title says
 *      `with governance gaps`, its why text names the file, and its agent row
 *      says `governance gaps` with the fix command it had before;
 *   2. a project with no governance file keeps all three of the old strings
 *      and the `harden-soul` fix;
 *   3. `--json` separates the two through `identity.governanceFile` and the
 *      finding's title, and no key of the document, of `summary` or of an
 *      agent is added, removed or renamed (`governanceStatus` keeps its two
 *      values and `summary.ungoverned` keeps counting);
 *   4. from a workspace root, `without governance` is printed for the
 *      project with no governance file and for no other.
 *
 * HERMETICITY: `detect` shells out to `ps aux`, so a planted `ps` on PATH
 * supplies exactly one running agent, and HOME is an empty planted directory
 * so no machine-wide tool config is read. Nothing here samples the host.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { assertDistFresh, BUILT_CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';
import {
  agentGovernanceLabel,
  GOVERNANCE_TITLE_GAPS,
  GOVERNANCE_TITLE_NO_FILE,
} from '../../src/scanner/detect';

let root: string;
let bin: string;
let home: string;

/** A SOUL.md with prose and no controls: found, scored, missing critical controls. */
const SCORED_SOUL = 'scored-soul';
/** A `.cursorrules` with no controls: found and scored, and it also evidences Cursor. */
const SCORED_CURSORRULES = 'scored-cursorrules';
/** Only an MCP config: no governance file at all. */
const NO_FILE = 'no-governance-file';

function write(rel: string, content: string): void {
  const full = path.join(root, rel);
  mkdirSync(path.dirname(full), { recursive: true });
  writeFileSync(full, content);
}

function detect(args: string[]): string {
  try {
    return execFileSync(process.execPath, [BUILT_CLI, 'detect', ...args], {
      encoding: 'utf8',
      timeout: 180_000,
      cwd: root,
      env: {
        ...process.env,
        NO_COLOR: '1',
        OPENA2A_TELEMETRY: 'off',
        HOME: home,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (e: unknown) {
    // `detect` exits 1 on a HIGH finding, which is every case here.
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

interface DetectDoc {
  summary: Record<string, unknown> & { ungoverned: number };
  agents: (Record<string, unknown> & { name: string; governanceStatus: string })[];
  identity: { governanceFile: string | null };
  findings: { category: string; title: string; whyItMatters: string; remediation?: string }[];
}

function detectJson(dir: string): DetectDoc {
  const raw = detect(['--json', dir]);
  expect(raw.length, `detect --json emitted nothing for ${dir}`).toBeGreaterThan(0);
  return JSON.parse(raw) as DetectDoc;
}

/** The governance finding, selected by the two titles the source writes. */
function governanceFinding(doc: DetectDoc): DetectDoc['findings'][number] | undefined {
  return doc.findings.find((f) =>
    f.title.includes(GOVERNANCE_TITLE_GAPS) || f.title.includes(GOVERNANCE_TITLE_NO_FILE));
}

/** The rows under the `AI Agents (N)` header, up to the next blank line. */
function agentRows(out: string): string[] {
  const lines = out.split('\n');
  const start = lines.findIndex((l) => /AI Agents \(\d+\)/.test(l));
  if (start < 0) return [];
  const rows: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() === '') break;
    rows.push(line);
  }
  return rows;
}

function count(out: string, needle: string): number {
  return out.split('\n').filter((l) => l.includes(needle)).length;
}

beforeAll(() => {
  assertDistFresh();
  root = tempDir('hma-detect-gaps-');
  bin = tempDir('hma-detect-gaps-bin-');
  home = tempDir('hma-detect-gaps-home-');

  write(`${SCORED_SOUL}/SOUL.md`, '# SOUL.md\n\nSome prose about the agent.\n');
  write(`${SCORED_CURSORRULES}/.cursorrules`, '# Rules\n\nUse the Drive connector.\n');
  write(`${NO_FILE}/.mcp.json`, JSON.stringify({
    mcpServers: { files: { command: 'npx', args: ['-y', 'mcp-files'] } },
  }, null, 2));

  const ps = path.join(bin, 'ps');
  writeFileSync(
    ps,
    '#!/bin/sh\n'
    + "printf '%s\\n' 'USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND'\n"
    + "printf '%s\\n' 'fixture 4242 0.0 0.0 4200 900 ?? S 1:00AM 0:00.10 /usr/local/bin/aider --yes'\n",
  );
  chmodSync(ps, 0o755);
}, 60_000);

describe('agentGovernanceLabel', () => {
  it('reads governed, governance gaps or ungoverned from the status and the governance file', () => {
    expect(agentGovernanceLabel({ governanceStatus: 'governed' }, 'SOUL.md')).toBe('governed');
    expect(agentGovernanceLabel({ governanceStatus: 'no governance' }, 'CLAUDE.md')).toBe('governance gaps');
    expect(agentGovernanceLabel({ governanceStatus: 'no governance' }, null)).toBe('ungoverned');
  });
});

describe('detect on a project whose governance file was read and scored', () => {
  it('says governance gaps, never that the agents have no governance or no rules', () => {
    const out = detect([SCORED_SOUL]);
    expect(out, 'no output captured').toContain('AI Agents (');

    expect(count(out, 'without governance'), out).toBe(0);
    expect(count(out, 'have no rules'), out).toBe(0);
    expect(count(out, 'ungoverned'), out).toBe(0);

    expect(out).toContain(`HIGH  1 AI agent ${GOVERNANCE_TITLE_GAPS}`);
    expect(out).toContain("This project's governance file, SOUL.md, was read and scored.");
    // The detail line still names the file and what it lacks.
    expect(out).toMatch(/Aider \(running\) — SOUL\.md is missing \d+ critical control\(s\)/);

    const rows = agentRows(out);
    expect(rows, `agents table:\n${rows.join('\n')}`).toHaveLength(1);
    expect(rows[0]).toMatch(/^\s+Aider\s+running\s+governance gaps\s+→\s+hackmyagent harden-soul /);
  });

  it('says governance gaps for every agent of a project governed by a .cursorrules', () => {
    const out = detect([SCORED_CURSORRULES]);
    expect(count(out, 'without governance'), out).toBe(0);
    expect(count(out, 'have no rules'), out).toBe(0);
    expect(count(out, 'ungoverned'), out).toBe(0);
    expect(out).toContain(`HIGH  2 AI agents ${GOVERNANCE_TITLE_GAPS}`);
    expect(out).toContain("This project's governance file, .cursorrules, was read and scored.");

    const rows = agentRows(out);
    expect(rows, `agents table:\n${rows.join('\n')}`).toHaveLength(2);
    expect(rows.find((r) => /^\s+Aider\s/.test(r))).toMatch(/running\s+governance gaps\s/);
    expect(rows.find((r) => /^\s+Cursor\s/.test(r))).toMatch(/installed\s+governance gaps \(\.cursorrules\)/);
  });
});

describe('detect on a project with no governance file', () => {
  it('keeps without governance, the no-rules text, the ungoverned row and the harden-soul fix', () => {
    const out = detect([NO_FILE]);
    expect(out).toContain(`HIGH  1 AI agent ${GOVERNANCE_TITLE_NO_FILE}`);
    expect(out).toContain('Aider (running) — no governance file found');
    expect(count(out, 'have no rules'), out).toBe(1);
    expect(out).toMatch(/Fix: hackmyagent harden-soul /);

    const rows = agentRows(out);
    expect(rows, `agents table:\n${rows.join('\n')}`).toHaveLength(1);
    expect(rows[0]).toMatch(/^\s+Aider\s+running\s+ungoverned\s+→\s+hackmyagent harden-soul /);
    expect(count(out, 'governance gaps'), out).toBe(0);
  });
});

describe('detect --json', () => {
  /**
   * The key names of 0.33.2's document, its `summary` and one running agent,
   * read from a build of the commit before this change. The wording change
   * adds no key; a later change that does has to update this list on purpose.
   */
  const DOCUMENT_KEYS = [
    'agents', 'aiConfigs', 'coverage', 'findings', 'identity', 'mcpServers',
    'scanDirectory', 'scanTimestamp', 'summary',
  ];
  const SUMMARY_KEYS = [
    'aiConfigs', 'governanceClamped', 'governanceRaw', 'governanceScore', 'localLlms',
    'mcpServers', 'recoverablePoints', 'totalAgents', 'ungoverned',
  ];
  const RUNNING_AGENT_KEYS = [
    'category', 'governanceStatus', 'identityStatus', 'name', 'pid', 'risk', 'source', 'state',
  ];

  it('separates a scored file from no file by identity.governanceFile and the title', () => {
    const scored = detectJson(SCORED_SOUL);
    expect(scored.identity.governanceFile).toBe('SOUL.md');
    expect(governanceFinding(scored)?.title).toBe(`1 AI agent ${GOVERNANCE_TITLE_GAPS}`);

    const none = detectJson(NO_FILE);
    expect(none.identity.governanceFile).toBeNull();
    expect(governanceFinding(none)?.title).toBe(`1 AI agent ${GOVERNANCE_TITLE_NO_FILE}`);
    expect(governanceFinding(none)?.remediation).toMatch(/^hackmyagent harden-soul /);
  });

  it('keeps the machine fields as they were: same keys, same governanceStatus, same count', () => {
    for (const dir of [SCORED_SOUL, NO_FILE]) {
      const doc = detectJson(dir);
      expect(Object.keys(doc).sort(), `${dir}: document keys`).toEqual(DOCUMENT_KEYS);
      expect(Object.keys(doc.summary).sort(), `${dir}: summary keys`).toEqual(SUMMARY_KEYS);
      const aider = doc.agents.find((a) => a.name === 'Aider');
      expect(aider, `${dir}: the planted agent is missing`).toBeDefined();
      expect(Object.keys(aider!).sort(), `${dir}: agent keys`).toEqual(RUNNING_AGENT_KEYS);
      expect(aider!.governanceStatus).toBe('no governance');
      expect(doc.summary.ungoverned).toBe(1);
    }
  });
});

describe('detect from a workspace root', () => {
  it('prints without governance for the project with no governance file and for no other', () => {
    const out = detect([]);
    for (const p of [SCORED_SOUL, SCORED_CURSORRULES, NO_FILE]) {
      expect(out, `missing ${p}`).toContain(p);
    }
    const noGovernance = out.split('\n').filter((l) => l.includes(GOVERNANCE_TITLE_NO_FILE));
    expect(noGovernance, out).toEqual([`  │ HIGH  1 AI agent ${GOVERNANCE_TITLE_NO_FILE}`]);
    expect(count(out, `AI agent ${GOVERNANCE_TITLE_GAPS}`), out).toBe(1);
    expect(count(out, `AI agents ${GOVERNANCE_TITLE_GAPS}`), out).toBe(1);
  });
});
