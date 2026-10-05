/**
 * `detect` names a credential in an AI config by what it is, never by its bytes.
 *
 * The credential finding's reason slot printed the value's vendor prefix, an
 * ellipsis and the length (`= sk-ant-api0… (45 chars)`), and for a value with
 * no vendor prefix an ellipsis and the length (`= … (30 chars)`). Neither is a
 * marker the tool's own marker contract recognises, so a reader of the text
 * or `--json` output could not tell it apart from a quoted fragment, and the
 * length is a fact about the secret the label does not need.
 *
 * The reason now carries the labelled marker `<label>: [REDACTED]` every other
 * credential finding prints: the value's vendor shape when it has one, else
 * `Credential`.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { scanAiConfigs } from '../../src/scanner/detect';
import { containsRedactionMarker } from '../../src/types/redacted-evidence';
import { tempDir } from '../helpers/temp-dir';

// Synthetic bodies: mixed case and digits so no window of one can occur in a
// label by accident.
const BODY = 'Q7x9Z2mK4pL8vR3tW6yB1nC5dF0gH2jS';
const ANTHROPIC = ['sk', `-ant-api03-${BODY}${BODY}`].join('');
const HF = ['hf', `_${BODY}`].join('');
const GITHUB = ['ghp', `_${BODY}Ab12`].join('');
const UNKNOWN = 'zq81Kd7Lm3Np9Rt2Vw5Xy8Ab4Cd6Ef0Gh';

/** Every 4-character window of `body` that `text` contains. */
function leakedWindows(text: string, body: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 4 <= body.length; i++) {
    const w = body.slice(i, i + 4);
    if (text.includes(w)) out.push(w);
  }
  return out;
}

const CASES: ReadonlyArray<{ name: string; file: string; content: string; value: string; reason: string }> = [
  {
    name: 'an Anthropic key in CLAUDE.md',
    file: 'CLAUDE.md',
    content: `# Agent\n\nANTHROPIC_API_KEY=${ANTHROPIC}\n`,
    value: ANTHROPIC,
    reason: '= Anthropic API key: [REDACTED]',
  },
  {
    name: 'a JSON-quoted Hugging Face token in .claude/settings.json',
    file: '.claude/settings.json',
    content: `{\n  "env": {\n    "HF_TOKEN": "${HF}"\n  }\n}\n`,
    value: HF,
    reason: '= Hugging Face token: [REDACTED]',
  },
  {
    name: 'a GitHub token in .cursorrules',
    file: '.cursorrules',
    content: `Use this.\ngithub_token: ${GITHUB}\n`,
    value: GITHUB,
    reason: '= GitHub personal access token: [REDACTED]',
  },
  {
    name: 'an unknown-shape password in .windsurfrules',
    file: '.windsurfrules',
    content: `Rules.\n\npassword = ${UNKNOWN}\n`,
    value: UNKNOWN,
    reason: '= Credential: [REDACTED]',
  },
];

describe('detect credential evidence', () => {
  let root: string;

  beforeAll(() => {
    root = tempDir('hma-detect-marker-');
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  for (const c of CASES) {
    it(`prints the labelled marker for ${c.name}`, () => {
      const dir = tempDir('case-', root);
      mkdirSync(dirname(join(dir, c.file)), { recursive: true });
      writeFileSync(join(dir, c.file), c.content);

      const hit = scanAiConfigs(dir).find((cfg) => cfg.file === c.file);
      expect(hit?.risk, `${c.file} was not reported as a credential`).toBe('critical');
      const reason = hit!.evidence?.reason ?? '';

      expect(reason).toBe(c.reason);
      expect(containsRedactionMarker(reason), reason).toBe(true);
      expect(reason, 'a starred prefix was printed').not.toMatch(/\*/);
      expect(reason, 'the value length was printed').not.toMatch(/chars\)/);
      expect(leakedWindows(reason, c.value), 'credential bytes were printed').toEqual([]);
      // `--json` serialises the evidence as is, so the whole record is checked.
      expect(leakedWindows(JSON.stringify(hit), c.value), 'credential bytes reached the record').toEqual([]);
    });
  }
});
