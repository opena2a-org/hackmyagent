/**
 * Census over the two live id namespaces.
 *
 * An attack payload id names a stimulus `attack` sends; a check id names a
 * defect `secure` looks for. They used to share one PREFIX-NNN string space,
 * and 58 of the 164 payload ids were byte-equal to a check id (`A2A-001`,
 * every `MCP-0NN`, `MEM-001..006`, all of FAKETOOL / LIFECYCLE / PARSE /
 * PERSIST). `MCP-003` then meant one thing in `attack --json` and another in
 * `secure --json`, and a consumer asking "is this a known check id?" got a yes
 * for the wrong object. Payload ids now carry an `ATK-` prefix that keeps the
 * family code, and this census keeps the two spaces apart.
 *
 * Neither set is a literal list here. The payload set is read out of whatever
 * modules exist under src/attack/payloads/ at test time; the check set is the
 * key set of getTaxonomyMap(), the same object `check-metadata` iterates. A new
 * payload or a new check enters this test by existing, not by being added to it.
 */

import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

import { getTaxonomyMap } from '../../src/hardening/taxonomy';
import { ALL_PAYLOADS, getPayloadById } from '../../src/attack/payloads';
import type { AttackCategory } from '../../src/attack/types';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PAYLOAD_DIR = path.resolve(HERE, '../../src/attack/payloads');

// Every module under src/attack/payloads/, loaded rather than named, so a new
// payload family is enumerated the moment its file lands.
const PAYLOAD_MODULES = import.meta.glob<Record<string, unknown>>(
  '../../src/attack/payloads/*.ts',
  { eager: true },
);

const loadedModuleFiles = Object.keys(PAYLOAD_MODULES).map((p) => path.basename(p)).sort();
const onDiskModuleFiles = fs
  .readdirSync(PAYLOAD_DIR)
  .filter((f) => f.endsWith('.ts'))
  .sort();

/**
 * Every id carried by every payload object exported by those modules. Walks
 * the exported arrays rather than naming them, so a family missing from
 * index.ts still counts. index.ts re-exports the same objects, so a set.
 */
function livePayloadIds(): Set<string> {
  const ids = new Set<string>();
  for (const mod of Object.values(PAYLOAD_MODULES)) {
    for (const value of Object.values(mod)) {
      if (!Array.isArray(value)) continue;
      for (const entry of value) {
        if (entry && typeof entry === 'object' && typeof (entry as { id?: unknown }).id === 'string') {
          ids.add((entry as { id: string }).id);
        }
      }
    }
  }
  return ids;
}

const payloadIdSet = livePayloadIds();
const checkIdSet = new Set(Object.keys(getTaxonomyMap()));

/** `ATK-<FAMILY>-NNN`: the family code survives the prefix. */
const ATK_ID = /^ATK-([A-Z][A-Z0-9]*)-\d{3}$/;

// The family code each category's ids carry after the prefix.
const FAMILY_BY_CATEGORY: Readonly<Record<AttackCategory, string>> = {
  'prompt-injection': 'PI',
  jailbreak: 'JB',
  'data-exfiltration': 'DE',
  'capability-abuse': 'CA',
  'context-manipulation': 'CM',
  'mcp-exploitation': 'MCP',
  'a2a-attack': 'A2A',
  'memory-weaponization': 'MEM',
  'context-window': 'CTX',
  'supply-chain': 'SUP',
  'tool-shadow': 'SHADOW',
  'parser-differential': 'PARSE',
  'persistent-agent': 'PERSIST',
  'fake-tool': 'FAKETOOL',
  'context-lifecycle': 'LIFECYCLE',
  'policy-enforcement-integrity': 'PEI',
};

describe('payload / check id census', () => {
  it('sees every payload module on disk, so neither set can go quietly empty', () => {
    expect(onDiskModuleFiles.length).toBeGreaterThan(0);
    expect(loadedModuleFiles).toEqual(onDiskModuleFiles);
    expect(payloadIdSet.size).toBeGreaterThan(0);
    expect(checkIdSet.size).toBeGreaterThan(0);
    for (const p of ALL_PAYLOADS) expect(payloadIdSet.has(p.id), p.id).toBe(true);
  });

  it('no payload id is also a check id', () => {
    const collisions = [...payloadIdSet].filter((id) => checkIdSet.has(id)).sort();
    expect(
      collisions,
      `${collisions.length} id(s) mean one thing to \`attack\` and another to \`secure\`: ${collisions.join(', ')}`,
    ).toEqual([]);
  });

  it('every payload id reads ATK-<FAMILY>-NNN with its own category family code', () => {
    const unprefixed = [...payloadIdSet].filter((id) => !ATK_ID.test(id)).sort();
    expect(unprefixed, `payload ids outside the ATK- namespace: ${unprefixed.join(', ')}`).toEqual([]);
    for (const p of ALL_PAYLOADS) {
      expect(ATK_ID.exec(p.id)?.[1], p.id).toBe(FAMILY_BY_CATEGORY[p.category]);
    }
  });

  it('no check id is in the ATK- namespace', () => {
    expect([...checkIdSet].filter((id) => id.startsWith('ATK-'))).toEqual([]);
  });

  it('a payload id from before the prefix still resolves to the same payload', () => {
    for (const p of ALL_PAYLOADS) {
      const legacy = p.id.replace(/^ATK-/, '');
      expect(getPayloadById(legacy)?.id, legacy).toBe(p.id);
      expect(getPayloadById(p.id)?.id).toBe(p.id);
    }
    expect(getPayloadById('ATK-INVALID-999')).toBeUndefined();
    expect(getPayloadById('INVALID-999')).toBeUndefined();
  });
});
