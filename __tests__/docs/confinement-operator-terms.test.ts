/**
 * The README and CHANGELOG state out-of-tree link confinement in the
 * operator's terms, and the report's retarget line uses the same phrase, so
 * the three cannot drift apart: a reader who sees the line in a report can
 * find the paragraph that explains it by searching for those words.
 *
 * "One contiguous sentence" is what the regex holds them to — a line break
 * inside the phrase would make the search fail on the rendered page.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { retargetInstruction, withheldLinkLines } from '../../src/hardening/withheld-links';

const ROOT = path.resolve(__dirname, '../..');
const PHRASE = /point the scan at/;

describe('out-of-tree link confinement is stated in the operator\'s terms', () => {
  it('README says it in one sentence containing the retarget phrase', () => {
    const readme = readFileSync(path.join(ROOT, 'README.md'), 'utf8');
    // README paragraphs are one line each, so "one contiguous sentence" is
    // "the phrase and its subject sit on one line".
    const lines = readme.split('\n').filter((l) => PHRASE.test(l));
    expect(lines, 'README line with "point the scan at"').toHaveLength(1);
    expect(lines[0]).toMatch(/is not followed/);
    expect(lines[0]).toMatch(/hackmyagent secure /);
  });

  it('CHANGELOG says it under Unreleased in one sentence containing the retarget phrase', () => {
    const changelog = readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
    const unreleased = changelog.split(/^## \[/m)[1] ?? '';
    expect(unreleased.startsWith('Unreleased]')).toBe(true);
    // A CHANGELOG paragraph is hard-wrapped; the sentence is contiguous once
    // the wrap is undone, and the phrase itself sits on one line.
    const unwrapped = unreleased.replace(/\n(?!\n)/g, ' ');
    const sentence = unwrapped.split(/(?<=\.)\s+/).find((s) => PHRASE.test(s));
    expect(sentence, 'CHANGELOG sentence with "point the scan at"').toBeDefined();
    expect(unreleased).toMatch(PHRASE);
    expect(unreleased).not.toMatch(/--follow-links-out/);
  });

  it('CHANGELOG makes no from-version range claim (none was execution-confirmed)', () => {
    const changelog = readFileSync(path.join(ROOT, 'CHANGELOG.md'), 'utf8');
    const unreleased = changelog.split(/^## \[/m)[1] ?? '';
    const section = unreleased.split(/^### /m).find((s) => /link out of the directory it scans/.test(s)) ?? '';
    expect(section.length).toBeGreaterThan(0);
    expect(section).not.toMatch(/versions? (before|since|from|through|up to) \d/i);
    expect(section).not.toMatch(/\d+\.\d+\.\d+\s*(-|–|to|through)\s*\d+\.\d+\.\d+/);
  });

  it('the report line carries the same phrase, so a reader can search for the paragraph', () => {
    const line = retargetInstruction('/srv/shared/.env', 'hackmyagent');
    expect(line).toMatch(PHRASE);
    expect(line).toContain('hackmyagent secure /srv/shared');
    const rendered = withheldLinkLines([{ rel: '.env', resolved: '/srv/shared/.env', call: 'readFile', retarget: line }]);
    expect(rendered[0]).toMatch(/1 link inside the scanned tree resolves outside it and was not read/);
    expect(rendered[1]).toBe('  .env -> /srv/shared/.env');
    expect(rendered[2]).toMatch(/^  To scan it, point the scan at \/srv\/shared: hackmyagent secure \/srv\/shared$/);
  });
});
