#!/usr/bin/env node
// CHANGELOG entries as one file per change, assembled into CHANGELOG.md at release.
//
// Each change is recorded as a fragment in `changelog.d/` beside the CHANGELOG.md
// it feeds. CHANGELOG.md is written only by `release`, in the version-bump change,
// and `check --base` proves that assembly byte for byte. Node standard library only.
//
//   new --type <type> [--issue <n>[,<n>]] [--breaking] [--name <slug>] [--changelog <path>] < entry.md
//   check [--changelog <path>] [--base <sha>]
//   preview [--changelog <path>] [--virtual | --version X.Y.Z [--date YYYY-MM-DD]]
//   release --version X.Y.Z [--date YYYY-MM-DD] [--changelog <path>]
//   verify-release --version X.Y.Z [--changelog <path>]
//   convert --base <ref> [--type <type>] [--name <slug>] [--changelog <path>]
//   convert --legacy [--type <type>] [--changelog <path>]
//
// Exit status: 0 success, 1 refused or check failed, 2 usage error.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const TYPES = [
  ['added', 'Added'],
  ['changed', 'Changed'],
  ['deprecated', 'Deprecated'],
  ['removed', 'Removed'],
  ['fixed', 'Fixed'],
  ['security', 'Security'],
  ['known-issue', 'Known issues'],
];
const TYPE_KEYS = new Set(TYPES.map(([k]) => k));
const TYPE_BY_LABEL = new Map(TYPES.map(([k, label]) => [label.toLowerCase(), k]));
const FRONT_MATTER_KEYS = ['type', 'issue', 'breaking'];
const NAME_RE = /^[a-z0-9]+(-[a-z0-9]+)*-[0-9a-f]{6}\.md$/;
const SLUG_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const SLUG_MAX = 60;
const NAME_MAX = 80;
const RELEASE_RE = /^## \[?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?(.*)$/;
const DATED_HEADING_RE = /^## \[(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\] - (\d{4}-\d{2}-\d{2})$/;
const UNRELEASED_RE = /^## \[Unreleased\][ \t]*$/i;
const HEADING_RE = /^ {0,3}#{1,6}(\s|$)/;
const LIST_ITEM_RE = /^ {0,3}([-*+]|\d{1,9}[.)])(\s|$)/;
const SCRIPT_PATH = 'scripts/changelog.mjs';
const FRAGMENT_DIR = 'changelog.d';

// The Unreleased block of every converted CHANGELOG.md holds this paragraph only.
const POINTER =
  'Entries for the next release are kept as one file per change in [`changelog.d/`](changelog.d/) ' +
  'and are added to this file when the release is cut. ' +
  '`node scripts/changelog.mjs preview --virtual` prints this file with them included.';

class Refusal extends Error {
  constructor(lines) {
    super(Array.isArray(lines) ? lines.join('\n') : lines);
    this.lines = Array.isArray(lines) ? lines : [lines];
  }
}
class Usage extends Error {}

// ---------------------------------------------------------------- git and files

let topCache;
function repoTop() {
  if (topCache === undefined) {
    try {
      topCache = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      topCache = null;
    }
  }
  return topCache;
}

function git(args, { buffer = false, allowFail = false } = {}) {
  const top = repoTop();
  if (!top) throw new Refusal('this command needs a git repository');
  try {
    const out = execFileSync('git', ['-C', top, ...args], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 28 });
    return buffer ? out : out.toString('utf8');
  } catch (e) {
    if (allowFail) return null;
    const msg = e.stderr ? e.stderr.toString('utf8').trim() : e.message;
    throw new Refusal(`git ${args.join(' ')} failed: ${msg}`);
  }
}

const toPosix = p => p.split(path.sep).join('/');
const relTop = abs => toPosix(path.relative(repoTop(), abs));
const shown = abs => path.relative(process.cwd(), abs) || abs;

/** Reads files from the working tree, or from a commit when `rev` is given. */
function treeReader(rev) {
  if (!rev) {
    return {
      read: abs => (fs.existsSync(abs) && fs.statSync(abs).isFile() ? fs.readFileSync(abs) : null),
      list: absDir => {
        if (!fs.existsSync(absDir)) return null;
        return fs.readdirSync(absDir, { withFileTypes: true }).map(d => ({ name: d.name, isFile: d.isFile() }));
      },
    };
  }
  return {
    read: abs => git(['cat-file', 'blob', `${rev}:${relTop(abs)}`], { buffer: true, allowFail: true }),
    list: absDir => {
      const out = git(['ls-tree', '-z', rev, '--', `${relTop(absDir)}/`], { allowFail: true });
      if (!out) return null;
      const entries = out.split('\0').filter(Boolean).map(e => {
        const [meta, p] = e.split('\t');
        return { name: path.posix.basename(p), isFile: meta.split(' ')[1] === 'blob' };
      });
      return entries.length ? entries : null;
    },
  };
}

const text = buf => (buf === null ? null : buf.toString('utf8'));
const fragmentDir = changelog => path.join(path.dirname(changelog), FRAGMENT_DIR);

// ---------------------------------------------------------------- markdown

/** For each line: true when it is a fence delimiter or inside a fenced code block. */
function fenceMask(lines) {
  const mask = [];
  let fence = null;
  for (const l of lines) {
    if (fence) {
      const close = /^ {0,3}(`{3,}|~{3,})[ \t]*$/.exec(l);
      if (close && close[1][0] === fence[0] && close[1].length >= fence.length) fence = null;
      mask.push(true);
      continue;
    }
    const open = /^ {0,3}(`{3,}|~{3,})/.exec(l);
    if (open && !(open[1][0] === '`' && l.slice(l.indexOf(open[1]) + open[1].length).includes('`'))) {
      fence = open[1];
      mask.push(true);
      continue;
    }
    mask.push(false);
  }
  return mask;
}

const isParagraphLine = l =>
  l.trim() !== '' && !LIST_ITEM_RE.test(l) && !HEADING_RE.test(l) && !/^ {0,3}>/.test(l) && !/^ {4,}/.test(l);

/** Level 1 to 3 headings outside fenced code: ATX (`#`, `##`, `###`) and setext underlines. */
function headingViolations(lines) {
  const mask = fenceMask(lines);
  const out = [];
  lines.forEach((l, i) => {
    if (mask[i]) return;
    if (/^ {0,3}#{1,3}(\s|$)/.test(l)) out.push(l);
    else if (/^ {0,3}(=+|-+)[ \t]*$/.test(l) && i > 0 && !mask[i - 1] && isParagraphLine(lines[i - 1])) out.push(`${lines[i - 1]} / ${l}`);
  });
  return out;
}

const trimBlankLines = lines => {
  let a = 0;
  let b = lines.length;
  while (a < b && lines[a].trim() === '') a++;
  while (b > a && lines[b - 1].trim() === '') b--;
  return lines.slice(a, b);
};

// ---------------------------------------------------------------- fragments

/** Parses one fragment file. Returns { fragment } or { errors }. */
function parseFragment(name, buf) {
  const errors = [];
  const bad = why => errors.push(`${name}: ${why}`);
  if (!NAME_RE.test(name)) bad('file name must match <slug>-<6 lowercase hex>.md (lowercase letters, digits and single hyphens)');
  if (name.length > NAME_MAX) bad(`file name is longer than ${NAME_MAX} characters`);
  let src;
  try {
    src = new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    bad('is not valid UTF-8');
    return { errors };
  }
  if (src.includes('\r')) {
    bad('has CR characters; use LF line endings');
    return { errors };
  }
  const lines = src.split('\n');
  const close = lines.indexOf('---', 1);
  if (lines[0] !== '---' || close < 0) {
    bad('must start with a front-matter block between two --- lines');
    return { errors };
  }
  const fm = {};
  for (const l of lines.slice(1, close)) {
    const m = /^([A-Za-z_-]+): (.*)$/.exec(l);
    if (!m) {
      bad(`front-matter line "${l}" is not "key: value"`);
      continue;
    }
    const [, k, v] = m;
    if (!FRONT_MATTER_KEYS.includes(k)) bad(`unknown front-matter key "${k}"`);
    else if (k in fm) bad(`duplicate front-matter key "${k}"`);
    else fm[k] = v;
  }
  if (fm.type === undefined) bad('front-matter has no "type"');
  else if (!TYPE_KEYS.has(fm.type)) bad(`type "${fm.type}" is not one of ${[...TYPE_KEYS].join(', ')}`);
  let issues = [];
  if (fm.issue !== undefined) {
    const parts = fm.issue.split(',').map(s => s.trim());
    for (const p of parts) if (!/^[1-9]\d*$/.test(p)) bad(`issue "${p}" is not an issue or PR number`);
    issues = parts.filter(p => /^[1-9]\d*$/.test(p)).map(Number);
  }
  if (fm.breaking !== undefined && fm.breaking !== 'true' && fm.breaking !== 'false') bad('breaking must be true or false');
  const body = trimBlankLines(lines.slice(close + 1));
  if (body.length === 0) bad('the entry text after the front-matter is empty');
  for (const h of headingViolations(body)) bad(`"${h}" is a level 1-3 heading outside a fenced code block; entries use #### or lower`);
  if (errors.length) return { errors };
  return { fragment: { name, type: fm.type, issues, breaking: fm.breaking === 'true', body: body.join('\n') } };
}

/** Every fragment in a changelog.d directory. README.md is skipped; anything else must be a valid fragment. */
function readFragments(dirAbs, reader) {
  const entries = reader.list(dirAbs) ?? [];
  const fragments = [];
  const errors = [];
  const raw = new Map();
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (e.name === 'README.md') continue;
    if (!e.isFile) {
      errors.push(`${e.name}: only fragment files and README.md may sit in ${FRAGMENT_DIR}/`);
      continue;
    }
    const buf = reader.read(path.join(dirAbs, e.name));
    raw.set(e.name, buf);
    const r = parseFragment(e.name, buf);
    if (r.errors) errors.push(...r.errors);
    else fragments.push(r.fragment);
  }
  return { fragments, errors, raw };
}

// ---------------------------------------------------------------- changelog structure

function parseChangelog(src) {
  const lines = src.split('\n');
  const mask = fenceMask(lines);
  const releases = [];
  let unreleased = -1;
  const h2 = [];
  lines.forEach((l, i) => {
    if (mask[i] || !l.startsWith('## ')) return;
    h2.push(i);
    if (UNRELEASED_RE.test(l)) {
      if (unreleased < 0) unreleased = i;
      return;
    }
    const m = RELEASE_RE.exec(l);
    if (m) releases.push({ version: m[1], index: i, heading: l, placeholder: /YYYY|TBD|unreleased/i.test(l) });
  });
  const nextH2 = i => h2.find(j => j > i) ?? lines.length;
  const unreleasedBody = unreleased < 0 ? null : lines.slice(unreleased + 1, nextH2(unreleased));
  return { lines, mask, releases, unreleased, unreleasedBody, h2, nextH2 };
}

const firstDated = cl => cl.releases.find(r => !r.placeholder);

function unreleasedErrors(cl) {
  if (cl.unreleased < 0) return ['has no "## [Unreleased]" heading'];
  const errs = [];
  for (const l of cl.unreleasedBody) {
    if (HEADING_RE.test(l)) errs.push(`"## [Unreleased]" holds a heading ("${l}"); entries are fragments in ${FRAGMENT_DIR}/`);
    else if (LIST_ITEM_RE.test(l)) errs.push(`"## [Unreleased]" holds a list item ("${l}"); entries are fragments in ${FRAGMENT_DIR}/`);
  }
  return errs;
}

// ---------------------------------------------------------------- versions and dates

function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(v ?? '');
  return m ? { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] ? m[4].split('.') : [] } : null;
}

function compareSemver(a, b) {
  for (const k of ['major', 'minor', 'patch']) if (a[k] !== b[k]) return a[k] - b[k];
  if (!a.pre.length || !b.pre.length) return b.pre.length - a.pre.length;
  for (let i = 0; i < Math.max(a.pre.length, b.pre.length); i++) {
    const x = a.pre[i];
    const y = b.pre[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny && +x !== +y) return +x - +y;
    if (nx !== ny) return nx ? -1 : 1;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function isRealDate(d) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d ?? '')) return false;
  const t = new Date(`${d}T00:00:00Z`);
  return !Number.isNaN(t.getTime()) && t.toISOString().slice(0, 10) === d;
}

const today = () => new Date().toISOString().slice(0, 10);

/** The section 2.2 bump rules. `newest` is the newest release heading's version, or undefined. */
function bumpErrors(fragments, version, newest) {
  const v = parseSemver(version);
  if (!v) return [`version "${version ?? ''}" is not semver X.Y.Z`];
  const errs = [];
  const n = newest === undefined ? null : parseSemver(newest);
  if (n && compareSemver(v, n) <= 0) errs.push(`version ${version} is not greater than the newest release ${newest}`);
  const major = fragments.filter(f => f.breaking || f.type === 'removed');
  if (n && major.length) {
    const names = major.map(f => f.name).join(', ');
    if (n.major === 0 && !(v.major > n.major || (v.major === n.major && v.minor > n.minor))) {
      errs.push(`${names} ${major.length === 1 ? 'is' : 'are'} breaking or removed: below 1.0.0 the minor or major number must rise (${newest} -> ${version})`);
    } else if (n.major > 0 && !(v.major > n.major)) {
      errs.push(`${names} ${major.length === 1 ? 'is' : 'are'} breaking or removed: the major number must rise (${newest} -> ${version})`);
    }
  }
  return errs;
}

// ---------------------------------------------------------------- layout (the one template)

const sortKey = f => (f.issues.length ? Math.min(...f.issues) : Infinity);
const byOrder = (a, b) => sortKey(a) - sortKey(b) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);

/** Type headings in fixed order; each fragment's text followed by exactly one blank line. */
function renderGroups(fragments) {
  const out = [];
  for (const [type, label] of TYPES) {
    const group = fragments.filter(f => f.type === type).sort(byOrder);
    if (!group.length) continue;
    out.push(`### ${label}`, '');
    for (const f of group) out.push(...f.body.split('\n'), '');
  }
  return out;
}

const renderSection = (fragments, version, date) => [`## [${version}] - ${date}`, '', ...renderGroups(fragments)];

/** Inserts lines directly above the newest release heading (below the Unreleased block). */
function insertBlock(src, block) {
  const cl = parseChangelog(src);
  const lines = [...cl.lines];
  if (cl.releases.length) {
    lines.splice(cl.releases[0].index, 0, ...block);
    return lines.join('\n');
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return [...lines, '', ...block].join('\n');
}

const assemble = (src, fragments, version, date) => insertBlock(src, renderSection(fragments, version, date));
const virtual = (src, fragments) => (fragments.length ? insertBlock(src, renderGroups(fragments)) : src);

// ---------------------------------------------------------------- shared by convert and convert --legacy

const isUndatedHeading = l => UNRELEASED_RE.test(l) || (RELEASE_RE.test(l) && /YYYY|TBD|unreleased/i.test(l));

const typeHeading = l => {
  const m = /^### (.+?)[ \t]*$/.exec(l);
  return m ? (TYPE_BY_LABEL.get(m[1].toLowerCase()) ?? null) : null;
};

function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, SLUG_MAX).replace(/-+$/, '');
}

function branchSlug() {
  let branch;
  try {
    branch = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    throw new Refusal('cannot read the current branch; pass --name <slug>');
  }
  const slug = slugify(branch.split('/').pop());
  if (!slug) throw new Refusal(`branch "${branch}" gives an empty slug; pass --name <slug>`);
  return slug;
}

function slugFromOption(name) {
  if (!SLUG_RE.test(name) || name.length > SLUG_MAX) {
    throw new Refusal(`--name "${name}" must be lowercase letters, digits and single hyphens, at most ${SLUG_MAX} characters`);
  }
  return name;
}

/** Issue numbers named in a promoted `#### title` line, in order of appearance. */
function titleIssues(body) {
  const first = body.split('\n')[0];
  if (!first.startsWith('#### ')) return [];
  return [...new Set([...first.matchAll(/#(\d+)\b/g)].map(m => Number(m[1])).filter(n => n > 0))];
}

function fragmentText({ type, issues = [], breaking = false, issueText }, body) {
  const fm = [`type: ${type}`];
  if (issueText !== undefined) fm.push(`issue: ${issueText}`);
  else if (issues.length) fm.push(`issue: ${issues.join(', ')}`);
  if (breaking) fm.push('breaking: true');
  return ['---', ...fm, '---', body, ''].join('\n');
}

/** Validates every planned fragment first, then writes each under a fresh random suffix. */
function writeFragments(dirAbs, planned) {
  const errors = [];
  for (const p of planned) {
    const probe = `${p.slug}-000000.md`;
    const r = parseFragment(probe, Buffer.from(p.text));
    if (r.errors) errors.push(...r.errors.map(e => e.replace(`${probe}: `, `entry "${p.body.split('\n')[0]}": `)));
  }
  if (errors.length) throw new Refusal(errors);
  fs.mkdirSync(dirAbs, { recursive: true });
  const written = [];
  for (const p of planned) {
    for (let attempt = 0; ; attempt++) {
      const file = path.join(dirAbs, `${p.slug}-${crypto.randomBytes(3).toString('hex')}.md`);
      try {
        fs.writeFileSync(file, p.text, { flag: 'wx' });
        written.push(file);
        break;
      } catch (e) {
        if (e.code !== 'EEXIST' || attempt > 32) throw e;
      }
    }
  }
  return written;
}

// ---------------------------------------------------------------- the R6 line-preservation check

/** The undated region: from the first `## ` heading to the first dated release heading. */
function undatedRegion(cl) {
  const start = cl.h2[0];
  if (start === undefined) return null;
  const dated = firstDated(cl);
  return { start, end: dated ? dated.index : cl.lines.length };
}

/**
 * Non-blank lines of the source's undated region, minus `##` headings and `### <type>`
 * headings, against the non-blank lines of the fragments, with each promoted `####` title
 * read back as `###`. Compared as multisets. Returns a list of differences.
 */
function preservationErrors(sourceText, fragments) {
  const cl = parseChangelog(sourceText);
  const region = undatedRegion(cl);
  const want = new Map();
  const add = (m, l, d) => m.set(l, (m.get(l) ?? 0) + d);
  if (region) {
    for (let i = region.start; i < region.end; i++) {
      const l = cl.lines[i];
      if (l.trim() === '') continue;
      if (!cl.mask[i] && (l.startsWith('## ') || typeHeading(l))) continue;
      add(want, l, 1);
    }
  }
  for (const f of fragments) {
    f.body.split('\n').forEach((l, i) => {
      if (l.trim() === '') return;
      add(want, i === 0 && l.startsWith('#### ') ? l.slice(1) : l, -1);
    });
  }
  const errs = [];
  for (const [l, n] of want) {
    if (n > 0) errs.push(`line missing from the fragments (${n}x): "${l}"`);
    if (n < 0) errs.push(`line in the fragments that is not in the converted region (${-n}x): "${l}"`);
  }
  return errs;
}

function pointerOnlyErrors(cl) {
  if (cl.unreleased < 0) return ['has no "## [Unreleased]" heading'];
  const body = trimBlankLines(cl.unreleasedBody);
  const errs = [];
  if (!body.length) errs.push('"## [Unreleased]" must hold the pointer paragraph');
  if (body.some(l => l.trim() === '')) errs.push('"## [Unreleased]" must hold one paragraph only, the pointer');
  if (body.some(l => HEADING_RE.test(l) || LIST_ITEM_RE.test(l) || /^ {0,3}(`{3,}|~{3,})/.test(l))) errs.push('"## [Unreleased]" holds entries; it must hold the pointer paragraph only');
  if (body.length && !body.join(' ').includes(FRAGMENT_DIR)) errs.push(`the "## [Unreleased]" paragraph does not point at ${FRAGMENT_DIR}/`);
  return errs;
}

// ---------------------------------------------------------------- commands

function changelogPath(opts) {
  return path.resolve(opts.changelog ?? 'CHANGELOG.md');
}

function readChangelog(abs) {
  if (!fs.existsSync(abs)) throw new Refusal(`${shown(abs)} does not exist`);
  return fs.readFileSync(abs, 'utf8');
}

function requireConverted(changelog) {
  const readme = path.join(fragmentDir(changelog), 'README.md');
  if (!fs.existsSync(readme)) throw new Refusal(`${shown(readme)} does not exist, so ${shown(changelog)} does not take fragments`);
}

function loadFragments(changelog) {
  const r = readFragments(fragmentDir(changelog), treeReader());
  if (r.errors.length) throw new Refusal(r.errors);
  return r.fragments;
}

function cmdNew(opts) {
  const changelog = changelogPath(opts);
  requireConverted(changelog);
  if (!opts.type) throw new Usage('new needs --type <type>');
  if (!TYPE_KEYS.has(opts.type)) throw new Refusal(`type "${opts.type}" is not one of ${[...TYPE_KEYS].join(', ')}`);
  const slug = opts.name !== undefined ? slugFromOption(opts.name) : branchSlug();
  let input;
  try {
    input = new TextDecoder('utf-8', { fatal: true }).decode(fs.readFileSync(0));
  } catch {
    throw new Refusal('the entry on standard input is not valid UTF-8');
  }
  if (input.includes('\r')) throw new Refusal('the entry has CR characters; use LF line endings');
  const body = trimBlankLines(input.split('\n')).join('\n');
  if (!body) throw new Refusal('the entry on standard input is empty');
  const [file] = writeFragments(fragmentDir(changelog), [
    { slug, body, text: fragmentText({ type: opts.type, issueText: opts.issue, breaking: !!opts.breaking }, body) },
  ]);
  process.stdout.write(`${shown(file)}\n`);
}

function cmdPreview(opts) {
  const changelog = changelogPath(opts);
  const src = readChangelog(changelog);
  const fragments = loadFragments(changelog);
  if (opts.virtual) {
    process.stdout.write(virtual(src, fragments));
    return;
  }
  const { version, date } = releaseInputs(opts, src, fragments);
  process.stdout.write(renderSection(fragments, version, date).join('\n'));
}

function releaseInputs(opts, src, fragments) {
  if (!opts.version) throw new Usage('--version X.Y.Z is required');
  const date = opts.date ?? today();
  const cl = parseChangelog(src);
  const errs = [...unreleasedErrors(cl)];
  if (!fragments.length) errs.push(`there are no fragments in ${FRAGMENT_DIR}/ to release`);
  if (!isRealDate(date)) errs.push(`date "${date}" is not a real YYYY-MM-DD date`);
  errs.push(...bumpErrors(fragments, opts.version, cl.releases[0]?.version));
  if (errs.length) throw new Refusal(errs);
  return { version: opts.version, date };
}

function cmdRelease(opts) {
  const changelog = changelogPath(opts);
  requireConverted(changelog);
  const src = readChangelog(changelog);
  const fragments = loadFragments(changelog);
  const { version, date } = releaseInputs(opts, src, fragments);
  fs.writeFileSync(changelog, assemble(src, fragments, version, date));
  for (const f of fragments) fs.unlinkSync(path.join(fragmentDir(changelog), f.name));
  process.stdout.write(`${shown(changelog)}: released ${version} - ${date} from ${fragments.length} fragment${fragments.length === 1 ? '' : 's'}\n`);
}

function cmdVerifyRelease(opts) {
  if (!opts.version) throw new Usage('verify-release needs --version X.Y.Z');
  const changelog = changelogPath(opts);
  const src = readChangelog(changelog);
  const errs = [];
  if (!parseSemver(opts.version)) errs.push(`version "${opts.version}" is not semver X.Y.Z`);
  const remaining = (treeReader().list(fragmentDir(changelog)) ?? []).filter(e => e.name !== 'README.md');
  if (remaining.length) errs.push(`${remaining.length} fragment${remaining.length === 1 ? '' : 's'} not assembled: ${remaining.map(e => e.name).join(', ')}`);
  const newest = parseChangelog(src).releases[0];
  const m = newest ? DATED_HEADING_RE.exec(newest.heading) : null;
  if (!newest) errs.push('has no release heading');
  else if (!m || m[1] !== opts.version || !isRealDate(m[2])) {
    errs.push(`the newest release heading is "${newest.heading}", not "## [${opts.version}] - <YYYY-MM-DD>" with a real date`);
  }
  if (errs.length) throw new Refusal(errs.map(e => `${shown(changelog)}: ${e}`));
  process.stdout.write(`ok: ${shown(changelog)} is assembled for ${opts.version}\n`);
}

function cmdConvert(opts) {
  if (opts.type !== undefined && !TYPE_KEYS.has(opts.type)) throw new Refusal(`type "${opts.type}" is not one of ${[...TYPE_KEYS].join(', ')}`);
  return opts.legacy ? convertLegacy(opts) : convertBranch(opts);
}

function convertBranch(opts) {
  if (!opts.base) throw new Usage('convert needs --base <ref> (or --legacy)');
  const changelog = changelogPath(opts);
  const rel = relTop(changelog);
  const mergeBase = git(['merge-base', opts.base, 'HEAD']).trim();
  const baseText = text(git(['cat-file', 'blob', `${mergeBase}:${rel}`], { buffer: true, allowFail: true }));
  const headText = fs.existsSync(changelog) ? fs.readFileSync(changelog, 'utf8') : null;
  if (headText === baseText) {
    process.stdout.write(`${shown(changelog)}: no change against the merge base; nothing to convert\n`);
    return;
  }
  if (baseText === null) throw new Refusal(`refused: ${rel} does not exist at the merge base ${mergeBase.slice(0, 12)}`);
  if (headText === null) throw new Refusal(`refused: ${rel} was deleted on this branch`);

  const diff = git(['diff', '--no-color', '--no-ext-diff', '--no-textconv', '-U0', mergeBase, '--', rel]);
  const added = new Set();
  const refusals = [];
  for (const l of diff.split('\n')) {
    const h = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(l);
    if (h) {
      const oldCount = h[1] === undefined ? 1 : +h[1];
      const start = +h[2];
      const count = h[3] === undefined ? 1 : +h[3];
      if (oldCount > 0) refusals.push(`refused: the hunk at line ${start} deletes or edits an existing line; only additions convert`);
      for (let i = start; i < start + count; i++) added.add(i);
    }
  }

  const cl = parseChangelog(headText);
  let section = null;
  let placeholderSection = false;
  let ctx = null;
  let cur = null;
  const found = [];
  cl.lines.forEach((l, idx) => {
    const n = idx + 1;
    const isAdded = added.has(n);
    const structural = !cl.mask[idx];
    if (structural && l.startsWith('## ')) {
      section = l;
      placeholderSection = isUndatedHeading(l);
      ctx = null;
      cur = null;
      return;
    }
    if (structural && typeHeading(l)) {
      ctx = typeHeading(l);
      cur = null;
      return;
    }
    if (!isAdded) {
      cur = null;
      return;
    }
    if (section === null) {
      refusals.push(`refused: line ${n} is added above the first "## " heading`);
      return;
    }
    if (!placeholderSection) {
      refusals.push(`refused: line ${n} is added under "${section}"; only the undated region converts`);
      return;
    }
    if (structural && l.startsWith('### ')) {
      cur = { type: ctx, lines: [`#${l}`] };
      found.push(cur);
      return;
    }
    if (!cur) {
      if (l.trim() === '') return;
      cur = { type: ctx, lines: [] };
      found.push(cur);
    }
    cur.lines.push(l);
  });
  if (refusals.length) throw new Refusal(refusals);

  const slug = opts.name !== undefined ? slugFromOption(opts.name) : found.length ? branchSlug() : null;
  const planned = planFragments(found, opts, () => slug);
  const files = writeFragments(fragmentDir(changelog), planned);
  fs.writeFileSync(changelog, baseText);
  for (const f of files) process.stdout.write(`${shown(f)}\n`);
}

/** Types, issues and slugs for converted entries; refuses untyped entries without --type. */
function planFragments(found, opts, slugFor) {
  const entries = found.map(f => ({ type: f.type, body: trimBlankLines(f.lines).join('\n') })).filter(f => f.body);
  const untyped = entries.filter(e => !e.type);
  if (untyped.length && !opts.type) {
    throw new Refusal([
      `${untyped.length} entr${untyped.length === 1 ? 'y has' : 'ies have'} no enclosing "### <Type>" heading; pass --type <type>:`,
      ...untyped.map(e => `  ${e.body.split('\n')[0]}`),
    ]);
  }
  return entries.map(e => ({
    slug: slugFor(e),
    body: e.body,
    text: fragmentText({ type: e.type ?? opts.type, issues: titleIssues(e.body) }, e.body),
  }));
}

function convertLegacy(opts) {
  const changelog = changelogPath(opts);
  const src = readChangelog(changelog);
  const cl = parseChangelog(src);
  const region = undatedRegion(cl);
  if (!region) throw new Refusal(`${shown(changelog)} has no "## " section to convert`);
  if (cl.unreleased >= 0 && pointerOnlyErrors(cl).length === 0 && region.end === cl.nextH2(cl.unreleased)) {
    throw new Refusal(`${shown(changelog)} already holds the pointer paragraph only; nothing to convert`);
  }
  const found = [];
  const refusals = [];
  let ctx = null;
  let cur = null;
  for (let i = region.start; i < region.end; i++) {
    const l = cl.lines[i];
    const structural = !cl.mask[i];
    if (structural && l.startsWith('## ')) {
      if (!isUndatedHeading(l)) refusals.push(`refused: line ${i + 1} "${l}" is neither "## [Unreleased]" nor a placeholder-dated release heading`);
      ctx = null;
      cur = null;
      continue;
    }
    if (structural && typeHeading(l)) {
      ctx = typeHeading(l);
      cur = null;
      continue;
    }
    if (structural && l.startsWith('### ')) {
      cur = { type: ctx, lines: [`#${l}`] };
      found.push(cur);
      continue;
    }
    if (!cur) {
      if (l.trim() === '') continue;
      cur = { type: ctx, lines: [] };
      found.push(cur);
    }
    cur.lines.push(l);
  }
  if (refusals.length) throw new Refusal(refusals);

  const planned = planFragments(found, opts, e => slugify(e.body.split('\n')[0].replace(/^#+\s*/, '')) || 'entry');
  const check = preservationErrors(src, planned);
  if (check.length) throw new Refusal(['refused: the conversion would not preserve every line', ...check]);

  const out = [...cl.lines.slice(0, region.start), '## [Unreleased]', '', POINTER, '', ...cl.lines.slice(region.end)];
  if (region.end === cl.lines.length) out.pop();
  const files = writeFragments(fragmentDir(changelog), planned);
  fs.writeFileSync(changelog, out.join('\n'));
  for (const f of files) process.stdout.write(`${shown(f)}\n`);
}

// ---------------------------------------------------------------- check

function discoverChangelogs(base) {
  const top = repoTop();
  const readmes = new Set();
  const want = p => p === `${FRAGMENT_DIR}/README.md` || p.endsWith(`/${FRAGMENT_DIR}/README.md`);
  if (top) {
    for (const p of git(['ls-files', '-z', '--cached', '--others', '--exclude-standard']).split('\0')) if (want(p)) readmes.add(p);
    if (base) for (const p of git(['ls-tree', '-r', '-z', '--name-only', base]).split('\0')) if (want(p)) readmes.add(p);
    return [...readmes].sort().map(p => path.join(top, path.dirname(path.dirname(p)), 'CHANGELOG.md'));
  }
  const local = path.resolve('CHANGELOG.md');
  return fs.existsSync(path.join(fragmentDir(local), 'README.md')) ? [local] : [];
}

function sameBytes(a, b) {
  if (a === null || b === null) return a === b;
  return Buffer.compare(a, b) === 0;
}

function packageVersion(buf) {
  if (buf === null) return null;
  try {
    return JSON.parse(buf.toString('utf8')).version ?? null;
  } catch {
    return null;
  }
}

function checkOne(changelog, base) {
  const errs = [];
  const dir = fragmentDir(changelog);
  const head = treeReader();
  const headConverted = head.read(path.join(dir, 'README.md')) !== null;
  const baseTree = base ? treeReader(base) : null;
  const baseConverted = baseTree ? baseTree.read(path.join(dir, 'README.md')) !== null : false;
  if (!headConverted) {
    if (baseConverted) errs.push(`${FRAGMENT_DIR}/README.md was removed; a converted changelog stays converted`);
    return { errs, count: 0 };
  }
  const headText = text(head.read(changelog));
  if (headText === null) return { errs: ['CHANGELOG.md is missing beside a changelog.d/README.md'], count: 0 };

  // R1
  const headFr = readFragments(dir, head);
  errs.push(...headFr.errors.map(e => `R1: ${FRAGMENT_DIR}/${e}`));
  // R2
  const cl = parseChangelog(headText);
  errs.push(...unreleasedErrors(cl).map(e => `R2: ${e}`));
  if (!base) return { errs, count: headFr.fragments.length };

  const baseText = text(baseTree.read(changelog));
  const baseFr = readFragments(dir, baseTree);

  if (!baseConverted) {
    // R6: the conversion change.
    if (baseText === null) return { errs: [...errs, `R6: CHANGELOG.md does not exist at ${base}`], count: headFr.fragments.length };
    errs.push(...pointerOnlyErrors(cl).map(e => `R6: ${e}`));
    const b = parseChangelog(baseText);
    const bDated = firstDated(b);
    const hDated = firstDated(cl);
    const bRest = bDated ? b.lines.slice(bDated.index).join('\n') : '';
    const hRest = hDated ? cl.lines.slice(hDated.index).join('\n') : '';
    if (bRest !== hRest) errs.push('R6: the released sections changed in the conversion; they must stay byte-identical');
    if (cl.unreleased >= 0 && cl.nextH2(cl.unreleased) !== (hDated ? hDated.index : cl.lines.length)) {
      errs.push('R6: a section sits between "## [Unreleased]" and the newest dated release');
    }
    const addedFragments = headFr.fragments.filter(f => !baseFr.raw.has(f.name));
    errs.push(...preservationErrors(baseText, addedFragments).map(e => `R6: ${e}`));
    return { errs, count: headFr.fragments.length };
  }

  // R3, R4
  const pkg = path.join(path.dirname(changelog), 'package.json');
  const basePkgV = packageVersion(baseTree.read(pkg));
  const headPkgV = packageVersion(head.read(pkg));
  const versionChanged = basePkgV !== headPkgV;
  const changelogChanged = baseText !== headText;
  if (changelogChanged) {
    const aErrs = assemblyErrors({ baseText, headText, baseFr, headFr, headPkgV, pkgExists: head.read(pkg) !== null });
    if (aErrs.length) {
      const bErrs = amendmentErrors({ baseText, headText, baseFr, headFr });
      if (versionChanged) {
        errs.push(`R4: package.json version changed (${basePkgV} -> ${headPkgV}), so CHANGELOG.md must be an assembly:`, ...aErrs.map(e => `  ${e}`));
      } else if (bErrs.length) {
        errs.push('R3: CHANGELOG.md changed, but not as an assembly or a released-section amendment.');
        errs.push('  as an assembly:', ...aErrs.map(e => `    ${e}`));
        errs.push('  as an amendment:', ...bErrs.map(e => `    ${e}`));
      }
    }
  } else if (versionChanged) {
    errs.push(`R4: package.json version changed (${basePkgV} -> ${headPkgV}) without assembling CHANGELOG.md; run release`);
  }

  // R5
  const top = repoTop();
  const script = path.join(top, SCRIPT_PATH);
  const baseScript = baseTree.read(script);
  if (baseScript !== null && !sameBytes(baseScript, head.read(script))) {
    if (changelogChanged) errs.push(`R5: ${SCRIPT_PATH} changed, so CHANGELOG.md must not change in the same change`);
    const deleted = [...baseFr.raw.keys()].filter(n => !headFr.raw.has(n));
    if (deleted.length) errs.push(`R5: ${SCRIPT_PATH} changed, so no fragment may be deleted in the same change (${deleted.join(', ')})`);
  }
  return { errs, count: headFr.fragments.length };
}

function assemblyErrors({ baseText, headText, baseFr, headFr, headPkgV, pkgExists }) {
  const errs = [];
  const b = parseChangelog(baseText);
  const h = parseChangelog(headText);
  const bv = b.releases.map(r => r.version);
  const hv = h.releases.map(r => r.version);
  if (!(hv.length === bv.length + 1 && hv.slice(1).every((v, i) => v === bv[i]))) {
    errs.push('exactly one release heading must be added, above the newest one');
    return errs;
  }
  const m = DATED_HEADING_RE.exec(h.releases[0].heading);
  if (!m || !isRealDate(m[2])) {
    errs.push(`the new heading "${h.releases[0].heading}" is not "## [X.Y.Z] - YYYY-MM-DD" with a real date`);
    return errs;
  }
  const [, version, date] = m;
  if (baseFr.errors.length) errs.push('the base fragments are not all valid');
  if (!baseFr.fragments.length) errs.push('there were no fragments at the base to assemble');
  if (headFr.raw.size) errs.push(`fragments remain or were added: ${[...headFr.raw.keys()].join(', ')}`);
  errs.push(...bumpErrors(baseFr.fragments, version, bv[0]));
  if (pkgExists && headPkgV !== version) errs.push(`package.json version ${headPkgV} does not equal the new heading's ${version}`);
  const expected = assemble(baseText, baseFr.fragments, version, date);
  if (expected !== headText) {
    const e = expected.split('\n');
    const a = headText.split('\n');
    let i = 0;
    while (i < Math.max(e.length, a.length) && e[i] === a[i]) i++;
    errs.push(`CHANGELOG.md is not byte-identical to the assembly of the base fragments; first difference at line ${i + 1}; run release again`);
  }
  return errs;
}

function amendmentErrors({ baseText, headText, baseFr, headFr }) {
  const errs = [];
  const b = parseChangelog(baseText);
  const h = parseChangelog(headText);
  const bv = b.releases.map(r => r.version).join(',');
  const hv = h.releases.map(r => r.version).join(',');
  if (bv !== hv) errs.push('the ordered list of release versions changed');
  const above = cl => cl.lines.slice(0, cl.releases.length ? cl.releases[0].index : cl.lines.length).join('\n');
  if (above(b) !== above(h)) errs.push('the text above the newest release heading changed');
  const names = [...new Set([...baseFr.raw.keys(), ...headFr.raw.keys()])];
  if (names.some(n => !sameBytes(baseFr.raw.get(n) ?? null, headFr.raw.get(n) ?? null))) errs.push(`${FRAGMENT_DIR}/ changed`);
  return errs;
}

function cmdCheck(opts) {
  const base = opts.base ? git(['rev-parse', '--verify', `${opts.base}^{commit}`]).trim() : null;
  const targets = opts.changelog ? [changelogPath(opts)] : discoverChangelogs(base);
  if (!targets.length) {
    process.stdout.write(`ok: no ${FRAGMENT_DIR}/README.md found; nothing to check\n`);
    return;
  }
  const failures = [];
  for (const c of targets) {
    const { errs, count } = checkOne(c, base);
    if (errs.length) failures.push(...errs.map(e => `${shown(c)}: ${e}`));
    else process.stdout.write(`ok: ${shown(c)} (${count} fragment${count === 1 ? '' : 's'})\n`);
  }
  if (failures.length) throw new Refusal(failures);
}

// ---------------------------------------------------------------- entry point

const BOOLEAN = new Set(['virtual', 'breaking', 'legacy']);
const VALUED = new Set(['type', 'issue', 'name', 'changelog', 'base', 'version', 'date']);
const COMMANDS = { new: cmdNew, check: cmdCheck, preview: cmdPreview, release: cmdRelease, 'verify-release': cmdVerifyRelease, convert: cmdConvert };
const USAGE = 'usage: changelog.mjs new|check|preview|release|verify-release|convert [options]  (see the header of scripts/changelog.mjs)';

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const opts = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const key = a.startsWith('--') ? a.slice(2) : null;
    if (key && BOOLEAN.has(key)) opts[key] = true;
    else if (key && VALUED.has(key)) {
      const v = rest[++i];
      if (v === undefined || v.startsWith('--')) throw new Usage(`${a} needs a value`);
      opts[key] = v;
    } else throw new Usage(`unknown argument "${a}"`);
  }
  return { command, opts };
}

try {
  const { command, opts } = parseArgs(process.argv.slice(2));
  const run = COMMANDS[command];
  if (!run) throw new Usage(command ? `unknown command "${command}"` : 'no command');
  run(opts);
} catch (e) {
  if (e instanceof Usage) {
    process.stderr.write(`changelog: ${e.message}\n${USAGE}\n`);
    process.exit(2);
  }
  if (e instanceof Refusal) {
    for (const l of e.lines) process.stderr.write(`changelog: ${l}\n`);
    process.exit(1);
  }
  throw e;
}
