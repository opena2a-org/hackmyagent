#!/usr/bin/env node
// Writes the five demo-agents projects into a directory outside any git work tree.
//
//   node test-fixtures/demo-agents/materialize.mjs [target] [--omit <path>]...
//
// With no target, a new directory is made under the system temporary directory.
// A target must be absent or an empty directory, and neither it nor its nearest
// existing parent may lie inside a git work tree. The project files next to this
// script are copied as they are; the files in templates.json are written from
// their lines, with each {{name}} replaced by the fragments of values[name]
// joined at run time. Every value is fake and carries the FAKE marker.
// --omit skips one template by its path (repeatable).
//
// Prints the target path on stdout and nothing else. Exit 0 written, 1 the
// template data is malformed, 2 the target was refused or the arguments are
// wrong; nothing is written on 1 or 2.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OWN_FILES = new Set(['README.md', 'materialize.mjs', 'templates.json']);
const MARKER = 'FAKE';

function fail(code, message) {
  process.stderr.write(`materialize: ${message}\n`);
  process.exit(code);
}

function parseArgs(argv) {
  const omit = new Set();
  let target;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--omit') {
      const value = argv[++i];
      if (!value) fail(2, '--omit needs a template path');
      omit.add(value);
    } else if (arg.startsWith('-')) {
      fail(2, `unknown option ${arg}`);
    } else if (target === undefined) {
      target = arg;
    } else {
      fail(2, 'takes one target directory');
    }
  }
  return { target, omit };
}

/** The path itself when it exists, otherwise its nearest existing parent. */
function nearestExisting(p) {
  let current = path.resolve(p);
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return current;
}

/** Refuses a directory that git reports as inside a work tree, or that git cannot check. */
function refuseInsideWorkTree(dir, label) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  const probe = nearestExisting(dir);
  const res = spawnSync('git', ['-C', probe, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8', env });
  if (res.error) fail(2, `git is needed to check that ${label} is outside a work tree: ${res.error.message}`);
  if (res.status === 0 && res.stdout.trim() === 'true') {
    fail(2, `${label} ${dir} is inside a git work tree; choose a directory outside any repository`);
  }
}

function loadTemplates(omit) {
  const data = JSON.parse(fs.readFileSync(path.join(HERE, 'templates.json'), 'utf8'));
  const values = new Map();
  for (const [name, fragments] of Object.entries(data.values ?? {})) {
    if (!Array.isArray(fragments) || !fragments.every((f) => typeof f === 'string')) {
      fail(1, `value ${name} is not a list of fragments`);
    }
    const value = fragments.join('');
    if (!value.includes(MARKER)) fail(1, `value ${name} does not carry the ${MARKER} marker`);
    values.set(name, value);
  }
  const known = new Set((data.files ?? []).map((f) => f.path));
  for (const p of omit) if (!known.has(p)) fail(2, `--omit ${p} is not a template path`);
  const files = [];
  for (const file of data.files ?? []) {
    if (omit.has(file.path)) continue;
    const rel = path.normalize(file.path);
    if (path.isAbsolute(rel) || rel.split(path.sep).includes('..')) fail(1, `template path ${file.path} leaves the target`);
    const text = `${file.lines.join('\n')}\n`.replace(/\{\{(\w+)\}\}/g, (_, name) => {
      if (!values.has(name)) fail(1, `${file.path} names an unknown value ${name}`);
      return values.get(name);
    });
    files.push({ rel, text });
  }
  return files;
}

const { target: requested, omit } = parseArgs(process.argv.slice(2));
const files = loadTemplates(omit);

let target;
if (requested === undefined) {
  refuseInsideWorkTree(os.tmpdir(), 'the temporary directory');
  target = fs.mkdtempSync(path.join(os.tmpdir(), 'hma-demo-agents-'));
} else {
  target = path.resolve(requested);
  refuseInsideWorkTree(target, 'target');
  if (fs.existsSync(target)) {
    if (!fs.statSync(target).isDirectory()) fail(2, `target ${target} is not a directory`);
    if (fs.readdirSync(target).length > 0) fail(2, `target ${target} is not empty`);
  }
  fs.mkdirSync(target, { recursive: true });
}

for (const entry of fs.readdirSync(HERE, { withFileTypes: true })) {
  if (OWN_FILES.has(entry.name) || !entry.isDirectory()) continue;
  fs.cpSync(path.join(HERE, entry.name), path.join(target, entry.name), { recursive: true });
}
for (const { rel, text } of files) {
  const dest = path.join(target, rel);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, text, { mode: 0o600 });
}

process.stdout.write(`${target}\n`);
