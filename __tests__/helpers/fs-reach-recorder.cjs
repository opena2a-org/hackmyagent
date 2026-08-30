'use strict';
// Out-of-tree reach recorder, preloaded into a spawned CLI or scan driver:
//
//   HMA_TEST_CONFINE_ROOTS=/fixture/linked HMA_TEST_REACH_MARKER=/tmp/reach.json \
//     node --require __tests__/helpers/fs-reach-recorder.cjs dist/cli.js secure /fixture/linked
//
// Instruments the REAL `fs/promises` and `fs` functions BEFORE `dist` loads,
// so the tracked namespace in `dist/hardening/tracked-fs.js` copies the
// instrumented functions and every call that gets PAST its guard is seen
// here. A call the guard refuses never reaches these wrappers, which is the
// property the test measures: what actually reached the filesystem, not what
// was attempted. On the pre-fix build the same preload records every reach.
//
// A reach is a link-following call whose first argument is lexically inside
// one of the confinement roots and whose real path is outside all of them —
// the invariant's own predicate, re-derived here from the real `realpathSync`
// (captured before any wrapping) rather than imported from the code under
// test. `lstat`/`readlink` are parent-only, as in the guard. Paths lexically
// outside every root (HMA's own files, `require()` reads of `dist`) are not
// reaches.
//
// Writes `{ reaches: [{call, path, resolved, frame}], calls: n }` to
// $HMA_TEST_REACH_MARKER at process exit.
//
// With $HMA_TEST_FETCH_MARKER set, `globalThis.fetch` is replaced by a stub
// that appends every request body to that file and answers with an empty
// Layer-3 result, so a `--deep` run's outbound payload is captured with no
// network and no key that works.

const path = require('node:path');
const fs = require('node:fs');
const fsp = require('node:fs/promises');

const MARKER = process.env.HMA_TEST_REACH_MARKER;
const ROOTS = (process.env.HMA_TEST_CONFINE_ROOTS || '')
  .split(path.delimiter)
  .filter(Boolean)
  .map((r) => path.resolve(r));

const realpathSync = fs.realpathSync.bind(fs);
const realpathNative = fs.realpathSync.native.bind(fs);
const REAL_ROOTS = ROOTS.flatMap((r) => {
  try { return [realpathSync(r)]; } catch { return []; }
});

const inside = (p, root) => p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep);
const reaches = [];
let calls = 0;

function pathArg(a) {
  if (typeof a === 'string') return a;
  if (Buffer.isBuffer(a)) return a.toString();
  if (a instanceof URL) { try { return require('node:url').fileURLToPath(a); } catch { return null; } }
  return null;
}

function frameOf() {
  const lines = (new Error().stack || '').split('\n').slice(3);
  if (process.env.HMA_TEST_REACH_STACK) return lines.map((l) => l.trim()).join(' | ');
  const hit = lines.find((l) => /dist\//.test(l) && !/fs-reach-recorder/.test(l)) || lines[0] || '';
  return hit.trim().replace(/^at\s+/, '');
}

function check(call, a, parentOnly) {
  const target = pathArg(a);
  if (target === null || ROOTS.length === 0) return;
  // The kernel's view: absolute WITHOUT normalization (`..` after a link must
  // be applied where the link lands), resolved by libc realpath.
  const raw = path.isAbsolute(target) ? target : process.cwd() + path.sep + target;
  if (!ROOTS.some((r) => inside(raw, r))) return;
  // The root's own metadata (its parent is outside the set by definition).
  if (parentOnly && ROOTS.includes(raw)) return;
  calls += 1;
  const leaf = path.basename(raw);
  const leafIsEntry = leaf !== '' && leaf !== '.' && leaf !== '..';
  const probe = parentOnly && leafIsEntry ? path.dirname(raw) : raw;
  let real;
  try { real = realpathNative(probe); } catch { return; }
  if (REAL_ROOTS.some((r) => inside(real, r))) return;
  const lexical = raw;
  reaches.push({
    call,
    path: lexical,
    resolved: parentOnly && leafIsEntry ? path.join(real, leaf) : real,
    frame: frameOf(),
  });
}

function wrap(obj, name, parentOnly) {
  const orig = obj[name];
  if (typeof orig !== 'function') return;
  obj[name] = function (...args) {
    try { check(name, args[0], parentOnly); } catch { /* never change the CLI's behaviour */ }
    return orig.apply(this, args);
  };
}

if (MARKER) {
  for (const n of ['readFile', 'stat', 'access', 'readdir', 'opendir', 'open']) wrap(fsp, n, false);
  for (const n of ['lstat', 'readlink']) wrap(fsp, n, true);
  for (const n of ['readFileSync', 'copyFileSync', 'statSync', 'accessSync', 'readdirSync', 'openSync', 'opendirSync']) wrap(fs, n, false);
  for (const n of ['lstatSync', 'readlinkSync']) wrap(fs, n, true);

  process.on('exit', () => {
    try {
      fs.writeFileSync(MARKER, JSON.stringify({ reaches, calls }, null, 2));
    } catch { /* ignore */ }
  });
}

const FETCH_MARKER = process.env.HMA_TEST_FETCH_MARKER;
if (FETCH_MARKER) {
  globalThis.fetch = async function (input, init) {
    try {
      const url = typeof input === 'string' ? input : (input && input.url) || String(input);
      const body = init && init.body !== undefined ? String(init.body) : '';
      fs.appendFileSync(FETCH_MARKER, JSON.stringify({ url, body }) + '\n');
    } catch { /* ignore */ }
    const stub = { content: [{ type: 'text', text: '{"findings":[]}' }], usage: { input_tokens: 1, output_tokens: 1 } };
    return new Response(JSON.stringify(stub), { status: 200, headers: { 'content-type': 'application/json' } });
  };
}
