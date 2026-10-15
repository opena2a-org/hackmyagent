'use strict';
// Records when the spawned CLI writes each chunk to stdout or stderr, preloaded
// with
//
//   NODE_OPTIONS='--require "__tests__/helpers/stdout-clock.cjs"' node dist/cli.js ...
//
// When $HMA_TEST_STDOUT_CLOCK names a file, every write is appended to it as one
// JSON line: { at: <Date.now() before the write>, stream, text }. Writes made
// with `fs.writeSync(1 | 2, ...)`, as the CLI writes a large JSON document,
// are recorded too.
//
// A test reads it to place a payload's time against what the run printed: a
// command prints its report after the scan finished and before it sends
// anything, so a payload stamped with the scan's time is no later than the
// report's first line, and one stamped when it was built or sent is later.

const fs = require('node:fs');

const LOG = process.env.HMA_TEST_STDOUT_CLOCK;
const appendFileSync = fs.appendFileSync;

function textOf(chunk, offset, length) {
  if (typeof chunk === 'string') return chunk;
  const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  if (typeof offset !== 'number') return buf.toString('utf8');
  return buf.subarray(offset, typeof length === 'number' ? offset + length : undefined).toString('utf8');
}

function note(stream, chunk, offset, length) {
  try {
    const text = textOf(chunk, offset, length);
    appendFileSync(LOG, JSON.stringify({ at: Date.now(), stream, text: text.slice(0, 400) }) + '\n');
  } catch {
    // Never let the record change the behaviour of the CLI under test.
  }
}

if (LOG) {
  for (const [stream, name] of [[process.stdout, 'stdout'], [process.stderr, 'stderr']]) {
    const write = stream.write.bind(stream);
    stream.write = function (chunk, ...rest) {
      note(name, chunk);
      return write(chunk, ...rest);
    };
  }
  const writeSync = fs.writeSync;
  fs.writeSync = function (fd, chunk, offset, length, ...rest) {
    if (fd === 1 || fd === 2) note(fd === 1 ? 'stdout' : 'stderr', chunk, offset, length);
    return writeSync.call(fs, fd, chunk, offset, length, ...rest);
  };
}
