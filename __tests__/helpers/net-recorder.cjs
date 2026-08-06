'use strict';
// Outbound-request recorder, preloaded into a spawned CLI:
//
//   node --require __tests__/helpers/net-recorder.cjs dist/cli.js check ...
//
// Appends the HOST of every request the process ATTEMPTS to the file named by
// $HMA_TEST_NET_MARKER, one per line.
//
// The recording happens at the call site, before the request is dispatched, so
// what lands in the marker is the process's intent — not the network's
// cooperation. That distinction is the whole point. A test asserting "pypi.org
// was never contacted" must not be satisfiable by pypi.org merely being
// unreachable, and a test asserting "pypi.org WAS contacted" has to hold on a
// machine that is offline. Recording the attempt gives both.
//
// Superseded approach, for the record: an earlier attempt to prove a command
// was network-dependent set HTTPS_PROXY to a dead port. Node's `fetch` ignores
// proxy environment variables, so the control proved nothing and was thrown out.

const fs = require('node:fs');

const MARKER = process.env.HMA_TEST_NET_MARKER;

if (MARKER) {
  const record = (host) => {
    try {
      fs.appendFileSync(MARKER, String(host) + '\n');
    } catch {
      // Never let instrumentation change the behaviour of the CLI under test.
    }
  };

  const hostOf = (u) => {
    try {
      return new URL(String(u)).host;
    } catch {
      return String(u);
    }
  };

  const origFetch = globalThis.fetch;
  if (typeof origFetch === 'function') {
    globalThis.fetch = function (input, init) {
      try {
        record(hostOf(typeof input === 'string' ? input : (input && input.url) || input));
      } catch {
        /* ignore */
      }
      return origFetch.call(this, input, init);
    };
  }

  // `fetch` is the only transport the check path uses today. http/https are
  // wrapped anyway so that swapping transport does not silently turn the
  // absence assertions in check-not-found-json.test.ts into no-ops.
  for (const name of ['http', 'https']) {
    const mod = require('node:' + name);
    for (const fn of ['request', 'get']) {
      const orig = mod[fn];
      if (typeof orig !== 'function') continue;
      mod[fn] = function (...args) {
        try {
          const a = args[0];
          if (typeof a === 'string' || a instanceof URL) record(hostOf(a));
          else if (a && typeof a === 'object') record(a.host || a.hostname || 'unknown');
        } catch {
          /* ignore */
        }
        return orig.apply(this, args);
      };
    }
  }
}
