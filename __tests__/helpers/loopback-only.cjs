'use strict';
// Keeps a spawned CLI off the network, preloaded with
//
//   NODE_OPTIONS='--require "__tests__/helpers/loopback-only.cjs"' node dist/cli.js check ...
//
// Every TCP connection a Node process opens, whether from `fetch`, http, https,
// tls or a proxy tunnel, starts in net.Socket.prototype.connect. This refuses
// it there when its host is not loopback (localhost, 127.0.0.0/8 or ::1),
// before the host name is looked up, and fails the socket with ECONNREFUSED,
// the error a closed port gives. A connection to a local socket path is let
// through.
//
// When $HMA_TEST_CONNECT_LOG names a file, each connection is appended to it as
// `allowed <host>:<port>` or `refused <host>:<port>`, so a test can show that
// the preload saw the connections the run made.

const fs = require('node:fs');
const net = require('node:net');

const LOG = process.env.HMA_TEST_CONNECT_LOG;

function note(line) {
  if (!LOG) return;
  try {
    fs.appendFileSync(LOG, line + '\n');
  } catch {
    // Never let the record change the behaviour of the CLI under test.
  }
}

function isLoopback(host) {
  const h = String(host).toLowerCase().replace(/^\[(.*)\]$/, '$1');
  return h === 'localhost' || h === '::1' || /^(::ffff:)?127(\.\d{1,3}){3}$/.test(h);
}

const connect = net.Socket.prototype.connect;

net.Socket.prototype.connect = function (...args) {
  // net.connect and tls.connect pass their arguments on already normalized,
  // as an array whose first element is the options object.
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  let host;
  let port;
  if (first !== null && typeof first === 'object') {
    if (first.path) return connect.apply(this, args);
    host = first.host || 'localhost';
    port = first.port;
  } else if (typeof first === 'string' && !/^\d+$/.test(first)) {
    return connect.apply(this, args); // connect(path)
  } else {
    host = typeof args[1] === 'string' ? args[1] : 'localhost';
    port = first;
  }
  const where = `${host}:${port}`;
  if (isLoopback(host)) {
    note(`allowed ${where}`);
    return connect.apply(this, args);
  }
  note(`refused ${where}`);
  const err = Object.assign(new Error(`connect ECONNREFUSED ${where} (only loopback is reachable under this preload)`), {
    code: 'ECONNREFUSED',
    syscall: 'connect',
    address: host,
    port,
  });
  process.nextTick(() => this.destroy(err));
  return this;
};
