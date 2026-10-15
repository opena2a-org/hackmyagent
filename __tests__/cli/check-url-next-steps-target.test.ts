/**
 * `check <URL>` cites in its Next Steps a target that `check` accepts.
 *
 * Before this, the `AI analysis:` line of a URL scan named the scan as its
 * header does: a cloned forge URL without its scheme and `.git`, as in
 * `check gitlab.com/<org>/<repo> --nanomind`, and a downloaded single file by
 * its file name, as in `check SKILL.md --nanomind`. `check` refuses both with
 * `Invalid skill identifier: unrecognized format.` and exit 1. The line now
 * names the URL as the run shows it, without a user name.
 *
 * Each case reads the cited target from the line and runs `check` on it, so
 * the test holds the cited command to what `check` takes, not to a spelling.
 *
 * Hermetic: `git` is a stand-in on PATH that writes one file where the clone
 * goes, and the single file is served by a server on localhost in a child
 * process (`spawnSync` blocks this worker's event loop). The CLI runs with no
 * proxy variables and with __tests__/helpers/loopback-only.cjs preloaded, so
 * nothing reaches the network.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { assertDistFresh, BUILT_CLI as CLI } from '../helpers/dist-freshness';
import { tempDir } from '../helpers/temp-dir';

// Every case reads a run of the built CLI, so a checkout that has not built
// fails here, naming the command to run, rather than skipping the suite.
beforeAll(assertDistFresh);

const LOOPBACK_ONLY = path.join(__dirname, '..', 'helpers', 'loopback-only.cjs');

const REPO = 'gitlab.com/example-org/example-repo';

// Stands in for a git whose clone succeeds: the last argument is where the
// clone goes, and it gets one file there.
const GIT_CLONES = `#!/bin/sh
for dest; do :; done
mkdir -p "$dest" && printf '# Example repository\\n' > "$dest/README.md"
`;

// Serves one markdown file at /SKILL.md, to HEAD and GET.
const SERVER_SRC = `
const http = require('node:http');
const body = '# Example skill\\n\\nSummarizes a file the user names.\\n';
const server = http.createServer((req, res) => {
  if (req.url !== '/SKILL.md') { res.statusCode = 404; res.end(); return; }
  res.setHeader('content-type', 'text/markdown');
  res.setHeader('content-length', Buffer.byteLength(body));
  res.end(req.method === 'HEAD' ? undefined : body);
});
server.listen(0, 'localhost', () => {
  process.stdout.write(String(server.address().port) + '\\n');
});
`;

interface Run {
  status: number | null;
  stdout: string;
  stderr: string;
}

interface Case {
  kind: string;
  typed: string;
  /** The target the `AI analysis:` line should cite. */
  cited: string;
  run?: Run;
  /** The run of `check` on the target the first run cited. */
  rerun?: Run;
}

let scratch = '';
let binDir = '';
let serverProc: ChildProcess | undefined;
const CASES: Case[] = [];

function run(label: string, target: string): Run {
  const dir = path.join(scratch, label);
  const home = path.join(dir, 'home');
  const opena2aHome = path.join(dir, 'opena2a');
  fs.mkdirSync(home, { recursive: true });
  fs.mkdirSync(opena2aHome, { recursive: true });

  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.ANTHROPIC_API_KEY; // no hosted analysis: the run stays local
  delete env.HMA_CLI_PREFIX; // citations read `hackmyagent ...`
  // A proxy on loopback would carry a request on to the network.
  for (const name of ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NODE_USE_ENV_PROXY']) {
    delete env[name];
  }
  const r = spawnSync(process.execPath, [CLI, 'check', target], {
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...env,
      NO_COLOR: '1',
      OPENA2A_TELEMETRY: 'off',
      HOME: home,
      OPENA2A_HOME: opena2aHome,
      PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ''}`,
      NODE_OPTIONS: [env.NODE_OPTIONS, `--require "${LOOPBACK_ONLY}"`].filter(Boolean).join(' '),
    },
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

/** The target of the `check ... --nanomind` command on the `AI analysis:` line, or null. */
function citedTarget(stdout: string): string | null {
  const m = /AI analysis:\s+hackmyagent check (\S+) --nanomind/.exec(stdout);
  return m ? m[1] : null;
}

beforeAll(async () => {
  // Removed when this file finishes, after the afterAll below stops the server.
  scratch = tempDir('hma-url-next-steps-');
  binDir = path.join(scratch, 'bin');
  fs.mkdirSync(binDir, { recursive: true });
  fs.writeFileSync(path.join(binDir, 'git'), GIT_CLONES, { mode: 0o755 });

  const serverFile = path.join(scratch, 'server.js');
  fs.writeFileSync(serverFile, SERVER_SRC);
  serverProc = spawn(process.execPath, [serverFile], { stdio: ['ignore', 'pipe', 'ignore'] });
  const port = await new Promise<string>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('file server did not start')), 10_000);
    serverProc!.stdout!.once('data', (d) => { clearTimeout(t); resolve(String(d).trim()); });
    serverProc!.once('exit', () => { clearTimeout(t); reject(new Error('file server exited')); });
  });
  const fileUrl = `http://localhost:${port}/SKILL.md`;

  CASES.push(
    { kind: 'a forge URL with no `.git`', typed: `https://${REPO}`, cited: `https://${REPO}` },
    { kind: 'a URL that ends in `.git`', typed: `https://${REPO}.git`, cited: `https://${REPO}.git` },
    { kind: 'a forge URL with a user name', typed: `https://fakeuser@${REPO}`, cited: `https://${REPO}` },
    { kind: 'a URL of a single file', typed: fileUrl, cited: fileUrl },
  );
  CASES.forEach((c, i) => {
    c.run = run(`case-${i}`, c.typed);
    const cited = citedTarget(c.run.stdout);
    if (cited !== null) c.rerun = run(`rerun-${i}`, cited);
  });
}, 600_000);

afterAll(() => {
  serverProc?.kill();
});

describe('check <URL> Next Steps cites a target check accepts', () => {
  for (const [i, kind] of ['a forge URL with no `.git`', 'a URL that ends in `.git`', 'a forge URL with a user name', 'a URL of a single file'].entries()) {
    it(`cites the URL as shown for ${kind}`, () => {
      const c = CASES[i];
      expect(c.kind).toBe(kind);
      expect(c.run!.stderr).not.toContain('Invalid skill identifier');
      expect(c.run!.stdout).toContain('Next Steps');
      expect(citedTarget(c.run!.stdout)).toBe(c.cited);
      expect(c.run!.stdout).not.toContain('fakeuser');
    });

    it(`check runs the cited command for ${kind}`, () => {
      const c = CASES[i];
      expect(c.rerun, 'the first run cited no `check ... --nanomind` command').toBeDefined();
      expect(c.rerun!.stderr).not.toContain('Invalid skill identifier');
      expect(c.rerun!.stdout).toContain('Next Steps');
      expect(citedTarget(c.rerun!.stdout)).toBe(c.cited);
    });
  }
});
