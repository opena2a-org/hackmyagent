import { describe, it, expect, afterEach } from 'vitest';
import { createServer, Server, Socket } from 'node:net';
import { mkdtempSync, rmSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  sendClassify,
  sendHealthz,
  isDaemonHealthy,
  isClassifyOk,
  isDaemonError,
} from '../../src/nanomind-core/inference/nanomind-guard-client';

// ============================================================================
// Mock daemon helpers
// ============================================================================

interface MockDaemon {
  server: Server;
  socketPath: string;
  receivedLines: string[];
  close: () => Promise<void>;
}

type MockHandler = (line: string, conn: Socket) => void;

const tmpDirs: string[] = [];
const activeMockDaemons: MockDaemon[] = [];

async function startMockDaemon(handler: MockHandler): Promise<MockDaemon> {
  const dir = mkdtempSync(join(tmpdir(), 'nanomind-guard-test-'));
  tmpDirs.push(dir);
  const socketPath = join(dir, 'daemon.sock');
  const receivedLines: string[] = [];
  const openConnections = new Set<Socket>();

  const server = createServer({ allowHalfOpen: true }, (conn) => {
    openConnections.add(conn);
    conn.on('close', () => openConnections.delete(conn));
    let buf = '';
    conn.on('data', (chunk: Buffer) => {
      buf += chunk.toString('utf8');
      const nl = buf.indexOf('\n');
      if (nl < 0) return;
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      receivedLines.push(line);
      handler(line, conn);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ path: socketPath }, () => {
      server.off('error', reject);
      resolve();
    });
  });

  const close = (): Promise<void> =>
    new Promise<void>((resolve) => {
      // Destroy any lingering connections first so server.close() can resolve
      // without waiting for the timeout-test connection to drain naturally.
      for (const conn of openConnections) {
        try {
          conn.destroy();
        } catch {
          // ignore
        }
      }
      openConnections.clear();
      server.close(() => resolve());
    });

  const daemon: MockDaemon = { server, socketPath, receivedLines, close };
  activeMockDaemons.push(daemon);
  return daemon;
}

afterEach(async () => {
  while (activeMockDaemons.length > 0) {
    const d = activeMockDaemons.pop()!;
    await d.close();
  }
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop()!;
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
});

// ============================================================================
// Fixtures
// ============================================================================

const bypassResponse = {
  ok: true,
  predictedAttackClass: 'none',
  confidence: null,
  classification: 'benign',
  source: 'input-classifier-gate',
  gateLabel: 'off-topic',
  gateReason: 'lr',
  gateProbaOffTopic: 0.83,
  gateThreshold: 0.65,
  gateLatencyMs: 1.4,
  nlmInvoked: false,
  nlmLatencyMs: null,
  nlmTokenCount: null,
};

const nlmResponse = {
  ok: true,
  predictedAttackClass: 'lateral_movement',
  confidence: 0.95,
  classification: 'malicious',
  severity: 'critical',
  analysis: 'detected agent attempts to traverse network',
  verdict: 'block',
  evidence: 'capability spec includes shell + network',
  remediation: 'remove shell capability or restrict network',
  source: 'nlm',
  gateLabel: 'security-artifact',
  gateReason: 'lr',
  gateProbaOffTopic: 0.12,
  gateThreshold: 0.65,
  gateLatencyMs: 1.6,
  nlmInvoked: true,
  nlmLatencyMs: 287.4,
  nlmTokenCount: 142,
};

const healthzResponse = {
  ok: true,
  daemonState: 'ready' as const,
  gateProbe: {
    input: '# README\n\nProject Setup',
    label: 'off-topic',
    expected: 'off-topic',
    passed: true,
  },
  uptimeSec: 12.7,
  requestsServed: 4,
  modelPath: '/opt/nanomind/nlm-v3',
  classifierPath: '/opt/nanomind/input-classifier-v1',
  classifierThreshold: 0.65,
  embedder: 'sentence-transformers/all-MiniLM-L6-v2',
};

const errorResponse = {
  ok: false,
  error: 'ERR_INPUT_TOO_LARGE',
  message: 'input is 2097152 bytes; max is 1048576',
};

// ============================================================================
// Tests
// ============================================================================

describe('nanomind-guard-client', () => {
  it('returns null when the socket does not exist', async () => {
    const result = await sendClassify('some artifact text', {
      socketPath: '/tmp/nanomind-guard-does-not-exist-' + Date.now() + '.sock',
      timeoutMs: 500,
    });
    expect(result).toBeNull();
  });

  it('returns the parsed bypass response on the gate-bypass path', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(bypassResponse) + '\n');
      conn.end();
    });

    const result = await sendClassify('# README\n\nrecipe for cookies', {
      socketPath: daemon.socketPath,
      timeoutMs: 2_000,
    });

    expect(result).not.toBeNull();
    expect(result && isClassifyOk(result)).toBe(true);
    if (result && isClassifyOk(result)) {
      expect(result.source).toBe('input-classifier-gate');
      expect(result.predictedAttackClass).toBe('none');
      expect(result.confidence).toBeNull();
      expect(result.nlmInvoked).toBe(false);
      expect(result.gateLabel).toBe('off-topic');
    }
    expect(daemon.receivedLines).toHaveLength(1);
    const sent = JSON.parse(daemon.receivedLines[0]);
    expect(sent.op).toBe('classify');
    expect(sent.text).toBe('# README\n\nrecipe for cookies');
  });

  it('returns the parsed NLM response with telemetry fields intact', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmResponse) + '\n');
      conn.end();
    });

    const result = await sendClassify('agent with shell capability', {
      socketPath: daemon.socketPath,
      timeoutMs: 2_000,
    });

    expect(result).not.toBeNull();
    if (result && isClassifyOk(result)) {
      expect(result.source).toBe('nlm');
      expect(result.nlmInvoked).toBe(true);
      expect(result.predictedAttackClass).toBe('lateral_movement');
      expect(result.confidence).toBe(0.95);
      // NLM-path telemetry preserved
      expect(result.nlmLatencyMs).toBe(287.4);
      expect(result.nlmTokenCount).toBe(142);
      // Forwarded NLM body (analysis/verdict/evidence/remediation)
      expect(result.analysis).toBe('detected agent attempts to traverse network');
      expect(result.remediation).toBe('remove shell capability or restrict network');
    } else {
      expect.fail('expected classify-ok response');
    }
  });

  it('returns the parsed error response shape for ERR_INPUT_TOO_LARGE', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(errorResponse) + '\n');
      conn.end();
    });

    const result = await sendClassify('a'.repeat(200_000), {
      socketPath: daemon.socketPath,
      timeoutMs: 2_000,
    });

    expect(result).not.toBeNull();
    expect(result && isDaemonError(result)).toBe(true);
    if (result && isDaemonError(result)) {
      expect(result.error).toBe('ERR_INPUT_TOO_LARGE');
      expect(result.message).toContain('max is');
    }
  });

  it('returns null when the daemon writes malformed JSON', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write('this is not json\n');
      conn.end();
    });
    const result = await sendClassify('input text', {
      socketPath: daemon.socketPath,
      timeoutMs: 2_000,
    });
    expect(result).toBeNull();
  });

  it('returns null when the daemon never responds (timeout)', async () => {
    const daemon = await startMockDaemon((_line, _conn) => {
      // intentionally write nothing and hold the connection
    });
    const start = Date.now();
    const result = await sendClassify('input text', {
      socketPath: daemon.socketPath,
      timeoutMs: 200,
    });
    const elapsed = Date.now() - start;
    expect(result).toBeNull();
    // Sanity: it actually waited for the timeout, didn't error instantly.
    expect(elapsed).toBeGreaterThanOrEqual(150);
    expect(elapsed).toBeLessThan(2_000);
  });

  it('returns null when the daemon closes mid-stream without a newline', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write('{"ok": true, "predictedAtt');
      conn.end();
    });
    const result = await sendClassify('input text', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(result).toBeNull();
  });

  it('returns null when the daemon writes a payload larger than the response cap', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      // 512 KB of `x` followed by a valid JSON-looking suffix, no newline yet.
      // Total > MAX_RESPONSE_BYTES (256 KB).
      conn.write('x'.repeat(512 * 1024) + '\n');
      conn.end();
    });
    const result = await sendClassify('input text', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(result).toBeNull();
  });

  it('guards empty input client-side without contacting the daemon', async () => {
    let received = false;
    const daemon = await startMockDaemon((_line, conn) => {
      received = true;
      conn.write(JSON.stringify(bypassResponse) + '\n');
      conn.end();
    });
    const result1 = await sendClassify('', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    const result2 = await sendClassify('   \t\n  ', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(result1).toBeNull();
    expect(result2).toBeNull();
    expect(received).toBe(false);
    expect(daemon.receivedLines).toHaveLength(0);
  });

  it('returns null for non-object response shapes', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write('42\n');
      conn.end();
    });
    const result = await sendClassify('input', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(result).toBeNull();
  });

  it('sendHealthz returns the parsed healthz response', async () => {
    const daemon = await startMockDaemon((line, conn) => {
      const req = JSON.parse(line);
      expect(req.op).toBe('healthz');
      conn.write(JSON.stringify(healthzResponse) + '\n');
      conn.end();
    });

    const result = await sendHealthz({
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });

    expect(result).not.toBeNull();
    expect(result?.daemonState).toBe('ready');
    expect(result?.gateProbe.passed).toBe(true);
    expect(result?.classifierThreshold).toBe(0.65);
    expect(result?.embedder).toBe('sentence-transformers/all-MiniLM-L6-v2');
  });

  it('isDaemonHealthy returns true when daemon answers ok', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(healthzResponse) + '\n');
      conn.end();
    });
    const healthy = await isDaemonHealthy({
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(healthy).toBe(true);
  });

  it('isDaemonHealthy returns false when daemon reports degraded', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(
        JSON.stringify({
          ...healthzResponse,
          ok: false,
          daemonState: 'degraded',
          gateProbe: { ...healthzResponse.gateProbe, passed: false },
        }) + '\n',
      );
      conn.end();
    });
    const healthy = await isDaemonHealthy({
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(healthy).toBe(false);
  });

  it('isDaemonHealthy returns false when the socket is absent', async () => {
    const healthy = await isDaemonHealthy({
      socketPath: '/tmp/nanomind-guard-not-here-' + Date.now() + '.sock',
      timeoutMs: 200,
    });
    expect(healthy).toBe(false);
  });

  it('refuses to connect when the socket path is a symbolic link', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(bypassResponse) + '\n');
      conn.end();
    });
    const linkDir = mkdtempSync(join(tmpdir(), 'nanomind-guard-link-'));
    tmpDirs.push(linkDir);
    const symlinkPath = join(linkDir, 'evil.sock');
    symlinkSync(daemon.socketPath, symlinkPath);

    const result = await sendClassify('some text', {
      socketPath: symlinkPath,
      timeoutMs: 500,
    });
    expect(result).toBeNull();
    expect(daemon.receivedLines).toHaveLength(0);
  });

  it('rejects daemon responses with confidence outside [0, 1]', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ...bypassResponse,
        confidence: 999.5,
      }) + '\n');
      conn.end();
    });
    const result = await sendClassify('input', {
      socketPath: daemon.socketPath,
      timeoutMs: 500,
    });
    expect(result).toBeNull();
  });

  it('rejects daemon responses with non-finite confidence', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      // JSON cannot represent Infinity, so the daemon would have to send a
      // string. Validator must catch the type mismatch.
      conn.write(JSON.stringify({
        ...bypassResponse,
        confidence: 'Infinity',
      }) + '\n');
      conn.end();
    });
    const result = await sendClassify('input', {
      socketPath: daemon.socketPath,
      timeoutMs: 500,
    });
    expect(result).toBeNull();
  });

  it('truncates an oversized analysis field that fits under the response cap', async () => {
    // 100 KB analysis: over STRING_FIELD_HARD_CAP (64 KB) but under
    // MAX_RESPONSE_BYTES (256 KB). Exercises validator-level truncation
    // without colliding with the response-size cap.
    const big = 'x'.repeat(100_000);
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ...nlmResponse,
        analysis: big,
      }) + '\n');
      conn.end();
    });
    const result = await sendClassify('input', {
      socketPath: daemon.socketPath,
      timeoutMs: 1_000,
    });
    expect(result).not.toBeNull();
    if (result && isClassifyOk(result)) {
      const cap = 64 * 1024;
      expect(String(result.analysis).length).toBeLessThanOrEqual(cap);
    }
  });

  it('drops unknown severity values rather than rejecting the response', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ...nlmResponse,
        severity: '<script>alert(1)</script>',
      }) + '\n');
      conn.end();
    });
    const result = await sendClassify('input', {
      socketPath: daemon.socketPath,
      timeoutMs: 500,
    });
    expect(result).not.toBeNull();
    if (result && isClassifyOk(result)) {
      // Forward-compat scrub: unknown severities are blanked, not the whole response rejected.
      expect(result.severity).toBe('');
    }
  });

  it('does not leak the temp socket file after the test', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(bypassResponse) + '\n');
      conn.end();
    });
    const path = daemon.socketPath;
    expect(existsSync(path)).toBe(true);
    // afterEach removes; nothing to assert here. This test mostly documents
    // the cleanup contract for readers.
  });
});
