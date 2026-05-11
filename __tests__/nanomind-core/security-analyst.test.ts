import { describe, it, expect, afterEach } from 'vitest';
import { createServer, Server, Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  getAnalystStatus,
  isAnalystReady,
  runAnalystInference,
  analyzeThreat,
  assessCredentialContext,
  assessFalsePositive,
} from '../../src/nanomind-core/inference/security-analyst';

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
  const dir = mkdtempSync(join(tmpdir(), 'analyst-test-'));
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
      for (const conn of openConnections) {
        try { conn.destroy(); } catch { /* ignore */ }
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
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  delete process.env.NANOMIND_GUARD_SOCK;
});

// ============================================================================
// Fixtures
// ============================================================================

const healthzOk = {
  ok: true,
  daemonState: 'ready' as const,
  gateProbe: {
    input: '# README\n\nProject Setup',
    label: 'off-topic',
    expected: 'off-topic',
    passed: true,
  },
  uptimeSec: 42.0,
  requestsServed: 17,
  modelPath: '/opt/nanomind/nlm-v3',
  classifierPath: '/opt/nanomind/input-classifier-v1',
  classifierThreshold: 0.65,
  embedder: 'sentence-transformers/all-MiniLM-L6-v2',
};

const nlmMalicious = {
  ok: true,
  predictedAttackClass: 'lateral_movement',
  confidence: 0.95,
  classification: 'malicious',
  severity: 'critical',
  analysis: 'agent capability set includes shell + network egress',
  verdict: 'block this agent',
  evidence: 'capability: shell\ncapability: network',
  remediation: 'remove shell capability\nrestrict network egress to allowlist',
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

const nlmBenignBypass = {
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

// ============================================================================
// Tests
// ============================================================================

describe('security-analyst — getAnalystStatus', () => {
  it('returns daemon body when /healthz answers ok', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(healthzOk) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;

    const status = await getAnalystStatus();
    expect(status.available).toBe(true);
    expect(status.backend).toBe('daemon');
    expect(status.modelCached).toBe(true);
    expect(status.daemon).not.toBeNull();
    expect(status.daemon?.classifierThreshold).toBe(0.65);
    expect(status.daemon?.uptimeSec).toBe(42.0);
    expect(status.setupCommand).toBe('hackmyagent nanomind setup');
  });

  it('returns backend=none with daemon=null when socket is absent', async () => {
    process.env.NANOMIND_GUARD_SOCK = '/tmp/nanomind-guard-absent-' + Date.now() + '.sock';
    const status = await getAnalystStatus();
    expect(status.available).toBe(false);
    expect(status.backend).toBe('none');
    expect(status.modelCached).toBe(false);
    expect(status.daemon).toBeNull();
    expect(status.setupCommand).toBe('hackmyagent nanomind setup');
  });

  it('isAnalystReady returns false when the daemon is absent', async () => {
    process.env.NANOMIND_GUARD_SOCK = '/tmp/nanomind-guard-absent-' + Date.now() + '.sock';
    const ready = await isAnalystReady();
    expect(ready).toBe(false);
  });
});

describe('security-analyst — analyzeThreat', () => {
  it('maps the daemon universal shape to the ThreatAnalysis contract', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;

    const result = await analyzeThreat(
      'agent_spec:\n  capabilities: [shell, network]\n',
      'lateral_movement',
    );

    expect(result).not.toBeNull();
    expect(result?.threatLevel).toBe('critical');
    expect(result?.attackVector).toBe('lateral_movement');
    expect(result?.description).toContain('shell + network egress');
    expect(result?.mitigations).toEqual([
      'remove shell capability',
      'restrict network egress to allowlist',
    ]);
    expect(result?.confidence).toBe(0.95);
  });

  it('returns null when the daemon is absent', async () => {
    process.env.NANOMIND_GUARD_SOCK = '/tmp/nanomind-guard-absent-' + Date.now() + '.sock';
    const result = await analyzeThreat('some content', 'credential_abuse');
    expect(result).toBeNull();
  });

  it('returns null when the daemon returns an ERR_BAD_REQUEST', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ok: false,
        error: 'ERR_BAD_REQUEST',
        message: 'missing text',
      }) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await analyzeThreat('content', 'lateral_movement');
    expect(result).toBeNull();
  });

  it('falls back to the caller-provided attackClass when daemon predicts none', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ...nlmMalicious,
        predictedAttackClass: 'none',
        classification: 'benign',
      }) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await analyzeThreat('content', 'credential_abuse');
    expect(result?.attackVector).toBe('credential_abuse');
  });
});

describe('security-analyst — assessCredentialContext', () => {
  it('returns classification "test" for daemon-benign responses', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmBenignBypass) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await assessCredentialContext('API_KEY=test-placeholder');
    expect(result?.classification).toBe('test');
    expect(result?.confidence).toBe(0.5);
  });

  it('returns classification "real" for daemon-malicious responses', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify({
        ...nlmMalicious,
        predictedAttackClass: 'credential_abuse',
      }) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await assessCredentialContext('API_KEY=sk-real-prod-key');
    expect(result?.classification).toBe('real');
    expect(result?.reasoning).toContain('shell + network');
  });
});

describe('security-analyst — assessFalsePositive', () => {
  it('returns isFalsePositive=true when daemon classifies benign', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmBenignBypass) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await assessFalsePositive('content', 'JWT validator detected');
    expect(result?.isFalsePositive).toBe(true);
  });

  it('returns isFalsePositive=false when daemon classifies malicious', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await assessFalsePositive('content', 'shell capability detected');
    expect(result?.isFalsePositive).toBe(false);
  });
});

describe('security-analyst — runAnalystInference shape adapters', () => {
  it('intelReport result carries summary/keyFindings/riskAssessment/recommendations', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const response = await runAnalystInference({
      taskType: 'intelReport',
      content: 'summary of scan findings',
    });
    expect(response).not.toBeNull();
    const r = response!.result;
    expect(r.summary).toContain('shell + network');
    expect(Array.isArray(r.keyFindings)).toBe(true);
    expect((r.keyFindings as string[]).length).toBe(2);
    expect(r.riskAssessment).toBe('block this agent');
    expect(Array.isArray(r.recommendations)).toBe(true);
  });

  it('governanceReasoning result carries gaps and recommendations', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const response = await runAnalystInference({
      taskType: 'governanceReasoning',
      content: 'agent governance spec',
    });
    expect(response).not.toBeNull();
    const r = response!.result;
    expect(Array.isArray(r.gaps)).toBe(true);
    expect((r.gaps as string[]).length).toBe(2);
    expect(Array.isArray(r.recommendations)).toBe(true);
  });

  it('checkExplanation result carries explanation/impact/recommendation', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const response = await runAnalystInference({
      taskType: 'checkExplanation',
      content: 'check fired on this artifact',
    });
    expect(response).not.toBeNull();
    const r = response!.result;
    expect(r.explanation).toContain('shell + network');
    expect(r.impact).toBe('block this agent');
    expect(r.recommendation).toContain('remove shell capability');
  });

  it('truncates input to MAX_INPUT_CHARS and prepends context when provided', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmBenignBypass) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const longContent = 'a'.repeat(8000);
    await runAnalystInference({
      taskType: 'threatAnalysis',
      content: longContent,
      context: 'Context: malicious agent',
    });
    expect(daemon.receivedLines).toHaveLength(1);
    const sent = JSON.parse(daemon.receivedLines[0]);
    expect(sent.text.startsWith('Context: malicious agent\n\n')).toBe(true);
    // Header (24 chars) + 2 newlines + 4096 truncated content = 4122
    expect(sent.text.length).toBe('Context: malicious agent'.length + 2 + 4096);
  });

  it('strips ANSI / OSC / C0 control sequences from daemon-controlled string fields', async () => {
    // Hostile daemon attempts to: rewrite terminal title via OSC, clear the
    // screen via CSI, inject a hyperlink via OSC 8, hide content via C0 BEL.
    const hostile = {
      ...nlmMalicious,
      analysis: 'before\x1b]2;PWNED\x07after\x1b[2J\x1b[Hcleared',
      verdict: 'pre\x1b[31mRED\x1b[0mpost',
      evidence: 'line\x07ok\nline2\x1b]8;;http://evil.example/\x07click\x1b]8;;\x07',
      remediation: 'do\x1bAfix\x9b9999D',
      severity: 'high',
      predictedAttackClass: 'lateral_movement',
      classification: 'malicious',
    };
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(hostile) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await runAnalystInference({
      taskType: 'threatAnalysis',
      content: 'agent spec',
    });
    expect(result).not.toBeNull();
    const r = result!.result;
    const desc = String(r.description);
    // No ESC, BEL, or C1 controls
    expect(/\x1b/.test(desc)).toBe(false);
    expect(/\x07/.test(desc)).toBe(false);
    expect(/[\x80-\x9f]/.test(desc)).toBe(false);
    // Visible content preserved
    expect(desc).toContain('before');
    expect(desc).toContain('after');
    expect(desc).toContain('cleared');
  });

  it('exposes the daemon source field on the AnalystResponse for renderer use', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmBenignBypass) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const result = await runAnalystInference({
      taskType: 'falsePositiveDetection',
      content: 'some content',
    });
    expect(result?.source).toBe('input-classifier-gate');
  });

  it('reports backend=daemon and the v3 model version in the response', async () => {
    const daemon = await startMockDaemon((_line, conn) => {
      conn.write(JSON.stringify(nlmMalicious) + '\n');
      conn.end();
    });
    process.env.NANOMIND_GUARD_SOCK = daemon.socketPath;
    const response = await runAnalystInference({
      taskType: 'threatAnalysis',
      content: 'agent spec',
    });
    expect(response?.backend).toBe('daemon');
    expect(response?.modelVersion).toBe('nanomind-analyst-v3.0.0');
    expect(typeof response?.durationMs).toBe('number');
  });
});
