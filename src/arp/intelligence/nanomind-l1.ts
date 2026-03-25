/**
 * NanoMind L1 — Behavioral Anomaly Detection Layer
 *
 * Integrates NanoMind-Runtime into ARP's event pipeline.
 * Processes every L0 event through the behavioral twin for anomaly scoring.
 *
 * Three-tier ARP model:
 *   L0: Rule-based (EventEngine) — microseconds, always runs
 *   L1: NanoMind-Runtime behavioral twin — milliseconds, this module
 *   L2: Claude/LLM intelligence — seconds, existing IntelligenceCoordinator
 *
 * L1 runs in parallel with L0 — never blocks the L0 decision.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { ARPEvent, ARPConfig, EnforcementAction } from '../types';
import type { EventEngine } from '../engine/event-engine';

// === Types (mirroring @nanomind/runtime) ===

type EventType =
  | 'TOOL_CALL'
  | 'CAPABILITY_CHECK'
  | 'MCP_CALL'
  | 'MEMORY_READ'
  | 'MEMORY_WRITE'
  | 'EXTERNAL_CALL';

type ARPAction = 'allow' | 'alert' | 'throttle' | 'suspend' | 'kill';

interface BehavioralEvent {
  agentId: string;
  sessionId: string;
  sequenceNum: number;
  eventType: EventType;
  capability: string;
  toolName: string | null;
  argHash: string;
  timestampDelta: number;
  wallClock: number;
  responseSize: number;
  responseCode: number;
  l0Decision: 'allow' | 'block' | 'alert';
}

interface BaselineStats {
  eventTypeCounts: Record<string, number>;
  avgTimingDelta: number;
  stdTimingDelta: number;
  capabilitySet: Set<string>;
  avgResponseSize: number;
  totalEvents: number;
  errorRate: number;
}

interface AnomalyResult {
  score: number;
  action: ARPAction;
  reason: string;
}

// Response thresholds
const RESPONSE_TABLE: Array<{ threshold: number; action: ARPAction; label: string }> = [
  { threshold: 0.2, action: 'allow', label: 'Normal behavior' },
  { threshold: 0.4, action: 'alert', label: 'Unusual pattern detected' },
  { threshold: 0.6, action: 'throttle', label: 'Suspicious behavior — rate limited' },
  { threshold: 0.8, action: 'suspend', label: 'High anomaly — agent suspended' },
  { threshold: 1.0, action: 'kill', label: 'Critical anomaly — agent terminated' },
];

// === L1 Anomaly Detector ===

export class NanoMindL1 {
  private agentId: string;
  private sessionId: string;
  private baseline: BaselineStats | null = null;
  private eventBuffer: BehavioralEvent[] = [];
  private sequenceNum = 0;
  private lastEventTime = Date.now();
  private eventLogPath: string;
  private enabled: boolean;

  constructor(agentId: string, config?: { enabled?: boolean }) {
    this.agentId = agentId;
    this.sessionId = crypto.randomUUID();
    this.enabled = config?.enabled ?? true;
    this.eventLogPath = path.join(os.homedir(), '.opena2a', 'arp', 'events.jsonl');

    // Load baseline if exists
    this.loadBaseline();
  }

  /**
   * Attach to an ARP EventEngine — processes every event for anomaly detection.
   * Non-blocking: L1 runs in parallel, L0 decision is returned immediately.
   */
  attach(engine: EventEngine): void {
    if (!this.enabled) return;

    engine.onEvent((event: ARPEvent) => {
      // Convert ARP event to behavioral event
      const behavioral = this.convertEvent(event);
      if (!behavioral) return;

      // Process asynchronously — never block L0
      setImmediate(() => {
        const result = this.processEvent(behavioral);

        // If L1 detects high anomaly, escalate
        if (result.score > 0.4) {
          // Log escalation
          this.logEscalation(event, result);
        }
      });
    });
  }

  /**
   * Process a behavioral event and return anomaly score.
   */
  processEvent(event: BehavioralEvent): AnomalyResult {
    this.eventBuffer.push(event);
    this.appendToLog(event);

    if (this.eventBuffer.length > 1000) {
      this.eventBuffer = this.eventBuffer.slice(-500);
    }

    const score = this.computeAnomalyScore(event);
    const response = this.getResponse(score);

    return {
      score,
      action: response.action,
      reason: response.label,
    };
  }

  /**
   * Convert an ARP event to a NanoMind behavioral event.
   */
  private convertEvent(event: ARPEvent): BehavioralEvent | null {
    const now = Date.now();
    const delta = now - this.lastEventTime;
    this.lastEventTime = now;
    this.sequenceNum++;

    // Map ARP event category to behavioral event type
    let eventType: EventType = 'TOOL_CALL';
    const source = String(event.data?.source || event.data?.monitor || '');
    if (source.includes('network')) eventType = 'EXTERNAL_CALL';
    else if (source.includes('filesystem')) eventType = 'MEMORY_READ';
    else if (source.includes('mcp')) eventType = 'MCP_CALL';
    else if (source.includes('capability')) eventType = 'CAPABILITY_CHECK';

    // Map L0 decision
    let l0Decision: 'allow' | 'block' | 'alert' = 'allow';
    if (event.data?._pendingAction === 'block') l0Decision = 'block';
    else if (event.category === 'threat' || event.category === 'violation') l0Decision = 'alert';
    else if (event.severity === 'high' || event.severity === 'critical') l0Decision = 'alert';

    const capability = String(event.data?.capability || event.data?.type || 'unknown');
    const toolName = event.data?.toolName ? String(event.data.toolName) : null;
    const responseSize = typeof event.data?.responseSize === 'number' ? event.data.responseSize : 0;

    return {
      agentId: this.agentId,
      sessionId: this.sessionId,
      sequenceNum: this.sequenceNum,
      eventType,
      capability,
      toolName,
      argHash: crypto.createHash('sha256').update(JSON.stringify(event.data || {})).digest('hex').substring(0, 16),
      timestampDelta: delta,
      wallClock: now,
      responseSize,
      responseCode: event.data?.error ? 1 : 0,
      l0Decision,
    };
  }

  /**
   * Compute anomaly score (same algorithm as @nanomind/runtime).
   */
  private computeAnomalyScore(event: BehavioralEvent): number {
    if (!this.baseline || this.baseline.totalEvents < 100) {
      this.updateBaseline(event);
      return 0.0;
    }

    let score = 0.0;

    // Unknown capability
    if (!this.baseline.capabilitySet.has(event.capability)) score += 0.3;

    // Timing anomaly
    if (this.baseline.stdTimingDelta > 0) {
      const z = Math.abs(event.timestampDelta - this.baseline.avgTimingDelta) / this.baseline.stdTimingDelta;
      if (z > 3) score += 0.2;
      if (z > 5) score += 0.2;
    }

    // Rare event type
    const typeRatio = (this.baseline.eventTypeCounts[event.eventType] || 0) / this.baseline.totalEvents;
    if (typeRatio < 0.01) score += 0.15;

    // L0 flagged
    if (event.l0Decision === 'block') score += 0.3;
    if (event.l0Decision === 'alert') score += 0.15;

    // Burst
    const recent = this.eventBuffer.slice(-10);
    const avgDelta = recent.reduce((s, e) => s + e.timestampDelta, 0) / recent.length;
    if (avgDelta < 10 && recent.length >= 10) score += 0.2;

    // Error spike
    if (recent.filter(e => e.responseCode > 0).length > 5) score += 0.15;

    return Math.min(score, 1.0);
  }

  private updateBaseline(event: BehavioralEvent): void {
    if (!this.baseline) {
      this.baseline = {
        eventTypeCounts: {},
        avgTimingDelta: 0,
        stdTimingDelta: 0,
        capabilitySet: new Set(),
        avgResponseSize: 0,
        totalEvents: 0,
        errorRate: 0,
      };
    }
    const b = this.baseline;
    b.totalEvents++;
    b.eventTypeCounts[event.eventType] = (b.eventTypeCounts[event.eventType] || 0) + 1;
    b.capabilitySet.add(event.capability);

    const n = b.totalEvents;
    const oldAvg = b.avgTimingDelta;
    b.avgTimingDelta = oldAvg + (event.timestampDelta - oldAvg) / n;
    const diff = event.timestampDelta - b.avgTimingDelta;
    b.stdTimingDelta = Math.sqrt(
      (b.stdTimingDelta ** 2 * (n - 1) + (event.timestampDelta - oldAvg) * diff) / n
    );
  }

  private getResponse(score: number): { action: ARPAction; label: string } {
    for (const entry of RESPONSE_TABLE) {
      if (score <= entry.threshold) return entry;
    }
    return { action: 'kill', label: 'Critical anomaly' };
  }

  private loadBaseline(): void {
    const bp = path.join(os.homedir(), '.opena2a', 'arp', `baseline-${this.agentId}.json`);
    try {
      if (fs.existsSync(bp)) {
        const data = JSON.parse(fs.readFileSync(bp, 'utf-8'));
        data.capabilitySet = new Set(data.capabilitySet || []);
        this.baseline = data;
      }
    } catch {}
  }

  private appendToLog(event: BehavioralEvent): void {
    try {
      const dir = path.dirname(this.eventLogPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.appendFileSync(this.eventLogPath, JSON.stringify(event) + '\n');
    } catch {}
  }

  private logEscalation(original: ARPEvent, result: AnomalyResult): void {
    try {
      const logDir = path.join(os.homedir(), '.opena2a', 'arp');
      if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
      fs.appendFileSync(
        path.join(logDir, 'l1-escalations.jsonl'),
        JSON.stringify({
          timestamp: new Date().toISOString(),
          agentId: this.agentId,
          eventId: original.id,
          score: result.score,
          action: result.action,
          reason: result.reason,
          category: original.category,
        }) + '\n'
      );
    } catch {}
  }
}
