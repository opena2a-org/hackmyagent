export const VERSION = '0.2.0';

// Re-export types
export type {
  ARPConfig,
  ARPEvent,
  MonitorType,
  EventCategory,
  EventSeverity,
  LLMAdapter,
  LLMAdapterType,
  LLMAssessment,
  LLMResponse,
  IntelligenceConfig,
  BudgetState,
  AlertRule,
  AlertCondition,
  MonitorConfig,
  InterceptorConfig,
  AILayerConfig,
  ProxyConfig,
  ProxyUpstream,
  EnforcementAction,
  EnforcementResult,
  Monitor,
} from './types';

// Re-export components
export { EventEngine } from './engine/event-engine';
export { IntelligenceCoordinator } from './intelligence/coordinator';
export { BudgetController } from './intelligence/budget';
export { AnomalyDetector } from './intelligence/anomaly';
export { AnthropicAdapter, OpenAIAdapter, OllamaAdapter, createAdapter, autoDetectAdapter } from './intelligence/adapters';
export { ProcessMonitor } from './monitors/process';
export { NetworkMonitor } from './monitors/network';
export { FilesystemMonitor } from './monitors/filesystem';
export { ProcessInterceptor } from './interceptors/process';
export { NetworkInterceptor } from './interceptors/network';
export { FilesystemInterceptor } from './interceptors/filesystem';
export { PromptInterceptor } from './interceptors/prompt';
export { MCPProtocolInterceptor } from './interceptors/mcp-protocol';
export { A2AProtocolInterceptor } from './interceptors/a2a-protocol';
export { EnforcementEngine, type AlertCallback } from './enforcement/kill-switch';
export { LocalLogger } from './reporting/local-log';
export { loadConfig, defaultConfig } from './config/loader';
export { scanText, PATTERN_SETS, ALL_PATTERNS, type ThreatPattern, type ScanResult } from './patterns/ai-threats';
export { ARPProxy, type ARPProxyDeps } from './proxy/server';
export {
  checkLicense,
  hasFeature,
  registerLicenseValidator,
  PREMIUM_FEATURES,
  type LicenseTier,
  type LicenseInfo,
} from './license';

import * as path from 'path';
import type { ARPConfig, ARPEvent, Monitor } from './types';
import { EventEngine } from './engine/event-engine';
import { IntelligenceCoordinator } from './intelligence/coordinator';
import { EnforcementEngine, type AlertCallback } from './enforcement/kill-switch';
import { LocalLogger } from './reporting/local-log';
import { ProcessMonitor } from './monitors/process';
import { NetworkMonitor } from './monitors/network';
import { FilesystemMonitor } from './monitors/filesystem';
import { ProcessInterceptor } from './interceptors/process';
import { NetworkInterceptor } from './interceptors/network';
import { FilesystemInterceptor } from './interceptors/filesystem';
import { PromptInterceptor } from './interceptors/prompt';
import { MCPProtocolInterceptor } from './interceptors/mcp-protocol';
import { A2AProtocolInterceptor } from './interceptors/a2a-protocol';
import { loadConfig } from './config/loader';

/**
 * Agent Runtime Protection — the main entry point.
 *
 * Provides 3-layer intelligent monitoring for AI agents:
 * - L0: Rule-based event classification (free, every event)
 * - L1: Statistical anomaly detection (free, flagged events)
 * - L2: LLM-assisted assessment (micro-prompts, budget-controlled)
 *
 * Usage:
 *   const arp = new AgentRuntimeProtection({ agentName: 'my-agent' });
 *   await arp.start();
 *   // ... agent runs ...
 *   await arp.stop();
 */
export class AgentRuntimeProtection {
  private readonly config: ARPConfig;
  private readonly engine: EventEngine;
  private readonly intelligence: IntelligenceCoordinator;
  private readonly enforcement: EnforcementEngine;
  private readonly logger: LocalLogger;
  private readonly monitors: Monitor[] = [];
  private running = false;

  constructor(configOrPath?: ARPConfig | string) {
    if (typeof configOrPath === 'string') {
      this.config = loadConfig(configOrPath);
    } else {
      this.config = configOrPath ?? loadConfig();
    }

    const dataDir = this.config.dataDir ?? path.join(process.cwd(), '.opena2a', 'arp');

    this.engine = new EventEngine(this.config);
    this.intelligence = new IntelligenceCoordinator(this.config, dataDir);
    this.enforcement = new EnforcementEngine();
    this.logger = new LocalLogger(dataDir);

    // Wire up: events → intelligence → logger
    this.engine.onEvent(async (event) => {
      await this.intelligence.analyze(event);
      this.logger.logEvent(event);
    });

    // Wire up: enforcement → logger
    this.engine.onEnforcement(async (result) => {
      const enforced = await this.enforcement.execute(result.action, result.event);
      this.logger.logEnforcement(enforced);
    });

    // Create monitors based on config
    const mc = this.config.monitors;
    if (mc?.process?.enabled !== false) {
      this.monitors.push(new ProcessMonitor(this.engine, mc?.process?.intervalMs));
    }
    if (mc?.network?.enabled !== false) {
      this.monitors.push(new NetworkMonitor(this.engine, mc?.network?.intervalMs, mc?.network?.allowedHosts));
    }
    if (mc?.filesystem?.enabled !== false) {
      this.monitors.push(new FilesystemMonitor(this.engine, mc?.filesystem?.watchPaths, mc?.filesystem?.allowedPaths));
    }

    // Create interceptors (application-level hooks — zero latency, 100% accuracy)
    const ic = this.config.interceptors;
    if (ic?.process?.enabled) {
      this.monitors.push(new ProcessInterceptor(this.engine));
    }
    if (ic?.network?.enabled) {
      this.monitors.push(new NetworkInterceptor(this.engine, ic.network.allowedHosts));
    }
    if (ic?.filesystem?.enabled) {
      this.monitors.push(new FilesystemInterceptor(this.engine, ic.filesystem.allowedPaths, [dataDir]));
    }

    // Create AI-layer interceptors
    const al = this.config.aiLayer;
    if (al?.prompt?.enabled) {
      this.monitors.push(new PromptInterceptor(this.engine));
    }
    if (al?.mcp?.enabled) {
      this.monitors.push(new MCPProtocolInterceptor(this.engine, al.mcp.allowedTools));
    }
    if (al?.a2a?.enabled) {
      this.monitors.push(new A2AProtocolInterceptor(this.engine, al.a2a.trustedAgents));
    }
  }

  /** Start all monitors */
  async start(): Promise<void> {
    if (this.running) return;

    for (const monitor of this.monitors) {
      await monitor.start();
    }

    this.running = true;
  }

  /** Stop all monitors and flush logs */
  async stop(): Promise<void> {
    if (!this.running) return;

    for (const monitor of this.monitors) {
      await monitor.stop();
    }

    await this.intelligence.stop();
    this.running = false;
  }

  /** Check if ARP is running */
  isRunning(): boolean {
    return this.running;
  }

  /** Get current status */
  getStatus(): {
    running: boolean;
    monitors: Array<{ type: string; running: boolean }>;
    budget: ReturnType<IntelligenceCoordinator['getBudgetStatus']>;
    pausedPids: number[];
  } {
    return {
      running: this.running,
      monitors: this.monitors.map((m) => ({ type: m.type, running: m.isRunning() })),
      budget: this.intelligence.getBudgetStatus(),
      pausedPids: this.enforcement.getPausedPids(),
    };
  }

  /** Get recent events */
  getEvents(limit?: number): ARPEvent[] {
    return this.logger.readEvents(limit);
  }

  /** Resume a paused process */
  resume(pid: number): boolean {
    return this.enforcement.resume(pid);
  }

  /** Subscribe to all ARP events (for external integrations, test harnesses, etc.) */
  onEvent(handler: (event: ARPEvent) => void | Promise<void>): void {
    this.engine.onEvent(handler);
  }

  /** Subscribe to all enforcement results */
  onEnforcement(handler: (result: import('./types').EnforcementResult) => void | Promise<void>): void {
    this.engine.onEnforcement(handler);
  }

  /** Set the alert callback for the enforcement engine */
  setAlertCallback(callback: AlertCallback): void {
    this.enforcement.setAlertCallback(callback);
  }

  /** Get the event engine (for custom integrations) */
  getEngine(): EventEngine {
    return this.engine;
  }

  /** Get the enforcement engine (for test harnesses) */
  getEnforcement(): EnforcementEngine {
    return this.enforcement;
  }
}
