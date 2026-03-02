import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  AgentRuntimeProtection,
  EventEngine,
  EnforcementEngine,
  type ARPConfig,
  type ARPEvent,
} from '../../arp';
import { EventCollector } from './event-collector';
import type { LabConfig } from './types';

/**
 * Wraps AgentRuntimeProtection for controlled testing.
 * Creates temp dataDir per test, registers EventCollector,
 * and provides injection + assertion helpers.
 */
export class ArpWrapper {
  private arp: AgentRuntimeProtection;
  private _dataDir: string;
  readonly collector: EventCollector;

  constructor(labConfig?: LabConfig) {
    this._dataDir = labConfig?.dataDir ?? fs.mkdtempSync(path.join(os.tmpdir(), 'arp-lab-'));

    const config: ARPConfig = {
      agentName: 'arp-lab-target',
      agentDescription: 'Test target for ARP security lab',
      declaredCapabilities: ['file read/write', 'HTTP requests'],
      dataDir: this._dataDir,
      monitors: {
        process: {
          enabled: labConfig?.monitors?.process ?? false,
          intervalMs: labConfig?.processIntervalMs,
        },
        network: {
          enabled: labConfig?.monitors?.network ?? false,
          intervalMs: labConfig?.networkIntervalMs,
          allowedHosts: labConfig?.networkAllowedHosts,
        },
        filesystem: {
          enabled: labConfig?.monitors?.filesystem ?? false,
          watchPaths: labConfig?.filesystemWatchPaths,
          allowedPaths: labConfig?.filesystemAllowedPaths,
        },
      },
      rules: labConfig?.rules,
      intelligence: {
        enabled: labConfig?.intelligence?.enabled ?? false,
        budgetUsd: 0,
      },
      interceptors: {
        process: { enabled: labConfig?.interceptors?.process ?? false },
        network: {
          enabled: labConfig?.interceptors?.network ?? false,
          allowedHosts: labConfig?.interceptorNetworkAllowedHosts,
        },
        filesystem: {
          enabled: labConfig?.interceptors?.filesystem ?? false,
          allowedPaths: labConfig?.interceptorFilesystemAllowedPaths,
        },
      },
    };

    this.arp = new AgentRuntimeProtection(config);
    this.collector = new EventCollector();

    // Register event and enforcement collectors
    this.arp.onEvent(this.collector.eventHandler);
    this.arp.onEnforcement(this.collector.enforcementHandler);
  }

  async start(): Promise<void> {
    await this.arp.start();
  }

  async stop(): Promise<void> {
    await this.arp.stop();
    this.collector.reset();
    // Clean up temp dir
    try {
      fs.rmSync(this._dataDir, { recursive: true, force: true });
    } catch {
      // Best effort cleanup
    }
  }

  /** Get the underlying ARP instance */
  getInstance(): AgentRuntimeProtection {
    return this.arp;
  }

  /** Get the event engine for direct event injection */
  getEngine(): EventEngine {
    return this.arp.getEngine();
  }

  /** Get the enforcement engine */
  getEnforcement(): EnforcementEngine {
    return this.arp.getEnforcement();
  }

  /** Inject a synthetic event into the ARP engine (for testing without real OS activity) */
  async injectEvent(event: Omit<ARPEvent, 'id' | 'timestamp' | 'classifiedBy'>): Promise<ARPEvent> {
    return this.getEngine().emit(event);
  }

  /** Wait for an event matching a predicate */
  waitForEvent(
    predicate: (event: ARPEvent) => boolean,
    timeoutMs: number = 10000,
  ): Promise<ARPEvent> {
    return this.collector.waitForEvent(predicate, timeoutMs);
  }

  /** Get the data directory */
  get dataDir(): string {
    return this._dataDir;
  }
}
