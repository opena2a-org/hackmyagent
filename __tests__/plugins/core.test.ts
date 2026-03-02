import { describe, it, expect, beforeEach } from 'vitest';
import {
  registerPlugin,
  getPlugin,
  listPlugins,
  clearRegistry,
} from '../../src/plugins/core';
import type { OpenA2APlugin, PluginMetadata, PluginStatus, Finding, Remediation } from '../../src/plugins/core';

const mockMetadata: PluginMetadata = {
  packageName: '@opena2a/test-plugin',
  displayName: 'Test Plugin',
  description: 'A test plugin',
  version: '0.1.0',
  findings: ['TEST-001', 'TEST-002'],
  scoreImprovement: 10,
};

class MockPlugin implements OpenA2APlugin {
  readonly metadata = mockMetadata;
  async init(): Promise<void> {}
  async scan(): Promise<Finding[]> { return []; }
  async fix(): Promise<Remediation[]> { return []; }
  async status(): Promise<PluginStatus> {
    return { name: 'Test', version: '0.1.0', active: false, findingsCount: 0 };
  }
}

describe('plugin registry', () => {
  beforeEach(() => {
    clearRegistry();
  });

  it('registers and retrieves a plugin', () => {
    registerPlugin({
      metadata: mockMetadata,
      create: () => new MockPlugin(),
    });

    const entry = getPlugin('@opena2a/test-plugin');
    expect(entry).toBeDefined();
    expect(entry!.metadata.displayName).toBe('Test Plugin');
  });

  it('creates a plugin instance from registry', () => {
    registerPlugin({
      metadata: mockMetadata,
      create: () => new MockPlugin(),
    });

    const entry = getPlugin('@opena2a/test-plugin');
    const plugin = entry!.create();
    expect(plugin.metadata.packageName).toBe('@opena2a/test-plugin');
  });

  it('returns undefined for unknown plugin', () => {
    expect(getPlugin('@opena2a/nonexistent')).toBeUndefined();
  });

  it('lists all registered plugins', () => {
    registerPlugin({ metadata: mockMetadata, create: () => new MockPlugin() });
    registerPlugin({
      metadata: { ...mockMetadata, packageName: '@opena2a/other', displayName: 'Other' },
      create: () => new MockPlugin(),
    });

    const all = listPlugins();
    expect(all.length).toBe(2);
  });

  it('clears the registry', () => {
    registerPlugin({ metadata: mockMetadata, create: () => new MockPlugin() });
    expect(listPlugins().length).toBe(1);

    clearRegistry();
    expect(listPlugins().length).toBe(0);
  });

  it('throws on duplicate registration', () => {
    registerPlugin({ metadata: mockMetadata, create: () => new MockPlugin() });
    expect(() =>
      registerPlugin({
        metadata: { ...mockMetadata, displayName: 'Updated' },
        create: () => new MockPlugin(),
      })
    ).toThrow(/already registered/);
    expect(listPlugins().length).toBe(1);
  });
});
