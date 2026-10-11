// Usage telemetry is off under CI and test runners unless asked for (#963).
//
// Each CI job and each spawn test starts from a fresh home directory, so each
// run registered as a new install: 197 of 219 monthly install ids were active
// on one day only. These cells hold the decision as a function; the spawn-level
// claim is in __tests__/harness/suite-sends-no-telemetry.test.ts.
import { describe, it, expect } from 'vitest';
import {
  automationMarker,
  automationOptOut,
  initWithAutomationOptOut,
  telemetryExplicitlyOn,
  CI_MARKERS,
  TEST_RUNNER_MARKERS,
} from '../../src/telemetry/automation';

const DISCARD = 'http://127.0.0.1:9';

describe('automationMarker (#963)', () => {
  it('names no marker for an interactive shell', () => {
    expect(automationMarker({ PATH: '/usr/bin', HOME: '/home/u', TERM: 'xterm' })).toBeUndefined();
  });

  it.each([...CI_MARKERS, ...TEST_RUNNER_MARKERS])('names %s when it is set', (name) => {
    expect(automationMarker({ [name]: 'true' })).toBe(name);
  });

  it('reads the values CI services set, not only "true"', () => {
    expect(automationMarker({ CI: '1' })).toBe('CI');
    expect(automationMarker({ JEST_WORKER_ID: '3' })).toBe('JEST_WORKER_ID');
    expect(automationMarker({ JENKINS_URL: 'https://ci.example.test/' })).toBe('JENKINS_URL');
    expect(automationMarker({ NODE_TEST_CONTEXT: 'child-v8' })).toBe('NODE_TEST_CONTEXT');
  });

  it('does not read CI=false, CI=0 or an empty CI as CI', () => {
    expect(automationMarker({ CI: 'false' })).toBeUndefined();
    expect(automationMarker({ CI: 'FALSE' })).toBeUndefined();
    expect(automationMarker({ CI: '0' })).toBeUndefined();
    expect(automationMarker({ CI: '' })).toBeUndefined();
    expect(automationMarker({ CI: '  ' })).toBeUndefined();
  });

  it('names NODE_ENV only when it is test', () => {
    expect(automationMarker({ NODE_ENV: 'test' })).toBe('NODE_ENV');
    expect(automationMarker({ NODE_ENV: 'production' })).toBeUndefined();
    expect(automationMarker({ NODE_ENV: 'development' })).toBeUndefined();
  });
});

describe('automationOptOut (#963)', () => {
  it('keeps telemetry off under a marker when OPENA2A_TELEMETRY is unset or empty', () => {
    expect(automationOptOut({ CI: 'true' })).toBe('CI');
    expect(automationOptOut({ VITEST: 'true', OPENA2A_TELEMETRY: '' })).toBe('VITEST');
  });

  it.each(['on', 'ON', '1', 'true', 'yes', ' on '])('lets OPENA2A_TELEMETRY=%j turn it back on', (value) => {
    expect(telemetryExplicitlyOn({ OPENA2A_TELEMETRY: value })).toBe(true);
    expect(automationOptOut({ CI: 'true', OPENA2A_TELEMETRY: value })).toBeUndefined();
  });

  it('does not read an off value or an unknown value as turning it on', () => {
    for (const value of ['off', '0', 'false', 'no', 'enabled', 'maybe']) {
      expect(telemetryExplicitlyOn({ OPENA2A_TELEMETRY: value }), value).toBe(false);
      expect(automationOptOut({ GITHUB_ACTIONS: 'true', OPENA2A_TELEMETRY: value }), value).toBe('GITHUB_ACTIONS');
    }
  });

  it('changes nothing outside automation', () => {
    expect(automationOptOut({})).toBeUndefined();
    // Every object in the suite that turns telemetry on also pins the endpoint
    // to loopback (__tests__/harness/suite-sends-no-telemetry.test.ts).
    expect(automationOptOut({ OPENA2A_TELEMETRY: 'on', OPENA2A_TELEMETRY_URL: DISCARD })).toBeUndefined();
  });
});

describe('initWithAutomationOptOut (#963)', () => {
  /** An `init` that records what the SDK would have read. */
  function recordingInit(env: NodeJS.ProcessEnv): { init: () => Promise<void>; seen: () => string | undefined } {
    let seen: string | undefined = 'not called';
    return {
      init: async () => { seen = env.OPENA2A_TELEMETRY; },
      seen: () => seen,
    };
  }

  it('runs init with OPENA2A_TELEMETRY=off under a marker, then removes it again', async () => {
    const env: NodeJS.ProcessEnv = { CI: 'true' };
    const r = recordingInit(env);
    await initWithAutomationOptOut(r.init, env);
    expect(r.seen()).toBe('off');
    expect('OPENA2A_TELEMETRY' in env).toBe(false);
  });

  it('puts back an empty value it replaced', async () => {
    const env: NodeJS.ProcessEnv = { VITEST: 'true', OPENA2A_TELEMETRY: '' };
    const r = recordingInit(env);
    await initWithAutomationOptOut(r.init, env);
    expect(r.seen()).toBe('off');
    expect(env.OPENA2A_TELEMETRY).toBe('');
  });

  it('restores the variable when init throws', async () => {
    const env: NodeJS.ProcessEnv = { CI: 'true' };
    await expect(initWithAutomationOptOut(async () => { throw new Error('boom'); }, env)).rejects.toThrow('boom');
    expect('OPENA2A_TELEMETRY' in env).toBe(false);
  });

  it('leaves the environment alone outside automation and on an explicit opt-in', async () => {
    const plain: NodeJS.ProcessEnv = {};
    const a = recordingInit(plain);
    await initWithAutomationOptOut(a.init, plain);
    expect(a.seen()).toBeUndefined();

    const optedIn: NodeJS.ProcessEnv = { CI: 'true', OPENA2A_TELEMETRY: 'on', OPENA2A_TELEMETRY_URL: DISCARD };
    const b = recordingInit(optedIn);
    await initWithAutomationOptOut(b.init, optedIn);
    expect(b.seen()).toBe('on');
    expect(optedIn.OPENA2A_TELEMETRY).toBe('on');
  });
});
