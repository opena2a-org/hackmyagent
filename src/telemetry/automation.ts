/**
 * Usage telemetry is off under CI and test runners unless asked for (#963).
 *
 * Telemetry is on by default, and a CI job, a test suite and a review harness
 * each sent a usage event per run, as an interactive user does. Measured on the
 * first-party aggregates (2026-10-11): 197 of 219 monthly install ids were
 * active on one day only, and the "top version" was the one a review harness
 * pins rather than one users run.
 *
 * A fresh home directory is not what makes a new install id (#999). The
 * pinned `@opena2a/telemetry` derives the id from a hash of the machine
 * identifier (of the hostname where none can be read) and stores it under the
 * home directory, so a spawn with an empty HOME re-derives the same id as
 * every other run on that machine. A job on another machine, or in a container
 * with no machine identifier and its own hostname, gets an id of its own.
 *
 * So a run that carries a CI or test-runner marker sends no usage event, unless
 * `OPENA2A_TELEMETRY` explicitly turns telemetry on for that run. The persisted
 * `telemetry on|off` choice is not consulted for the opt-in: the default and an
 * explicit `on` look the same in the config file.
 *
 * Lives outside `src/cli.ts` so it can be tested as a function (see the note
 * at the top of command-success.ts).
 */

/**
 * Variables CI services set on every job. `CI`, `CONTINUOUS_INTEGRATION`,
 * `BUILD_NUMBER` and `RUN_ID` are the generic markers; the rest name one
 * service each, for jobs that do not set `CI`.
 */
export const CI_MARKERS: readonly string[] = [
  'CI',
  'CONTINUOUS_INTEGRATION',
  'BUILD_NUMBER',
  'RUN_ID',
  'GITHUB_ACTIONS',
  'GITLAB_CI',
  'BUILDKITE',
  'CIRCLECI',
  'TRAVIS',
  'TF_BUILD',
  'JENKINS_URL',
  'TEAMCITY_VERSION',
  'CODEBUILD_BUILD_ID',
  'BITBUCKET_BUILD_NUMBER',
  'APPVEYOR',
  'DRONE',
];

/**
 * Variables a test runner sets in the processes it runs, which a spawned CLI
 * inherits: Vitest, Jest and `node --test`. `NODE_ENV=test` is checked as well
 * (see `automationMarker`).
 */
export const TEST_RUNNER_MARKERS: readonly string[] = [
  'VITEST',
  'JEST_WORKER_ID',
  'NODE_TEST_CONTEXT',
];

/** `OPENA2A_TELEMETRY` values that turn usage telemetry on for one run. */
const OPT_IN_VALUES: ReadonlySet<string> = new Set(['on', '1', 'true', 'yes']);

/** Set to something other than empty, `false` or `0` (`CI=false` is not CI). */
function markerSet(value: string | undefined): boolean {
  if (value === undefined) return false;
  const v = value.trim().toLowerCase();
  return v !== '' && v !== 'false' && v !== '0';
}

/** The first CI or test-runner marker in `env`, or undefined when there is none. */
export function automationMarker(env: NodeJS.ProcessEnv): string | undefined {
  for (const name of [...CI_MARKERS, ...TEST_RUNNER_MARKERS]) {
    if (markerSet(env[name])) return name;
  }
  if (env.NODE_ENV?.trim().toLowerCase() === 'test') return 'NODE_ENV';
  return undefined;
}

/** Whether `OPENA2A_TELEMETRY` turns usage telemetry on for this run. */
export function telemetryExplicitlyOn(env: NodeJS.ProcessEnv): boolean {
  return OPT_IN_VALUES.has(env.OPENA2A_TELEMETRY?.trim().toLowerCase() ?? '');
}

/**
 * The marker that keeps usage telemetry off for this run, or undefined when
 * the run is not automated or `OPENA2A_TELEMETRY` turns telemetry on.
 */
export function automationOptOut(env: NodeJS.ProcessEnv): string | undefined {
  if (telemetryExplicitlyOn(env)) return undefined;
  return automationMarker(env);
}

/**
 * Why usage telemetry is off for this run, when a CI or test-runner marker is
 * the reason, or undefined when it is not (#999).
 *
 * `enabledOtherwise` is the state the user's own settings give (the persisted
 * `telemetry on|off` and `OPENA2A_TELEMETRY=off`): when those already turn
 * telemetry off, the marker is not the reason, and `OPENA2A_TELEMETRY=on`
 * would not turn it back on, so no reason naming the marker is given.
 *
 * Without it, `CI=true hackmyagent telemetry on` printed `state: on` and the
 * next `telemetry status` printed `state: off`, and `--version` printed
 * `Telemetry: off` with no word on why.
 */
export function automationOffReason(env: NodeJS.ProcessEnv, enabledOtherwise: boolean): string | undefined {
  if (!enabledOtherwise) return undefined;
  const marker = automationOptOut(env);
  if (!marker) return undefined;
  const named = marker === 'NODE_ENV' ? 'NODE_ENV=test' : marker;
  return `${named} is set, and usage telemetry is off under CI and test runners unless OPENA2A_TELEMETRY=on is set for the run`;
}

/**
 * Run the SDK's `init` with usage telemetry off when `automationOptOut` names a
 * marker in `env`.
 *
 * The SDK reads its opt-out from `process.env.OPENA2A_TELEMETRY` inside `init`
 * and keeps the result for the session, and it takes no option for it. So the
 * variable is set to `off` for that call only and put back afterwards: left
 * set, it would be inherited by every child process, and `arp telemetry
 * status` would name an environment variable the user never set as the reason
 * its own channel is off.
 */
export async function initWithAutomationOptOut(
  init: () => Promise<void>,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  if (!automationOptOut(env)) {
    await init();
    return;
  }
  const had = Object.prototype.hasOwnProperty.call(env, 'OPENA2A_TELEMETRY');
  const prior = env.OPENA2A_TELEMETRY;
  env.OPENA2A_TELEMETRY = 'off';
  try {
    await init();
  } finally {
    if (had) env.OPENA2A_TELEMETRY = prior;
    else delete env.OPENA2A_TELEMETRY;
  }
}
