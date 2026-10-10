/**
 * Places the generative analyst's install where a test can build it, so a test
 * of the built CLI can vary whether an analyst is installed and nothing else.
 *
 * A preload because the test spawns the built CLI: the claim under test is
 * what a person reads in a terminal, with the exit code that goes with it.
 *
 * Whether an analyst is installed is read from a launchd agent in the home
 * directory, on macOS, for a daemon on one fixed socket. A test cannot hold
 * any of the three on the machine it runs on, so with this loaded:
 *
 *   - the install is looked for as on macOS, under HOME as the test set it,
 *     serving the socket named by NANOMIND_GUARD_SOCK. Everything after that
 *     is the code under test: the file check, the connection to the socket and
 *     the health probe all run;
 *   - every `fetch` is rejected, which is what an unreachable Registry looks
 *     like;
 *   - the local classifier answers a confident benign without loading or
 *     downloading a model (its download goes through `https.get`, not
 *     `fetch`), so a scan gives the same answer on a machine with a cached
 *     model and on one without.
 */
const path = require('node:path');

const DIST = path.join(__dirname, '..', '..', 'dist', 'nanomind-core', 'inference');

const analyst = require(path.join(DIST, 'security-analyst.js'));
const { getAnalystStatus, isAnalystInstalledStopped } = analyst;
const install = () => ({ platform: 'darwin', agentSocketPath: process.env.NANOMIND_GUARD_SOCK });
analyst.getAnalystStatus = () => getAnalystStatus(install());
analyst.isAnalystInstalledStopped = () => isAnalystInstalledStopped(install());

const { TMEClassifier } = require(path.join(DIST, 'tme-classifier.js'));
TMEClassifier.prototype.ensureModel = async function ensureModel() {};
TMEClassifier.prototype.classifyAsync = async function classifyAsync() {
  return {
    intentClass: 'benign',
    attackClass: 'none',
    confidence: 0.99,
    topClasses: [{ class: 'benign', score: 0.99 }],
  };
};

globalThis.fetch = async () => {
  throw new TypeError('fetch failed');
};
