// One line that records a rendered walkthrough: the sidecar's path and sha256, the build it names,
// when it was rendered, the measured wall clock and the metered cost. The render scripts print it
// last; a release record carries it, so the sidecar that shipped can be matched by its hash.
// Usage: node docs/vhs/sidecar-line.mjs docs/vhs/<name>.json   (from the repository root)
//
// Exits 1 and prints no line when the sidecar carries no wall clock in seconds or a metered cost
// other than 0: a render that was not timed, or that cost money, is not recorded as one that was
// timed and free.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: node docs/vhs/sidecar-line.mjs docs/vhs/<name>.json");
  process.exit(1);
}
const bytes = readFileSync(file);
const sidecar = JSON.parse(bytes.toString("utf8"));
const problems = [];
if (!("wallClockSeconds" in sidecar)) problems.push("carries no wallClockSeconds");
else if (typeof sidecar.wallClockSeconds !== "number" || !(sidecar.wallClockSeconds > 0)) {
  problems.push(`has wallClockSeconds ${JSON.stringify(sidecar.wallClockSeconds)}, not a measured number of seconds`);
}
if (!("meteredCostUsd" in sidecar)) problems.push("carries no meteredCostUsd");
else if (sidecar.meteredCostUsd !== 0) problems.push(`has meteredCostUsd ${JSON.stringify(sidecar.meteredCostUsd)}, not 0`);
if (problems.length > 0) {
  console.error(`sidecar-line: ${file} ${problems.join(" and ")}; re-render it with the script its tape names.`);
  process.exit(1);
}
const build = sidecar.npmIntegrity
  ? "from npm"
  : sidecar.packedFromCommit
    ? `packed from ${sidecar.packedFromCommit}`
    : "build not named";
const sha256 = createHash("sha256").update(bytes).digest("hex");
console.log(
  `sidecar ${file} sha256 ${sha256}: ${sidecar.tool} ${sidecar.version} (${build}), rendered ${sidecar.ranAtUtc}, ` +
    `wall clock ${sidecar.wallClockSeconds} s, metered cost $${sidecar.meteredCostUsd}`,
);
