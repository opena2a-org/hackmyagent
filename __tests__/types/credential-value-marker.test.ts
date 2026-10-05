/**
 * A finding names a credential by what it is, never by its bytes.
 *
 * The standard form is the labelled marker `<label>: [REDACTED]`, the form the
 * canonical credential scan already prints. Two finding-text routes still built
 * their own starred prefix instead:
 *
 *   - the package narrative's hardcoded-secret block printed the vendor prefix
 *     plus stars, and for a value with no vendor prefix the first EIGHT
 *     characters of the secret plus stars;
 *   - the NemoClaw scanner printed the first four characters plus `***`, which
 *     for an `nv-` key is one byte of secret body.
 *
 * Every assertion here reads the route's output, not the helper alone: each
 * must carry a marker the tool's own marker contract recognises, no star run,
 * and no four-character window of the value past its vendor prefix.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { credentialValueMarker } from "../../src/types/credential-format.js";
import { containsRedactionMarker } from "../../src/types/redacted-evidence.js";
import { buildPackageNarrative, type BuildPackageNarrativeInput } from "../../src/narrative/build-narrative.js";
import type { SecurityAST } from "../../src/nanomind-core/types.js";
import type { SecurityFinding } from "../../src/hardening/security-check.js";

// Synthetic bodies: mixed case and digits so no window of one can occur in a
// label by accident.
const BODY = "Q7x9Z2mK4pL8vR3tW6yB1nC5dF0gH2jS";
const HF = `hf_${BODY}`;
const ANTHROPIC = `sk-ant-api03-${BODY}${BODY}`;
const UNKNOWN = `zq81Kd7Lm3Np9Rt2Vw5Xy8Ab4Cd6Ef0Gh`;
const NVIDIA = `nvapi-${BODY}`;
const NVIDIA_SHORT_HEAD = `nv-${BODY}`;

/** Every 4-character window of `body` that `text` contains. */
function leakedWindows(text: string, body: string): string[] {
  const out: string[] = [];
  for (let i = 0; i + 4 <= body.length; i++) {
    const w = body.slice(i, i + 4);
    if (text.includes(w)) out.push(w);
  }
  return out;
}

function expectLabelledMarker(text: string, body: string): void {
  expect(containsRedactionMarker(text), text).toBe(true);
  expect(text, "a starred prefix was printed").not.toMatch(/\*/);
  expect(leakedWindows(text, body), "credential body bytes were printed").toEqual([]);
}

describe("credentialValueMarker", () => {
  it("names a vendor-shaped value by its registry label", () => {
    expect(credentialValueMarker(HF)).toBe("Hugging Face token: [REDACTED]");
    expect(credentialValueMarker(ANTHROPIC)).toBe("Anthropic API key: [REDACTED]");
    expect(credentialValueMarker(`eyJhbGciOiJIUzI1NiJ9.${BODY}.${BODY}`)).toBe("JSON Web Token: [REDACTED]");
  });

  it("prefers the value's own shape over the caller's label", () => {
    expect(credentialValueMarker(HF, "Anthropic API key")).toBe("Hugging Face token: [REDACTED]");
  });

  it("falls back to the caller's label, then to a generic one, for an unknown shape", () => {
    expect(credentialValueMarker(UNKNOWN, "AWS secret access key")).toBe("AWS secret access key: [REDACTED]");
    expect(credentialValueMarker(UNKNOWN)).toBe("Credential: [REDACTED]");
    expect(credentialValueMarker(UNKNOWN, "  ")).toBe("Credential: [REDACTED]");
  });
});

const ast = { artifactType: "skill", declaredCapabilities: [], declaredConstraints: [], declaredDataAccess: [],
  inferredCapabilities: [], inferredRiskSurface: [], evidenceSpans: [], dependsOn: [], governedBy: [],
  declaredPurpose: "", intentClassification: "unknown", intentConfidence: 0 } as unknown as SecurityAST;

const input = (findings: SecurityFinding[]): BuildPackageNarrativeInput => ({
  ast, packageName: "opena2a/example-skill", packageVersion: "1.0.0", findings, verdict: "WARNING",
  scanStatus: "completed", attestations: {}, communityScans: 0, cleanCommunityScans: 0, hasSoulFile: false,
  publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
});

const finding = (o: Partial<SecurityFinding>): SecurityFinding => ({
  checkId: "AST-CRED-001", name: "x", description: "x", category: "credentials", severity: "critical",
  passed: false, message: "x", fixable: false, file: "SKILL.md", line: 3, ...o,
} as SecurityFinding);

function secrets(n: unknown): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (v && typeof v === "object") {
      const o = v as Record<string, unknown>;
      if ("maskedValue" in o && "totalChars" in o) out.push(o);
      Object.values(o).forEach(walk);
    }
  };
  walk((n as { hardcodedSecrets?: unknown } | null)?.hardcodedSecrets);
  return out;
}

describe("package narrative hardcoded-secret block", () => {
  const cases: Array<[string, Partial<SecurityFinding>, string, string]> = [
    ["vendor prefix", { name: "Hardcoded Hugging Face token", details: { value: HF } } as Partial<SecurityFinding>,
      "Hugging Face token: [REDACTED]", BODY],
    ["unknown shape with a finding label", { name: "Hardcoded AWS secret access key", details: { value: UNKNOWN } } as Partial<SecurityFinding>,
      "AWS secret access key: [REDACTED]", UNKNOWN],
    ["unknown shape with no label", { name: "Secret in config", details: { rawValue: UNKNOWN } } as Partial<SecurityFinding>,
      "Credential: [REDACTED]", UNKNOWN],
  ];

  for (const [what, o, marker, body] of cases) {
    it(`prints the labelled marker and no value bytes (${what})`, async () => {
      const n = await buildPackageNarrative(input([finding(o)]));
      const listed = secrets(n);
      expect(listed).toHaveLength(1);
      const value = String((o.details as { value?: string; rawValue?: string }).value ?? (o.details as { rawValue?: string }).rawValue);
      expect(listed[0].maskedValue).toBe(marker);
      expect(listed[0].shownChars).toBe(0);
      expect(listed[0].totalChars).toBe(value.length);
      expectLabelledMarker(String(listed[0].maskedValue), body);
      expect(leakedWindows(JSON.stringify(n), body), "the narrative carries credential body bytes").toEqual([]);
    });
  }
});

describe("NemoClaw key findings", () => {
  let home: string;
  let target: string;
  const savedHome = process.env.HOME;
  type Probe = { checkNMC001(d: string): SecurityFinding[]; checkNMC002(): SecurityFinding[]; checkNMC004(): SecurityFinding[] };
  let scanner: Probe;

  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "hma-nmc-home-"));
    target = mkdtempSync(join(tmpdir(), "hma-nmc-target-"));
    writeFileSync(join(target, ".nemoclawrc"), `NVIDIA_API_KEY=${NVIDIA}\n`);
    mkdirSync(join(home, ".openshell", "logs"), { recursive: true });
    writeFileSync(join(home, ".openshell", "logs", "gateway.log"), `auth ${NVIDIA_SHORT_HEAD}\n`);
    writeFileSync(join(home, ".zsh_history"), `export NVIDIA_API_KEY=${NVIDIA}\n`);
    // The scanner resolves its home directories when the module loads.
    process.env.HOME = home;
    vi.resetModules();
    const { NemoClawScanner } = await import("../../src/hardening/nemoclaw-scanner.js");
    scanner = new NemoClawScanner() as unknown as Probe;
  });

  /** The message with the temp directories cut out, so a random path suffix is not read as a leak. */
  const text = (f: SecurityFinding): string => f.message.split(home).join("").split(target).join("");

  afterAll(() => {
    process.env.HOME = savedHome;
    rmSync(home, { recursive: true, force: true });
    rmSync(target, { recursive: true, force: true });
  });

  it("HMA-NMC-001 names the key in a plaintext config without printing it", () => {
    const f = scanner.checkNMC001(target).find((x) => x.checkId === "HMA-NMC-001" && !x.passed);
    expect(f?.message).toBe(`Found NVIDIA API key: [REDACTED] in ${join(target, ".nemoclawrc")} at line 1`);
    expectLabelledMarker(text(f!), BODY);
  });

  it("HMA-NMC-002 names a short-headed key in gateway logs without printing a byte of its body", () => {
    const f = scanner.checkNMC002().find((x) => x.checkId === "HMA-NMC-002" && !x.passed);
    expect(f?.message).toContain("Found NVIDIA API key: [REDACTED] in ");
    expectLabelledMarker(text(f!), BODY);
    // The old four-character prefix of `nv-<body>` was one byte of body.
    expect(text(f!)).not.toContain("nv-");
  });

  it("HMA-NMC-004 names the key in shell history without printing it", () => {
    const f = scanner.checkNMC004().find((x) => x.checkId === "HMA-NMC-004" && !x.passed);
    expect(f?.message).toBe("Found NVIDIA API key: [REDACTED] in .zsh_history at line 1");
    expectLabelledMarker(text(f!), BODY);
  });
});
