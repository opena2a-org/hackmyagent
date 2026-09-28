/**
 * #586 — the package narrative turned credential-forwarding findings into a
 * phantom hardcoded secret: `AST-CRED-002` and `SHELL-EXFIL-001` carry class
 * `CRED-EXFIL`, no value and no "Hardcoded <label>" name, and were reshaped
 * into `type: 'unknown'`, `maskedValue: ''`, `totalChars: 0` at critical — a
 * secret the artifact does not contain, on a surface the Registry publishes.
 */
import { describe, expect, it } from "vitest";
import { buildPackageNarrative, type BuildPackageNarrativeInput } from "../../src/narrative/build-narrative.js";
import type { SecurityAST } from "../../src/nanomind-core/types.js";
import type { SecurityFinding } from "../../src/hardening/security-check.js";

const ast = { artifactType: "skill", declaredCapabilities: [], declaredConstraints: [], declaredDataAccess: [],
  inferredCapabilities: [], inferredRiskSurface: [], evidenceSpans: [], dependsOn: [], governedBy: [],
  declaredPurpose: "", intentClassification: "unknown", intentConfidence: 0 } as unknown as SecurityAST;

const input = (findings: SecurityFinding[]): BuildPackageNarrativeInput => ({
  ast, packageName: "opena2a/example-skill", packageVersion: "1.0.0", findings, verdict: "WARNING",
  scanStatus: "completed", attestations: {}, communityScans: 0, cleanCommunityScans: 0, hasSoulFile: false,
  publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
});

const finding = (o: Partial<SecurityFinding>): SecurityFinding => ({
  checkId: "X", name: "x", description: "x", category: "credentials", severity: "critical",
  passed: false, message: "x", fixable: false, file: "SKILL.md", line: 3, ...o,
} as SecurityFinding);

/** Every secret entry the published narrative carries, whatever block shape wraps them. */
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

describe("#586 package narrative lists only secrets the artifact holds", () => {
  const forwarding = finding({ checkId: "AST-CRED-002", name: "Credential Forwarding Detected", attackClass: "CRED-EXFIL" });
  const shellExfil = finding({ checkId: "SHELL-EXFIL-001", name: "Shell credential exfiltration", attackClass: "CRED-EXFIL", category: "credential-exposure" });
  const hardcoded = finding({
    checkId: "AST-CRED-001", name: "Hardcoded Anthropic API key", attackClass: "CRED-HARDCODED",
    details: { value: `sk-ant-api03-${"A".repeat(40)}` },
  } as Partial<SecurityFinding>);

  it("does not reshape a forwarding or exfiltration finding into a phantom secret", async () => {
    const n = await buildPackageNarrative(input([forwarding, shellExfil]));
    const phantom = secrets(n).filter((s) => s.totalChars === 0);
    expect(phantom, "an empty-valued secret was listed").toEqual([]);
    expect(secrets(n)).toEqual([]);
  });

  it("still lists a real hardcoded secret next to them", async () => {
    const n = await buildPackageNarrative(input([forwarding, hardcoded, shellExfil]));
    const listed = secrets(n);
    expect(listed).toHaveLength(1);
    expect(listed[0].totalChars).toBe(53);
    expect(String(listed[0].maskedValue)).not.toContain("A".repeat(40));
  });

  it("keeps a forwarding finding that does carry the credential value", async () => {
    const carrying = { ...forwarding, details: { value: `ghp_${"b".repeat(36)}` } } as SecurityFinding;
    const n = await buildPackageNarrative(input([carrying]));
    expect(secrets(n)).toHaveLength(1);
  });
});
