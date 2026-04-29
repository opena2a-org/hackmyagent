/**
 * Issue #147 — `analyzeGovernance` populates `line:` on AST-GOV-002
 * (Weak Constraint Enforceability / Decorative Constraint) when the
 * constraint text is a verbatim substring of the artifact, so the
 * data-driven `generateVerifyCommand()` (post-#141) produces a real
 * `sed -n 'Np' file` Verify.
 *
 * The other AST-GOV-* checks (001/003/004/005) are absence findings —
 * they fire on missing domains, missing override resistance, governance
 * ratio. There is no positional evidence for those, so line stays
 * undefined and the renderer cleanly omits Verify.
 */

import { describe, it, expect } from "vitest";
import { analyzeGovernance } from "../../src/nanomind-core/analyzers/governance-analyzer";
import type { SecurityAST } from "../../src/nanomind-core/types";

const passVerifier = () => true;

function makeAST(overrides: Partial<SecurityAST> = {}): SecurityAST {
  return {
    artifactType: "soul",
    contentHash: "deadbeef",
    artifactPath: "SOUL.md",
    artifactSize: 1024,
    declaredPurpose: "agent configuration",
    declaredCapabilities: [],
    declaredConstraints: [],
    declaredDataAccess: [],
    inferredCapabilities: [],
    inferredRiskSurface: [],
    intentClassification: "suspicious",
    intentConfidence: 0.7,
    dependsOn: [],
    governedBy: [],
    evidenceSpans: [],
    signature: "synthetic",
    modelVersion: "test-1",
    compiledAt: new Date(0).toISOString(),
    ...overrides,
  };
}

describe("AST-GOV-002 line population (#147)", () => {
  const decorativeText = "The agent should try to handle errors gracefully when appropriate.";
  const content = [
    "# SOUL",
    "",
    "## Error Handling",
    "",
    decorativeText,
    "",
    "## End",
  ].join("\n");

  it("populates line on Weak/Decorative Constraint from constraint.text", () => {
    const ast = makeAST({
      declaredConstraints: [
        {
          text: decorativeText,
          domain: "error_handling",
          enforceability: 0.2, // < 0.3 → "Decorative Constraint"
          bypassRisk: 0.85,
        },
      ],
    });

    const findings = analyzeGovernance(ast, passVerifier, undefined, undefined, content);
    const gov002 = findings.find((f) => f.checkId === "AST-GOV-002");
    expect(gov002).toBeDefined();
    expect(gov002?.line).toBe(5);
    expect(gov002?.file).toBe("SOUL.md");
  });

  it("leaves line undefined when content is omitted", () => {
    const ast = makeAST({
      declaredConstraints: [
        {
          text: decorativeText,
          domain: "error_handling",
          enforceability: 0.2,
          bypassRisk: 0.85,
        },
      ],
    });

    const findings = analyzeGovernance(ast, passVerifier);
    const gov002 = findings.find((f) => f.checkId === "AST-GOV-002");
    expect(gov002).toBeDefined();
    expect(gov002?.line).toBeUndefined();
  });

  it("leaves line undefined for project-level constraints not in this artifact's content", () => {
    // A constraint coming from a SIBLING SOUL.md (passed as projectConstraints)
    // won't match the current artifact's content. The analyzer must NOT
    // fabricate a line — that would mis-cite the source location.
    const ast = makeAST({
      artifactType: "mcp_config",
      artifactPath: "mcp.json",
      declaredConstraints: [],
      // The mcp.json content does not contain the SOUL.md constraint text.
      declaredCapabilities: [
        { name: "mcp.example", scope: "example", declared: true, inferred: false, riskLevel: "low" },
      ],
    });

    const projectConstraints = [
      {
        text: decorativeText,
        domain: "error_handling" as const,
        enforceability: 0.2,
        bypassRisk: 0.85,
      },
    ];

    const mcpJsonContent = '{ "mcpServers": { "example": { "command": "x" } } }';

    const findings = analyzeGovernance(
      ast,
      passVerifier,
      undefined,
      projectConstraints,
      mcpJsonContent,
    );
    const gov002 = findings.find((f) => f.checkId === "AST-GOV-002");
    expect(gov002).toBeDefined();
    expect(gov002?.line).toBeUndefined();
  });
});
