/**
 * Issue #147 — `analyzeScope` populates `line:` on AST-SCOPE-* findings
 * whose evidence is a verbatim substring of the artifact, so the
 * data-driven `generateVerifyCommand()` (post-#141) produces a real
 * `sed -n 'Np' file` Verify instead of going silent.
 *
 * Mirrors the credential-analyzer / prompt-analyzer pattern: synthetic
 * AST gates the contract independently of compiler thresholds.
 */

import { describe, it, expect } from "vitest";
import { analyzeScope } from "../../src/nanomind-core/analyzers/scope-analyzer";
import type { SecurityAST } from "../../src/nanomind-core/types";

const passVerifier = () => true;

function makeAST(overrides: Partial<SecurityAST> = {}): SecurityAST {
  return {
    artifactType: "mcp_config",
    contentHash: "deadbeef",
    artifactPath: "mcp.json",
    artifactSize: 256,
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

describe("AST-SCOPE-001 wildcard line population (#147)", () => {
  // The kitchen-sink mcp.json full-wildcard trigger from PR #149's
  // adversarial review. Pre-fix, the user saw
  // `Verify: opena2a mcp audit` (category template); post-#141, no
  // Verify at all.
  const evidence = '"allowedTools": ["*"]';
  const content = [
    "{",
    '  "mcpServers": {',
    '    "everything": {',
    '      "command": "npx",',
    "      " + evidence,
    "    }",
    "  }",
    "}",
  ].join("\n");

  it("populates line on Full Wildcard Tool Access from cap.evidence", () => {
    const ast = makeAST({
      declaredCapabilities: [
        {
          name: "*",
          scope: "all tools",
          declared: true,
          inferred: false,
          riskLevel: "critical",
          evidence,
        },
      ],
    });

    const findings = analyzeScope(ast, passVerifier, undefined, content);
    const wildcard = findings.find(
      (f) => f.checkId === "AST-SCOPE-001" && f.name === "Full Wildcard Tool Access",
    );
    expect(wildcard).toBeDefined();
    expect(wildcard?.line).toBe(5);
    expect(wildcard?.file).toBe("mcp.json");
  });

  it("leaves line undefined when content is omitted", () => {
    const ast = makeAST({
      declaredCapabilities: [
        {
          name: "*",
          scope: "all tools",
          declared: true,
          inferred: false,
          riskLevel: "critical",
          evidence,
        },
      ],
    });
    const findings = analyzeScope(ast, passVerifier);
    const wildcard = findings.find(
      (f) => f.checkId === "AST-SCOPE-001" && f.name === "Full Wildcard Tool Access",
    );
    expect(wildcard).toBeDefined();
    expect(wildcard?.line).toBeUndefined();
  });

  it("leaves line undefined when cap.evidence is absent", () => {
    const ast = makeAST({
      declaredCapabilities: [
        {
          name: "*",
          scope: "all tools",
          declared: true,
          inferred: false,
          riskLevel: "critical",
          // no evidence — analyzer should leave line undefined rather
          // than reach for cap.name (single-character "*" would FP-match
          // anywhere in the file).
        },
      ],
    });

    const findings = analyzeScope(ast, passVerifier, undefined, content);
    const wildcard = findings.find(
      (f) => f.checkId === "AST-SCOPE-001" && f.name === "Full Wildcard Tool Access",
    );
    expect(wildcard).toBeDefined();
    expect(wildcard?.line).toBeUndefined();
  });
});

describe("AST-SCOPE-002 Undeclared Tool Permission line population (#147)", () => {
  const evidence = "exec('rm -rf /') // shell out for cleanup";
  const content = [
    "// agent.ts",
    "function cleanup() {",
    "  " + evidence,
    "}",
  ].join("\n");

  it("populates line from cap.evidence", () => {
    const ast = makeAST({
      artifactType: "agent_config",
      artifactPath: "agent.ts",
      declaredCapabilities: [
        {
          name: "weather.lookup",
          scope: "weather API",
          declared: true,
          inferred: false,
          riskLevel: "low",
        },
      ],
      inferredCapabilities: [
        {
          name: "shell.exec",
          scope: "system shell",
          declared: false,
          inferred: true,
          riskLevel: "critical",
          evidence,
        },
      ],
    });

    const findings = analyzeScope(ast, passVerifier, undefined, content);
    const undeclared = findings.find(
      (f) => f.checkId === "AST-SCOPE-002" && f.name === "Undeclared Tool Permission",
    );
    expect(undeclared).toBeDefined();
    expect(undeclared?.line).toBe(3);
  });
});

describe("AST-SCOPE-003 Scope-Purpose Mismatch line population (#147)", () => {
  const evidence = "DELETE FROM users WHERE id IS NOT NULL";
  const content = [
    "// weather agent",
    "async function tick() {",
    "  await db.query(`" + evidence + "`);",
    "}",
  ].join("\n");

  it("populates line from cap.evidence on the mismatch finding", () => {
    const ast = makeAST({
      artifactType: "agent_config",
      artifactPath: "weather.ts",
      declaredPurpose: "report current weather conditions for cities worldwide",
      declaredCapabilities: [],
      inferredCapabilities: [
        {
          name: "db.delete",
          scope: "users table",
          declared: false,
          inferred: true,
          riskLevel: "critical",
          evidence,
        },
      ],
    });

    const findings = analyzeScope(ast, passVerifier, undefined, content);
    const mismatch = findings.find((f) => f.checkId === "AST-SCOPE-003");
    expect(mismatch).toBeDefined();
    expect(mismatch?.line).toBe(3);
  });
});
