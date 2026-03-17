import { describe, it, expect } from 'vitest';
import {
  parseDeclaredCapabilities,
  inferActualCapabilities,
  validateCapabilities,
} from '../../src/hardening/skill-capability-validator';
import type {
  SkillDeclaredCapabilities,
  InferredCapability,
} from '../../src/hardening/skill-capability-validator';

describe('parseDeclaredCapabilities', () => {
  it('should parse capabilities from inline YAML list', () => {
    const content = `---
name: test-skill
capabilities: [filesystem:read, network:outbound]
---

# Test Skill`;

    const result = parseDeclaredCapabilities(content);
    expect(result.capabilities).toContain('filesystem:read');
    expect(result.capabilities).toContain('network:outbound');
  });

  it('should parse capabilities from block YAML list', () => {
    const content = `---
name: test-skill
capabilities:
  - filesystem:read
  - network:outbound
  - shell:execute
---

# Test Skill`;

    const result = parseDeclaredCapabilities(content);
    expect(result.capabilities).toHaveLength(3);
    expect(result.capabilities).toContain('shell:execute');
  });

  it('should return empty capabilities when no frontmatter', () => {
    const content = '# Just a heading\n\nSome content.';
    const result = parseDeclaredCapabilities(content);
    expect(result.capabilities).toHaveLength(0);
    expect(Object.keys(result.permissions)).toHaveLength(0);
  });

  it('should parse permissions block', () => {
    const content = `---
name: test-skill
capabilities:
  - filesystem:read
permissions:
  filesystem:
    - ./data/**
    - ./config/**
---

# Test Skill`;

    const result = parseDeclaredCapabilities(content);
    expect(result.permissions['filesystem']).toBeDefined();
    expect(result.permissions['filesystem']).toContain('./data/**');
    expect(result.permissions['filesystem']).toContain('./config/**');
  });

  it('should extract prefix from capability entries into permissions', () => {
    const content = `---
name: test-skill
capabilities:
  - network:outbound
---

# Test`;

    const result = parseDeclaredCapabilities(content);
    expect(result.permissions['network']).toBeDefined();
    expect(result.permissions['network']).toContain('outbound');
  });
});

describe('inferActualCapabilities', () => {
  it('should detect filesystem access to sensitive paths', () => {
    const content = `---
name: ssh-tool
---

# SSH Helper

\`\`\`bash
cat ~/.ssh/id_rsa
ls ~/.aws/credentials
\`\`\`
`;

    const inferred = inferActualCapabilities(content);
    const capabilities = inferred.map(i => i.capability);
    expect(capabilities).toContain('filesystem:~/.ssh');
    expect(capabilities).toContain('filesystem:~/.aws');
  });

  it('should detect network outbound capabilities', () => {
    const content = `---
name: fetcher
---

# Data Fetcher

\`\`\`javascript
const data = await fetch('https://api.example.com');
curl https://example.com/data
\`\`\`
`;

    const inferred = inferActualCapabilities(content);
    const capabilities = inferred.map(i => i.capability);
    expect(capabilities).toContain('network:outbound');
  });

  it('should detect shell execution capabilities', () => {
    const content = `---
name: runner
---

# Command Runner

\`\`\`javascript
exec('ls -la');
spawn('node', ['script.js']);
\`\`\`
`;

    const inferred = inferActualCapabilities(content);
    const capabilities = inferred.map(i => i.capability);
    expect(capabilities).toContain('shell:execute');
  });

  it('should detect network inbound capabilities', () => {
    const content = `---
name: server
---

# Server Skill

\`\`\`javascript
const server = createServer((req, res) => {});
server.listen(8080);
\`\`\`
`;

    const inferred = inferActualCapabilities(content);
    const capabilities = inferred.map(i => i.capability);
    expect(capabilities).toContain('network:inbound');
  });

  it('should not infer capabilities from frontmatter', () => {
    const content = `---
name: safe-skill
capabilities:
  - filesystem:~/.ssh
---

# Safe Skill

Just a description.
`;

    const inferred = inferActualCapabilities(content);
    expect(inferred).toHaveLength(0);
  });

  it('should include line numbers', () => {
    const content = `---
name: test
---

# Test

curl https://example.com
`;

    const inferred = inferActualCapabilities(content);
    expect(inferred.length).toBeGreaterThan(0);
    expect(inferred[0].lineNumber).toBeGreaterThan(0);
  });
});

describe('validateCapabilities', () => {
  it('should generate SKILL-018 for undeclared filesystem access', () => {
    const declared: SkillDeclaredCapabilities = {
      capabilities: ['network:outbound'],
      permissions: { network: ['outbound'] },
    };
    const inferred: InferredCapability[] = [
      { capability: 'filesystem:~/.ssh', evidence: 'cat ~/.ssh/id_rsa', lineNumber: 10 },
    ];

    const findings = validateCapabilities(declared, inferred, 'test-skill.md');
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('SKILL-018');
    expect(findings[0].severity).toBe('medium');
    expect(findings[0].passed).toBe(false);
  });

  it('should not flag declared capabilities', () => {
    const declared: SkillDeclaredCapabilities = {
      capabilities: ['filesystem:read', 'network:outbound'],
      permissions: { filesystem: ['read'], network: ['outbound'] },
    };
    const inferred: InferredCapability[] = [
      { capability: 'filesystem:~/.config', evidence: 'ls ~/.config', lineNumber: 10 },
      { capability: 'network:outbound', evidence: 'curl example.com', lineNumber: 12 },
    ];

    const findings = validateCapabilities(declared, inferred);
    expect(findings).toHaveLength(0);
  });

  it('should generate findings for undeclared network access', () => {
    const declared: SkillDeclaredCapabilities = {
      capabilities: ['filesystem:read'],
      permissions: { filesystem: ['read'] },
    };
    const inferred: InferredCapability[] = [
      { capability: 'network:outbound', evidence: 'wget http://evil.com', lineNumber: 5 },
    ];

    const findings = validateCapabilities(declared, inferred, 'skill.md');
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe('SKILL-018');
    expect(findings[0].message).toContain('network:outbound');
  });

  it('should return empty findings when all capabilities are declared', () => {
    const declared: SkillDeclaredCapabilities = {
      capabilities: ['shell:execute', 'network:outbound', 'filesystem:~/.ssh'],
      permissions: {
        shell: ['execute'],
        network: ['outbound'],
        filesystem: ['~/.ssh'],
      },
    };
    const inferred: InferredCapability[] = [
      { capability: 'shell:execute', evidence: 'exec("ls")', lineNumber: 10 },
      { capability: 'network:outbound', evidence: 'curl example.com', lineNumber: 11 },
      { capability: 'filesystem:~/.ssh', evidence: 'cat ~/.ssh/id_rsa', lineNumber: 12 },
    ];

    const findings = validateCapabilities(declared, inferred);
    expect(findings).toHaveLength(0);
  });

  it('should handle empty inferred capabilities', () => {
    const declared: SkillDeclaredCapabilities = {
      capabilities: ['filesystem:read'],
      permissions: {},
    };
    const findings = validateCapabilities(declared, []);
    expect(findings).toHaveLength(0);
  });
});
