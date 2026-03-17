/**
 * Skill Dependency Graph Analysis
 *
 * Parses SKILL.md files, builds a dependency graph, and detects:
 * - SKILL-010: Circular dependencies
 * - SKILL-011: Phantom dependencies (referenced but not found)
 * - SKILL-012: Unpinned dependency versions
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Finding, Severity } from '../plugins/core';

// --- Types ---

export interface SkillMetadata {
  /** Skill name from frontmatter */
  name: string;
  /** Version declared in frontmatter */
  version?: string;
  /** Dependencies declared in frontmatter (name or name@version) */
  dependencies: string[];
  /** Tools declared in frontmatter */
  tools: string[];
  /** File path where this SKILL.md was found */
  filePath: string;
}

export interface DependencyGraph {
  /** All skills indexed by name */
  nodes: Map<string, SkillMetadata>;
  /** Adjacency list: skill name -> set of dependency names */
  edges: Map<string, Set<string>>;
}

// --- Frontmatter Parsing ---

/**
 * Parse YAML frontmatter from SKILL.md content.
 * Extracts name, version, dependencies, and tools fields.
 */
export function parseSkillFrontmatter(content: string, filePath: string = ''): SkillMetadata {
  const metadata: SkillMetadata = {
    name: '',
    version: undefined,
    dependencies: [],
    tools: [],
    filePath,
  };

  // Extract frontmatter between --- delimiters
  const frontmatterMatch = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) {
    // If no frontmatter, try to extract name from first heading
    const headingMatch = content.match(/^#\s+(.+)/m);
    if (headingMatch) {
      metadata.name = headingMatch[1].trim();
    }
    return metadata;
  }

  const frontmatter = frontmatterMatch[1];

  // Parse name
  const nameMatch = frontmatter.match(/^name:\s*(.+)$/m);
  if (nameMatch) {
    metadata.name = nameMatch[1].trim().replace(/^["']|["']$/g, '');
  }

  // Parse version
  const versionMatch = frontmatter.match(/^version:\s*(.+)$/m);
  if (versionMatch) {
    metadata.version = versionMatch[1].trim().replace(/^["']|["']$/g, '');
  }

  // Parse dependencies (YAML list)
  metadata.dependencies = parseYamlList(frontmatter, 'dependencies');

  // Parse tools (YAML list)
  metadata.tools = parseYamlList(frontmatter, 'tools');

  return metadata;
}

/**
 * Parse a simple YAML list field from frontmatter content.
 * Supports both inline [a, b] and block list formats.
 */
function parseYamlList(frontmatter: string, field: string): string[] {
  // Try inline format: field: [a, b, c]
  const inlineMatch = frontmatter.match(new RegExp(`^${field}:\\s*\\[([^\\]]*)]`, 'm'));
  if (inlineMatch) {
    return inlineMatch[1]
      .split(',')
      .map((item) => item.trim().replace(/^["']|["']$/g, ''))
      .filter((item) => item.length > 0);
  }

  // Try block format:
  // field:
  //   - item1
  //   - item2
  const blockMatch = frontmatter.match(new RegExp(`^${field}:\\s*\\n((?:\\s+-\\s+.+\\n?)*)`, 'm'));
  if (blockMatch) {
    return blockMatch[1]
      .split('\n')
      .map((line) => {
        const itemMatch = line.match(/^\s+-\s+(.+)/);
        return itemMatch ? itemMatch[1].trim().replace(/^["']|["']$/g, '') : '';
      })
      .filter((item) => item.length > 0);
  }

  return [];
}

// --- Graph Construction ---

/**
 * Recursively scan a directory for SKILL.md files and build a dependency graph.
 */
export function buildDependencyGraph(skillDir: string): DependencyGraph {
  const graph: DependencyGraph = {
    nodes: new Map(),
    edges: new Map(),
  };

  const skillFiles = findSkillFiles(skillDir);

  for (const filePath of skillFiles) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const metadata = parseSkillFrontmatter(content, filePath);

      // Use filename-based name as fallback
      if (!metadata.name) {
        const dirName = path.basename(path.dirname(filePath));
        metadata.name = dirName !== '.' ? dirName : path.basename(filePath, '.md');
      }

      graph.nodes.set(metadata.name, metadata);

      // Build edges from dependencies
      const depNames = new Set<string>();
      for (const dep of metadata.dependencies) {
        // Strip version from dependency reference (e.g., "skill-a@1.0.0" -> "skill-a")
        const depName = dep.split('@')[0];
        depNames.add(depName);
      }
      graph.edges.set(metadata.name, depNames);
    } catch {
      // Skip files that cannot be read
    }
  }

  return graph;
}

/**
 * Recursively find all SKILL.md files in a directory.
 */
function findSkillFiles(dir: string): string[] {
  const results: string[] = [];

  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
        results.push(...findSkillFiles(fullPath));
      } else if (entry.isFile() && entry.name.toUpperCase() === 'SKILL.MD') {
        results.push(fullPath);
      }
    }
  } catch {
    // Directory not readable
  }

  return results;
}

// --- Detection Functions ---

/**
 * Detect circular dependencies using DFS with a recursion stack.
 */
export function detectCircularDeps(graph: DependencyGraph): Finding[] {
  const findings: Finding[] = [];
  const visited = new Set<string>();
  const inStack = new Set<string>();
  const cyclePaths: string[][] = [];

  function dfs(node: string, pathSoFar: string[]): void {
    if (inStack.has(node)) {
      // Found a cycle — extract the cycle portion
      const cycleStart = pathSoFar.indexOf(node);
      const cycle = [...pathSoFar.slice(cycleStart), node];
      cyclePaths.push(cycle);
      return;
    }

    if (visited.has(node)) return;

    visited.add(node);
    inStack.add(node);

    const deps = graph.edges.get(node);
    if (deps) {
      for (const dep of deps) {
        dfs(dep, [...pathSoFar, node]);
      }
    }

    inStack.delete(node);
  }

  for (const nodeName of graph.nodes.keys()) {
    dfs(nodeName, []);
  }

  for (const cycle of cyclePaths) {
    const cycleStr = cycle.join(' -> ');
    const node = graph.nodes.get(cycle[0]);
    findings.push({
      id: 'SKILL-010',
      title: 'Circular dependency detected',
      description: `Circular dependency chain: ${cycleStr}`,
      severity: 'high' as Severity,
      filePath: node?.filePath,
      autoFixable: false,
    });
  }

  return findings;
}

/**
 * Detect phantom dependencies — referenced skills that do not exist in the graph.
 */
export function detectPhantomDeps(graph: DependencyGraph): Finding[] {
  const findings: Finding[] = [];

  for (const [skillName, deps] of graph.edges.entries()) {
    for (const dep of deps) {
      if (!graph.nodes.has(dep)) {
        const node = graph.nodes.get(skillName);
        findings.push({
          id: 'SKILL-011',
          title: 'Phantom dependency',
          description: `Skill "${skillName}" depends on "${dep}" which was not found in the scanned directory`,
          severity: 'medium' as Severity,
          filePath: node?.filePath,
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

/**
 * Detect unpinned dependency versions — dependencies without a version specifier.
 */
export function detectUnpinnedDeps(graph: DependencyGraph): Finding[] {
  const findings: Finding[] = [];

  for (const [, metadata] of graph.nodes.entries()) {
    for (const dep of metadata.dependencies) {
      // Check if dep has a version pin (contains @version after the name)
      // e.g., "skill-a@1.0.0" is pinned, "skill-a" is not
      const hasVersion = dep.includes('@') && dep.split('@').length === 2 && dep.split('@')[1].length > 0;
      if (!hasVersion) {
        findings.push({
          id: 'SKILL-012',
          title: 'Unpinned dependency version',
          description: `Skill "${metadata.name}" depends on "${dep}" without a pinned version. Pin to a specific version (e.g., "${dep}@1.0.0") to prevent supply chain attacks.`,
          severity: 'low' as Severity,
          filePath: metadata.filePath,
          autoFixable: false,
        });
      }
    }
  }

  return findings;
}

// --- Main Entry Point ---

/**
 * Analyze skill dependencies in a directory.
 * Combines circular dependency detection, phantom dependency detection,
 * and unpinned version detection.
 */
export function analyzeSkillDependencies(skillDir: string): Finding[] {
  const graph = buildDependencyGraph(skillDir);

  if (graph.nodes.size === 0) {
    return [];
  }

  const findings: Finding[] = [
    ...detectCircularDeps(graph),
    ...detectPhantomDeps(graph),
    ...detectUnpinnedDeps(graph),
  ];

  return findings;
}
