/**
 * Context Lifecycle Assembly Scanner (Stage 1)
 *
 * Simulates how agents assemble their system prompt from multiple components
 * (SOUL.md, tool descriptions, memory entries, user preferences, conversation
 * history) and detects injections that only activate post-assembly.
 *
 * Key threat model:
 * - A memory entry that looks benign alone but becomes a prompt injection
 *   when concatenated with the system prompt.
 * - Tool descriptions that contain hidden instructions exploiting their
 *   position adjacent to safety rules.
 * - Components that combine across boundaries to form split injections
 *   (half in memory, half in tool description).
 * - Benign-looking padding that displaces safety instructions out of the
 *   attention window.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import type {
  SecurityFinding,
  AssemblyComponent,
  AssemblyInteraction,
  LifecycleScanResult,
} from '../hardening/security-check';

/** Patterns that indicate prompt injection when found in assembled context */
const INJECTION_PATTERNS: { pattern: RegExp; name: string; severity: 'critical' | 'high' | 'medium' }[] = [
  { pattern: /ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|rules?|guidelines?)/i, name: 'instruction-override', severity: 'critical' },
  { pattern: /\[SYSTEM\s*(UPDATE|OVERRIDE|INSTRUCTION)\]/i, name: 'fake-system-tag', severity: 'critical' },
  { pattern: /you\s+are\s+now\s+(a\s+)?(?:new|different|unrestricted)/i, name: 'role-reassignment', severity: 'critical' },
  { pattern: /disregard\s+(your\s+)?(safety|security|guidelines?|rules?|instructions?)/i, name: 'safety-disregard', severity: 'critical' },
  { pattern: /new\s+instructions?\s*:\s*/i, name: 'instruction-injection', severity: 'high' },
  { pattern: /\bdo\s+not\s+follow\s+(the\s+)?(system|original|initial)\b/i, name: 'anti-system', severity: 'high' },
  { pattern: /\bassistant\s*:\s*\n/i, name: 'role-delimiter-injection', severity: 'high' },
  { pattern: /\bsystem\s*:\s*\n/i, name: 'system-delimiter-injection', severity: 'high' },
  { pattern: /\b(reveal|show|output|print)\s+(your\s+)?(system\s+prompt|instructions?|rules?)/i, name: 'prompt-extraction', severity: 'medium' },
  { pattern: /<!--[\s\S]*?(ignore|override|disregard)[\s\S]*?-->/i, name: 'html-comment-injection', severity: 'high' },
  { pattern: /\u200b|\u200c|\u200d|\ufeff/g, name: 'zero-width-char', severity: 'medium' },
];

/**
 * Patterns that are benign in isolation but become injections when components
 * are concatenated. Each entry has two halves: one from component A, one from
 * component B. When they appear adjacent in the assembled prompt, it's a
 * cross-component (semantic split) injection.
 */
const SPLIT_INJECTION_PAIRS: { partA: RegExp; partB: RegExp; name: string }[] = [
  { partA: /ignore\s+all\s*$/im, partB: /^\s*previous\s+instructions/im, name: 'split-override' },
  { partA: /\[SYSTEM$/im, partB: /^\s*OVERRIDE\]/im, name: 'split-system-tag' },
  { partA: /new\s+role\s*:\s*$/im, partB: /^\s*unrestricted\s+assistant/im, name: 'split-role-change' },
  { partA: /you\s+must\s+now\s*$/im, partB: /^\s*output\s+all\s+(secrets?|credentials?|api\s*keys?)/im, name: 'split-exfiltration' },
  { partA: /disregard\s*$/im, partB: /^\s*(safety|security)\s+guidelines/im, name: 'split-safety-bypass' },
];

/** Files that typically contribute to agent system prompt assembly */
const SOUL_FILES = ['SOUL.md', 'soul.md', 'SOUL.yaml', 'soul.yaml', 'system-prompt.md', 'system-prompt.txt', 'system_prompt.md', 'persona.md'];
const TOOL_DESC_FILES = ['tools.json', 'mcp.json', 'mcpServers.json', '.mcp.json', 'tool-descriptions.json', 'capabilities.json'];
const MEMORY_FILES = ['memory.json', 'context.json', '.memory', 'agent-memory.json', 'conversation-history.json', '.claude/memory/*.md'];
const USER_PREF_FILES = ['user-preferences.json', 'preferences.json', 'config.json', 'agent-config.json', '.agent.json', 'settings.json'];
const HISTORY_FILES = ['history.json', 'messages.json', 'chat-history.json', 'conversation.json'];

interface AssemblyScanOptions {
  targetDir: string;
  /** Maximum assembled prompt size in chars before triggering displacement warning */
  maxAssemblySize?: number;
  /** Progress callback */
  onProgress?: (message: string) => void;
}

/**
 * Discovers assembly components from the target directory.
 */
async function discoverComponents(targetDir: string): Promise<AssemblyComponent[]> {
  const components: AssemblyComponent[] = [];

  const tryReadFiles = async (
    filenames: string[],
    role: AssemblyComponent['role'],
  ) => {
    for (const filename of filenames) {
      // Handle glob-like patterns
      if (filename.includes('*')) {
        const dir = path.join(targetDir, path.dirname(filename));
        try {
          const entries = await fs.readdir(dir);
          for (const entry of entries) {
            const filePath = path.join(dir, entry);
            try {
              const stat = await fs.stat(filePath);
              if (stat.isFile()) {
                const content = await fs.readFile(filePath, 'utf-8');
                components.push({
                  source: path.relative(targetDir, filePath),
                  role,
                  content,
                });
              }
            } catch { /* skip */ }
          }
        } catch { /* directory doesn't exist */ }
        continue;
      }

      const filePath = path.join(targetDir, filename);
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        components.push({
          source: filename,
          role,
          content,
        });
      } catch { /* file doesn't exist - skip */ }
    }
  };

  await tryReadFiles(SOUL_FILES, 'soul');
  await tryReadFiles(TOOL_DESC_FILES, 'toolDescription');
  await tryReadFiles(MEMORY_FILES, 'memory');
  await tryReadFiles(USER_PREF_FILES, 'userPreference');
  await tryReadFiles(HISTORY_FILES, 'conversationHistory');

  // Also scan for inline system instructions in source files
  const srcDir = path.join(targetDir, 'src');
  try {
    const srcExists = await fs.access(srcDir).then(() => true).catch(() => false);
    if (srcExists) {
      const entries = await fs.readdir(srcDir, { recursive: true }) as string[];
      for (const entry of entries) {
        const entryStr = String(entry);
        if (!/\.(ts|js|py|mjs)$/.test(entryStr)) continue;
        const filePath = path.join(srcDir, entryStr);
        try {
          const stat = await fs.stat(filePath);
          if (!stat.isFile() || stat.size > 100_000) continue;
          const content = await fs.readFile(filePath, 'utf-8');
          // Extract string literals assigned to systemPrompt/system_prompt variables
          const systemPromptMatch = content.match(
            /(?:systemPrompt|system_prompt|system_message|SYSTEM_PROMPT)\s*(?:=|:)\s*[`'"]([\s\S]*?)[`'"]/
          );
          if (systemPromptMatch) {
            components.push({
              source: path.relative(targetDir, filePath),
              role: 'systemInstruction',
              content: systemPromptMatch[1],
            });
          }
        } catch { /* skip */ }
      }
    }
  } catch { /* no src dir */ }

  return components;
}

/**
 * Simulates the assembly process: concatenates components in typical agent
 * assembly order (system instructions -> SOUL -> tools -> memory -> prefs -> history).
 */
function assemblePrompt(components: AssemblyComponent[]): { assembled: string; components: AssemblyComponent[] } {
  // Sort by assembly priority (system instructions first, history last)
  const roleOrder: Record<AssemblyComponent['role'], number> = {
    systemInstruction: 0,
    soul: 1,
    toolDescription: 2,
    userPreference: 3,
    memory: 4,
    conversationHistory: 5,
  };

  const sorted = [...components].sort((a, b) => roleOrder[a.role] - roleOrder[b.role]);

  let offset = 0;
  const enriched: AssemblyComponent[] = [];
  const parts: string[] = [];

  for (const comp of sorted) {
    const section = `\n--- ${comp.role}: ${comp.source} ---\n${comp.content}\n`;
    enriched.push({
      ...comp,
      assembledOffset: offset,
      assembledLength: section.length,
    });
    parts.push(section);
    offset += section.length;
  }

  return { assembled: parts.join(''), components: enriched };
}

/**
 * Scans the assembled prompt for injection patterns that may not be visible
 * in individual components.
 */
function scanAssembledPrompt(
  assembled: string,
  components: AssemblyComponent[],
): { findings: SecurityFinding[]; interactions: AssemblyInteraction[] } {
  const findings: SecurityFinding[] = [];
  const interactions: AssemblyInteraction[] = [];

  // 1. Scan full assembled prompt for injection patterns
  for (const { pattern, name, severity } of INJECTION_PATTERNS) {
    const matches = assembled.matchAll(new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'));
    for (const match of matches) {
      if (match.index === undefined) continue;
      const matchOffset = match.index;

      // Find which component this match falls in
      const sourceComp = components.find(c =>
        c.assembledOffset !== undefined &&
        c.assembledLength !== undefined &&
        matchOffset >= c.assembledOffset &&
        matchOffset < c.assembledOffset + c.assembledLength
      );

      // Check if this pattern exists in the original component (pre-assembly)
      // If it does, it's a Stage 0 finding (already detectable). We only flag
      // patterns that emerge from assembly (cross-boundary or context-dependent).
      if (sourceComp) {
        const existsInSource = new RegExp(pattern.source, pattern.flags).test(sourceComp.content);
        if (existsInSource) continue; // Already detectable at Stage 0
      }

      findings.push({
        checkId: `LIFECYCLE-001`,
        name: 'Assembly-emergent injection',
        description: `Injection pattern "${name}" detected in assembled system prompt but not visible in individual components. This injection emerges only after components are concatenated.`,
        category: 'context-lifecycle',
        severity,
        passed: false,
        message: `Assembly-emergent injection: "${name}" at offset ${matchOffset}${sourceComp ? ` (near ${sourceComp.source})` : ''}`,
        fixable: false,
        file: sourceComp?.source,
        fix: 'Sanitize component content before assembly. Add injection detection between assembly stages.',
        guidance: 'This injection is invisible when scanning individual files but activates after components are concatenated into the system prompt. Implement assembly-stage sanitization.',
        attackClass: 'ASSEMBLY-INJECT',
      });
    }
  }

  // 2. Detect cross-component (semantic split) injections
  for (let i = 0; i < components.length - 1; i++) {
    const compA = components[i];
    const compB = components[i + 1];

    for (const { partA, partB, name } of SPLIT_INJECTION_PAIRS) {
      if (partA.test(compA.content) && partB.test(compB.content)) {
        const interaction: AssemblyInteraction = {
          components: [compA.source, compB.source],
          attackType: 'semanticSplit',
          assembledSegment: `...${compA.content.slice(-100)}${compB.content.slice(0, 100)}...`,
          confidence: 0.85,
        };
        interactions.push(interaction);

        findings.push({
          checkId: 'LIFECYCLE-002',
          name: 'Cross-component split injection',
          description: `Split injection "${name}" detected across component boundary: half in ${compA.source}, half in ${compB.source}. Each component appears benign alone.`,
          category: 'context-lifecycle',
          severity: 'critical',
          passed: false,
          message: `Split injection "${name}" spans ${compA.source} -> ${compB.source}`,
          fixable: false,
          file: compA.source,
          fix: 'Scan component boundaries for split patterns. Add boundary delimiters that prevent cross-component injection.',
          guidance: 'Split injections place half of a malicious instruction in one component and the other half in an adjacent component. When assembled, they form a complete injection that bypasses per-file scanning.',
          attackClass: 'ASSEMBLY-SPLIT',
        });
      }
    }
  }

  // 3. Detect context window displacement attacks
  // If any single component is disproportionately large, it may push
  // safety instructions (typically in soul/systemInstruction) out of
  // the effective attention window.
  const totalLength = assembled.length;
  const safetyComponents = components.filter(c => c.role === 'soul' || c.role === 'systemInstruction');
  const safetyLength = safetyComponents.reduce((sum, c) => sum + c.content.length, 0);

  for (const comp of components) {
    if (comp.role === 'soul' || comp.role === 'systemInstruction') continue;
    // Flag if a non-safety component is >60% of total assembled prompt
    if (comp.content.length > totalLength * 0.6 && totalLength > 2000) {
      interactions.push({
        components: [comp.source, ...(safetyComponents.map(c => c.source))],
        attackType: 'displacementAttack',
        assembledSegment: `Component ${comp.source} is ${comp.content.length} chars (${Math.round(comp.content.length / totalLength * 100)}% of assembled prompt)`,
        confidence: 0.7,
      });

      findings.push({
        checkId: 'LIFECYCLE-003',
        name: 'Context window displacement',
        description: `Component "${comp.source}" (${comp.role}) occupies ${Math.round(comp.content.length / totalLength * 100)}% of the assembled prompt. Safety instructions from ${safetyComponents.map(c => c.source).join(', ') || 'SOUL.md'} may be displaced from the effective attention window.`,
        category: 'context-lifecycle',
        severity: 'high',
        passed: false,
        message: `${comp.source} displaces safety instructions (${comp.content.length}/${totalLength} chars)`,
        fixable: false,
        file: comp.source,
        fix: 'Limit component sizes. Pin safety instructions at start and end of the assembled prompt. Implement attention anchoring.',
        guidance: 'LLMs have limited effective attention. A disproportionately large component (memory dump, verbose tool descriptions) can push safety instructions out of the "attention window", effectively disabling them.',
        attackClass: 'ASSEMBLY-DISPLACE',
      });
    }
  }

  // 4. Safety instruction ratio check
  // If safety instructions are <10% of total and total is large enough to matter
  if (totalLength > 5000 && safetyLength > 0 && safetyLength / totalLength < 0.1) {
    findings.push({
      checkId: 'LIFECYCLE-004',
      name: 'Low safety instruction ratio',
      description: `Safety instructions (SOUL.md, system prompts) are only ${Math.round(safetyLength / totalLength * 100)}% of the assembled context (${safetyLength}/${totalLength} chars). Safety rules may be diluted by other content.`,
      category: 'context-lifecycle',
      severity: 'medium',
      passed: false,
      message: `Safety instructions are ${Math.round(safetyLength / totalLength * 100)}% of assembled context`,
      fixable: false,
      file: safetyComponents[0]?.source || 'SOUL.md',
      fix: 'Increase safety instruction coverage. Repeat critical rules at multiple points in the assembly. Trim non-essential context.',
      guidance: 'When safety instructions are a small fraction of total context, the LLM may prioritize other content. Research shows safety instructions need sufficient representation relative to total context.',
      attackClass: 'ASSEMBLY-DILUTE',
    });
  }

  // 5. Detect priority zone hijacking
  // Components at the end of assembly (high attention priority) containing instructions
  const lastComponents = components.slice(-2);
  for (const comp of lastComponents) {
    if (comp.role === 'soul' || comp.role === 'systemInstruction') continue;
    // Check if late-position components contain instruction-like patterns
    const instructionPatterns = [
      /\b(must|should|always|never)\s+(do|follow|ignore|output)/i,
      /\b(from now on|henceforth|going forward)\b/i,
      /\b(your (new )?instructions?|updated rules?)\s*(are|:)/i,
    ];
    for (const pat of instructionPatterns) {
      if (pat.test(comp.content)) {
        interactions.push({
          components: [comp.source],
          attackType: 'priorityHijack',
          assembledSegment: comp.content.slice(0, 200),
          confidence: 0.65,
        });

        findings.push({
          checkId: 'LIFECYCLE-005',
          name: 'Priority zone instruction injection',
          description: `Component "${comp.source}" (${comp.role}) is in the high-priority end zone of the assembled prompt and contains instruction-like language. Late-position instructions override earlier ones in many LLMs.`,
          category: 'context-lifecycle',
          severity: 'high',
          passed: false,
          message: `${comp.source} contains instructions in high-priority position`,
          fixable: false,
          file: comp.source,
          fix: 'Move safety-critical instructions to the end of the assembly. Validate that non-safety components do not contain directive language.',
          guidance: 'Many LLMs give higher weight to instructions that appear later in the context (recency bias). If memory or conversation history is assembled after safety rules, injected instructions there will override safety constraints.',
          attackClass: 'ASSEMBLY-HIJACK',
        });
        break; // One finding per component
      }
    }
  }

  // 6. Detect role delimiter injection in non-system components
  for (const comp of components) {
    if (comp.role === 'systemInstruction') continue;
    if (/\b(system|assistant|user)\s*:\s*\n/i.test(comp.content)) {
      findings.push({
        checkId: 'LIFECYCLE-006',
        name: 'Role delimiter in non-system component',
        description: `Component "${comp.source}" (${comp.role}) contains role delimiters (system:/assistant:/user:) that could trick the LLM into treating injected text as a new conversation turn.`,
        category: 'context-lifecycle',
        severity: 'high',
        passed: false,
        message: `${comp.source} contains role delimiters in ${comp.role} component`,
        fixable: false,
        file: comp.source,
        fix: 'Strip or escape role delimiters from non-system components before assembly.',
        guidance: 'Role delimiters in memory entries, tool descriptions, or user preferences can trick the LLM into treating the following text as a new system instruction or assistant response, breaking the intended conversation structure.',
        attackClass: 'ASSEMBLY-DELIMITER',
      });
    }
  }

  // 7. Detect HTML/markdown comment hiding
  for (const comp of components) {
    const commentMatches = comp.content.matchAll(/<!--([\s\S]*?)-->/g);
    for (const match of commentMatches) {
      const commentContent = match[1];
      // Check if the comment contains instruction-like content
      if (/ignore|override|disregard|new\s+instructions?|system\s*:|you\s+are/i.test(commentContent)) {
        findings.push({
          checkId: 'LIFECYCLE-007',
          name: 'Hidden instructions in HTML comments',
          description: `Component "${comp.source}" contains HTML comments with instruction-like content. Some LLMs process HTML comment content, making this an injection vector.`,
          category: 'context-lifecycle',
          severity: 'high',
          passed: false,
          message: `${comp.source} has hidden instructions in HTML comments`,
          fixable: false,
          file: comp.source,
          fix: 'Strip HTML comments from all components before assembly, or sanitize comment content.',
          guidance: 'HTML comments are invisible to humans reading markdown but may be processed by LLMs during inference. Attackers hide instructions in comments within memory entries or tool descriptions.',
          attackClass: 'ASSEMBLY-HIDDEN',
        });
      }
    }
  }

  return { findings, interactions };
}

/**
 * Runs the full Stage 1 assembly scan.
 */
export async function scanAssembly(options: AssemblyScanOptions): Promise<{
  findings: SecurityFinding[];
  components: AssemblyComponent[];
  interactions: AssemblyInteraction[];
  assembledPrompt: string;
  tokenEstimate: number;
}> {
  const { targetDir, onProgress } = options;

  if (onProgress) onProgress('Discovering assembly components...');
  const rawComponents = await discoverComponents(targetDir);

  if (rawComponents.length === 0) {
    return {
      findings: [],
      components: [],
      interactions: [],
      assembledPrompt: '',
      tokenEstimate: 0,
    };
  }

  if (onProgress) onProgress(`Found ${rawComponents.length} assembly components, simulating assembly...`);
  const { assembled, components } = assemblePrompt(rawComponents);

  if (onProgress) onProgress('Scanning assembled prompt for lifecycle attacks...');
  const { findings, interactions } = scanAssembledPrompt(assembled, components);

  // Rough token estimate: ~4 chars per token for English
  const tokenEstimate = Math.ceil(assembled.length / 4);

  // 8. Check for assembly without safety instructions
  const hasSafety = components.some(c => c.role === 'soul' || c.role === 'systemInstruction');
  if (!hasSafety && components.length > 1) {
    findings.push({
      checkId: 'LIFECYCLE-008',
      name: 'Assembly without safety instructions',
      description: 'Agent assembles context from multiple components but has no SOUL.md or system prompt to establish safety boundaries.',
      category: 'context-lifecycle',
      severity: 'critical',
      passed: false,
      message: `${components.length} components assembled with no safety instructions`,
      fixable: false,
      file: components[0]?.source,
      fix: 'Add a SOUL.md or system prompt with safety boundaries. Run: hackmyagent scan-soul to generate one.',
      guidance: 'Without explicit safety instructions in the assembled context, the agent behavior is entirely determined by other components (memory, tools, history) which may be attacker-influenced.',
      attackClass: 'ASSEMBLY-NOSAFETY',
    });
  }

  // 9. Check for duplicate/conflicting instructions across components
  const instructionComponents = components.filter(c =>
    c.role === 'soul' || c.role === 'systemInstruction' || c.role === 'userPreference'
  );
  if (instructionComponents.length > 1) {
    // Simple heuristic: if multiple components define contradictory rules
    const rules = instructionComponents.map(c => ({
      source: c.source,
      hasAllow: /\b(allow|permit|enable)\b/i.test(c.content),
      hasDeny: /\b(deny|forbid|disable|never)\b/i.test(c.content),
    }));
    const hasConflict = rules.some(r => r.hasAllow) && rules.some(r => r.hasDeny);
    if (hasConflict) {
      const allowSources = rules.filter(r => r.hasAllow).map(r => r.source);
      const denySources = rules.filter(r => r.hasDeny).map(r => r.source);
      findings.push({
        checkId: 'LIFECYCLE-009',
        name: 'Conflicting assembly instructions',
        description: `Conflicting directives detected: permissive rules in ${allowSources.join(', ')} vs restrictive rules in ${denySources.join(', ')}. LLM behavior under contradiction is unpredictable.`,
        category: 'context-lifecycle',
        severity: 'medium',
        passed: false,
        message: `Conflicting instructions across ${instructionComponents.length} components`,
        fixable: false,
        file: instructionComponents[0].source,
        fix: 'Consolidate instructions into a single authoritative source (SOUL.md). Remove conflicting directives from other components.',
        guidance: 'When multiple components provide contradictory instructions, LLM behavior is unpredictable. An attacker can exploit this by injecting permissive rules in a lower-priority component that conflict with safety rules.',
        attackClass: 'ASSEMBLY-CONFLICT',
      });
    }
  }

  // 10. Token budget exhaustion risk
  const maxSafe = options.maxAssemblySize || 100_000; // ~25K tokens
  if (assembled.length > maxSafe) {
    findings.push({
      checkId: 'LIFECYCLE-010',
      name: 'Assembly exceeds safe context budget',
      description: `Assembled prompt is ${assembled.length} chars (~${tokenEstimate} tokens), exceeding safe budget of ${maxSafe} chars. Early components (safety instructions) may be truncated or compressed.`,
      category: 'context-lifecycle',
      severity: 'high',
      passed: false,
      message: `Assembled prompt: ${assembled.length} chars (~${tokenEstimate} tokens) exceeds ${maxSafe} char budget`,
      fixable: false,
      file: components[components.length - 1]?.source,
      fix: 'Reduce component sizes. Implement context pruning. Use summarization for memory/history. Prioritize safety-critical content.',
      guidance: 'When the assembled prompt exceeds the model context window, providers typically truncate from the beginning, which removes safety instructions. Even within the window, extreme length degrades instruction-following quality.',
      attackClass: 'ASSEMBLY-OVERFLOW',
    });
  }

  if (onProgress) onProgress(`Assembly scan complete: ${findings.length} findings from ${components.length} components`);

  return { findings, components, interactions, assembledPrompt: assembled, tokenEstimate };
}

/**
 * Wraps a Stage 0 ScanResult into a LifecycleScanResult.
 * This is backward-compatible: existing scan results become Stage 0 lifecycle results.
 */
export function toLifecycleResult(
  scanResult: import('../hardening/security-check').ScanResult,
  stage: import('../hardening/security-check').LifecycleStage = 0,
): LifecycleScanResult {
  return {
    stage,
    scanResult,
  };
}
