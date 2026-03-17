/**
 * Context-Aware Skill Section Analysis
 *
 * Classifies lines in SKILL.md files by section type to reduce false positives.
 * Prose mentions of "chrome" or ".env" are not attacks -- only code blocks
 * and command blocks are real signals for SKILL-010/011/012.
 */

export type SkillSection = 'frontmatter' | 'prose' | 'codeblock' | 'command';

/**
 * Classify what section type a given line index falls within.
 * Parses the full content to determine context.
 */
export function classifySkillSection(content: string, lineIndex: number): SkillSection {
  const lines = content.split('\n');
  if (lineIndex < 0 || lineIndex >= lines.length) {
    return 'prose';
  }

  let inFrontmatter = false;
  let frontmatterCount = 0;
  let inCodeBlock = false;

  for (let i = 0; i <= lineIndex; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Track frontmatter (--- delimiters at start of file)
    if (trimmed === '---' || trimmed === '---\r') {
      if (i === 0 || (frontmatterCount === 0 && i <= 1)) {
        inFrontmatter = true;
        frontmatterCount++;
        if (i === lineIndex) return 'frontmatter';
        continue;
      } else if (inFrontmatter && frontmatterCount === 1) {
        frontmatterCount++;
        inFrontmatter = false;
        if (i === lineIndex) return 'frontmatter';
        continue;
      }
    }

    if (inFrontmatter) {
      if (i === lineIndex) return 'frontmatter';
      continue;
    }

    // Track fenced code blocks (``` or ~~~)
    if (/^(`{3,}|~{3,})/.test(trimmed)) {
      inCodeBlock = !inCodeBlock;
      if (i === lineIndex) return inCodeBlock ? 'codeblock' : 'codeblock';
      continue;
    }

    if (inCodeBlock) {
      if (i === lineIndex) return 'codeblock';
      continue;
    }

    // Command lines: start with $ or >
    if (/^\s*[$>]\s+\S/.test(line)) {
      if (i === lineIndex) return 'command';
      continue;
    }

    // Indented code block: 4+ spaces after a blank line
    if (/^ {4,}\S/.test(line) && i > 0 && lines[i - 1].trim() === '') {
      if (i === lineIndex) return 'command';
      continue;
    }
  }

  if (inFrontmatter) return 'frontmatter';
  if (inCodeBlock) return 'codeblock';
  return 'prose';
}

/**
 * Determine if a pattern match is likely a false positive based on section context.
 *
 * For SKILL-010/011/012, matches in prose or frontmatter (including capabilities/permissions
 * declarations) are treated as false positives. Only code blocks and command blocks
 * are real signals for these checks.
 */
export function isLikelyFalsePositive(
  checkId: string,
  line: string,
  section: SkillSection,
  fullContent: string
): boolean {
  const contextSensitiveChecks = ['SKILL-010', 'SKILL-011', 'SKILL-012'];

  if (!contextSensitiveChecks.includes(checkId)) {
    return false;
  }

  // Matches inside capabilities/permissions YAML blocks are declarations, not attacks
  if (section === 'frontmatter') {
    return true;
  }

  // Prose mentions are false positives for these checks
  if (section === 'prose') {
    return true;
  }

  // Check if line is inside a permissions: or capabilities: YAML block in body
  // (some skills declare permissions outside frontmatter in structured blocks)
  const trimmedLine = line.trim();
  if (/^(permissions|capabilities)\s*:/.test(trimmedLine)) {
    return true;
  }

  // Check if the line is a YAML list item under permissions/capabilities
  if (/^\s*-\s+/.test(line)) {
    const lines = fullContent.split('\n');
    const lineIdx = lines.indexOf(line);
    if (lineIdx >= 0) {
      // Look backwards for a permissions:/capabilities: header
      for (let i = lineIdx - 1; i >= 0 && i >= lineIdx - 10; i--) {
        const prevLine = lines[i].trim();
        if (/^(permissions|capabilities)\s*:/.test(prevLine)) {
          return true;
        }
        // If we hit a non-indented, non-list line, stop looking
        if (prevLine !== '' && !prevLine.startsWith('-') && !prevLine.startsWith(' ')) {
          break;
        }
      }
    }
  }

  // Code blocks and command blocks are real signals
  return false;
}
