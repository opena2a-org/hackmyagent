/**
 * Terminal-side renderer for `RenderedRichBlock` — applies HMA's
 * chalk palette to the structured tone-tagged output produced by
 * `renderCheckRichBlock` from `@opena2a/cli-ui`.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3).
 *
 * cli-ui returns tone-tagged lines (no chalk imports); this module
 * paints them in HMA's terminal style and writes to stdout. ai-trust
 * has a parallel module — the dividers, indents, and labels are
 * byte-identical across CLIs (parity F12 / F13).
 */

import type { RenderedRichBlock } from "@opena2a/cli-ui";

type ColorFn = (s: string) => string;

/**
 * Color palette interface — kept structural so callers can pass HMA's
 * existing `colors` object without dragging chalk into this module's
 * imports.
 */
export interface RichBlockPalette {
  reset: string;
  dim: ColorFn;
  bold: ColorFn;
  white: ColorFn;
  green: ColorFn;
  yellow: ColorFn;
  red: ColorFn;
  brightRed: ColorFn;
  cyan: ColorFn;
}

export interface PrintRichBlockOptions {
  palette: RichBlockPalette;
  /** Width of section divider rule. Defaults to 62 chars. */
  dividerWidth?: number;
}

/**
 * Print the rich block to stdout. The input is the typed render output
 * from cli-ui; this function only translates tones to ANSI and writes.
 */
export function printRichBlock(
  block: RenderedRichBlock,
  options: PrintRichBlockOptions,
): void {
  const { palette } = options;
  const dividerWidth = options.dividerWidth ?? 62;

  // -- Header --------------------------------------------------------------
  console.log();
  console.log(`  ${palette.bold(palette.white(block.header.name))}`);
  for (const line of block.header.metaLines) {
    console.log(`  ${paintTone(line.text, line.tone, palette)}`);
  }

  // -- Sections ------------------------------------------------------------
  for (const section of block.sections) {
    printDivider(section.divider, section.dividerTone, palette, dividerWidth);
    for (const line of section.lines) {
      const indent = "  " + "  ".repeat(line.indent);
      console.log(`${indent}${paintTone(line.text, line.tone, palette)}`);
    }
  }
  console.log();
}

function printDivider(
  label: string,
  tone: RenderedRichBlock["sections"][number]["dividerTone"],
  palette: RichBlockPalette,
  width: number,
): void {
  const dashCount = Math.max(1, width - label.length - 4);
  const labelPainted = paintTone(label, tone, palette);
  const dashesLeft = palette.dim("──");
  const dashesRight = palette.dim("─".repeat(dashCount));
  console.log();
  console.log(`  ${dashesLeft} ${palette.bold(labelPainted)} ${dashesRight}`);
}

function paintTone(
  text: string,
  tone: RenderedRichBlock["sections"][number]["lines"][number]["tone"],
  palette: RichBlockPalette,
): string {
  switch (tone) {
    case "good":
      return palette.green(text);
    case "warning":
      return palette.yellow(text);
    case "critical":
      return palette.brightRed(text);
    case "dim":
      return palette.dim(text);
    case "default":
    default:
      return text;
  }
}
