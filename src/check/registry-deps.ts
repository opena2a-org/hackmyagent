/**
 * The `Deps` line of the registry block `check` prints. Both render paths
 * (the registry-only block and the block beside a local scan) take its value
 * from `formatRegistryDeps`, so they cannot disagree on when it shows.
 *
 * The line shows only when the registry record counts at least one
 * dependency. A record with `totalDeps` of 0 or no `totalDeps` holds no
 * dependency to take a minimum over, so a `min trust` beside it states a
 * measurement that was not made; and 0 cannot be told apart from a count the
 * registry never recorded (`express` 5.3.0 lists 28 runtime dependencies on
 * npm, and its registry record counts 0).
 * The line is omitted rather than printed as `0 total`.
 */

export interface RegistryDependencySummary {
  totalDeps?: number;
  vulnerableDeps?: number;
  minTrustLevel?: number;
}

export interface RegistryDepsStyle {
  /** Wraps the `N vulnerable` segment, for colour. Identity by default. */
  vulnerable?: (text: string) => string;
  /** Joins the segments. ` · ` by default. */
  separator?: string;
}

/**
 * The value of the `Deps` line, or `null` when the line is omitted: no
 * dependency summary, or a `totalDeps` that is not a count above zero.
 */
export function formatRegistryDeps(
  deps: RegistryDependencySummary | undefined,
  style: RegistryDepsStyle = {},
): string | null {
  if (!deps) return null;
  const total = deps.totalDeps;
  if (typeof total !== 'number' || !Number.isFinite(total) || total <= 0) return null;
  const paintVulnerable = style.vulnerable ?? ((text: string) => text);
  const parts: string[] = [`${total} total`];
  if (typeof deps.vulnerableDeps === 'number' && deps.vulnerableDeps > 0) {
    parts.push(paintVulnerable(`${deps.vulnerableDeps} vulnerable`));
  }
  if (typeof deps.minTrustLevel === 'number') parts.push(`min trust ${deps.minTrustLevel}/4`);
  return parts.join(style.separator ?? ' · ');
}
