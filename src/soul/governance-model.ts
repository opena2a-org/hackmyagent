/**
 * `scan-soul --explain` printer (#163).
 *
 * Renders the 9-domain governance model that scan-soul evaluates, with no
 * scan side-effects. The data source is the existing CONTROL_DEFS array;
 * this file is a render-only consumer so changes to the domain set or
 * profile mapping in scanner.ts flow through automatically.
 */

import { CONTROL_DEFS, DOMAIN_ORDER, PROFILE_DOMAINS } from './scanner';
import type { AgentProfile, AgentTier } from './scanner';

const ALL_TIERS: AgentTier[] = ['BASIC', 'TOOL-USING', 'AGENTIC', 'MULTI-AGENT'];

const PROFILE_NAMES: AgentProfile[] = [
  'conversational',
  'code-assistant',
  'tool-agent',
  'autonomous',
  'orchestrator',
];

interface DomainSummary {
  id: number;
  name: string;
  controlCount: number;
  /** Distinct tiers across all controls in the domain (sorted by ALL_TIERS order). */
  tiers: AgentTier[];
  /** Profile names for which this domain is in scope. */
  profiles: AgentProfile[];
}

export function buildDomainSummaries(): DomainSummary[] {
  return DOMAIN_ORDER.map((domainName): DomainSummary => {
    const controls = CONTROL_DEFS.filter((c) => c.domain === domainName);
    if (controls.length === 0) {
      throw new Error(`scan-soul governance model: domain '${domainName}' has no controls in CONTROL_DEFS`);
    }
    const domainId = controls[0].domainId;

    const tierSet = new Set<AgentTier>();
    for (const c of controls) {
      for (const t of c.tiers) tierSet.add(t);
    }
    const tiers = ALL_TIERS.filter((t) => tierSet.has(t));

    const profiles = PROFILE_NAMES.filter((p) => PROFILE_DOMAINS[p].includes(domainId));

    return {
      id: domainId,
      name: domainName,
      controlCount: controls.length,
      tiers,
      profiles,
    };
  });
}

function formatTiers(tiers: AgentTier[]): string {
  return tiers.length === ALL_TIERS.length ? 'all tiers' : tiers.join(', ');
}

function formatProfiles(profiles: AgentProfile[]): string {
  return profiles.length === PROFILE_NAMES.length ? 'all profiles' : profiles.join(', ');
}

export function renderGovernanceModel(): string {
  const lines: string[] = [];
  const domains = buildDomainSummaries();
  const totalControls = domains.reduce((acc, d) => acc + d.controlCount, 0);

  lines.push(`scan-soul governance model: ${domains.length} domains, ${totalControls} controls`);
  lines.push('');
  lines.push('Domains are evaluated in the order shown. The agent profile (--profile)');
  lines.push('selects which domains apply; tiers narrow the controls within each domain.');
  lines.push('');

  for (const d of domains) {
    lines.push(`Domain ${d.id} — ${d.name}`);
    lines.push(`  Controls: ${d.controlCount}`);
    lines.push(`  Tiers:    ${formatTiers(d.tiers)}`);
    lines.push(`  Profiles: ${formatProfiles(d.profiles)}`);
    lines.push('');
  }

  lines.push('Profile → domain map:');
  for (const profile of PROFILE_NAMES) {
    const ids = PROFILE_DOMAINS[profile];
    const names = DOMAIN_ORDER.filter((dn) => {
      const c = CONTROL_DEFS.find((cd) => cd.domain === dn);
      return c ? ids.includes(c.domainId) : false;
    });
    lines.push(`  ${profile.padEnd(15)} → ${names.join(', ')}`);
  }
  lines.push('');
  lines.push('Run `hackmyagent scan-soul <directory>` to evaluate a target against this model.');

  return lines.join('\n');
}

export function printGovernanceModel(): void {
  process.stdout.write(renderGovernanceModel() + '\n');
}
