/**
 * ARP (Agent Runtime Protection) — thin re-export.
 *
 * The runtime-protection engine lives in the AIM agent-side SDK
 * (`@opena2a/aim-sdk/arp`): event engine, runtime twin, intelligence
 * coordinator, monitors, interceptors, enforcement kill-switch, proxy, and
 * the telemetry producers. hackmyagent keeps the scan-time surface (static
 * scanner, hardening rules, artifact parsing, NanoMind artifact
 * classification) and re-exports the runtime module here so existing
 * consumers of `hackmyagent/arp` — including the published `arp-guard`
 * package — keep working unchanged.
 *
 * Boundary: scan with hackmyagent (CI / pre-deploy); protect at runtime
 * with the AIM SDK (in-process).
 */
export * from '@opena2a/aim-sdk/arp';
