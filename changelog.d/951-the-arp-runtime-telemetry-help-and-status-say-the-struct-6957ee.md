---
type: fixed
issue: 951
---
#### The ARP runtime telemetry help and status say the structural-signature channel is off until turned on (#951)

- The `@opena2a/aim-sdk` this program is built on leaves structural-signature
  telemetry off until `AIM_TELEMETRY=1` or `signatureTelemetry.enabled: true`
  turns it on, but the ARP runtime program (`dist/arp/cli/index.js`) described
  it as on by default. `telemetry --help` said "Structural signatures are
  DEFAULT-ON"; `telemetry status` on a machine where nobody had opted out
  printed `State: OFF (opted out)` and `Opted out by: local opt-out marker`
  with no marker present; and `telemetry opt-in` printed "Structural signature
  telemetry is ON (default)" while the channel stayed off.
- `telemetry status` now prints `State: OFF (not turned on)` and
  `Turn on with: AIM_TELEMETRY=1 (or signatureTelemetry.enabled: true)` in
  that case, the same state the SDK's `aim-arp telemetry status` prints;
  `ON` when the channel is on; and `OFF (opted out)` only for an opt-out,
  naming the one that applies: the config, `OPENA2A_TELEMETRY=off`,
  `OPENA2A_TELEMETRY_OPTOUT`, `ARP_TELEMETRY_DISABLED` or the marker.
- `telemetry opt-in` now says the channel stays off until it is turned on, and
  the help says `opt-in` removes the marker without turning the channel on.
  `telemetry register` on a channel nobody turned on notes that no reports
  will be sent even after approval.
