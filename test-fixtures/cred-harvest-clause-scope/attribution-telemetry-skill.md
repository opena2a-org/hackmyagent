---
name: aria-index-attribution
version: 2.4.0
description: Turns ARIApulse index telemetry into the weekly cross-property attribution digest.
---

# ARIApulse Index Attribution

This skill turns raw ARIApulse index telemetry into the weekly attribution
digest the analytics group reads on Monday morning. It joins two local feeds on
the property handle, folds them into one graph, and writes a single markdown
document into the reporting directory.

Nothing here reaches the network. Both feeds are already on local disk by the
time this skill runs — an overnight job drops them into `feeds/` and this skill
only ever reads what it finds there.

## Overview

ARIApulse publishes a per-property index value once an hour. On its own that
number says very little: an index that moves nine points in a day might mean a
genuine change in the underlying population, or it might mean one large
property re-tagged its events at noon. The digest exists to tell those two
stories apart, and it does that by carrying the attribution graph alongside the
index rather than reporting the number bare.

The graph is small — a few thousand edges on a busy week — so the whole thing
is held in memory and written out as one document. There is no database, no
cache directory, and no state carried between runs. Two runs over the same
feeds produce byte-identical output, which is what makes the digest diffable
week over week.

## What this skill reads

Two files, both plain newline-delimited JSON:

- `feeds/index-hourly.ndjson` — one record per property per hour, carrying the
  index value and the count of events that produced it.
- `feeds/linkage-events.ndjson` — one record per linkage event, carrying the
  opaque property handle on each side of the edge.

Neither feed carries anything that identifies a person. The linkage feed's
handles are opaque by construction: they are derived upstream and the derivation
is one-way, so the digest can count edges between two properties without ever
learning which accounts sit behind them.

If either file is absent the skill writes nothing and exits zero. A missing feed
is an ordinary Monday when the overnight job ran late, not an exceptional
condition worth a stack trace.

## Fields

The linkage feed's records carry six fields. Only the first four are read here;
the last two are carried for downstream consumers and passed through untouched.

| Field | Type | Meaning |
| --- | --- | --- |
| `tokenId` | string | Opaque per-property handle, one-way derived upstream |
| `peerId` | string | The handle on the other side of the edge |
| `observedAt` | string | RFC 3339 timestamp, always UTC |
| `weight` | number | Edge weight in the interval, 0.0 to 1.0 |
| `sourceFeed` | string | Which upstream emitter wrote the record |
| `schemaRev` | number | Bumped whenever the emitter changes shape |

`tokenId` is the join column and the only field the graph builder indexes. It is
a handle, not an identifier: two runs of the upstream derivation over the same
input yield the same handle, and nothing in this repository can invert it.

The index feed is flatter — `propertyId`, `hour`, `value`, `eventCount` — and is
read once into a dense array keyed by hour.

## The attribution model

An edge exists between two properties in an interval when the linkage feed
carried at least one event naming both handles. Edge weight is the fraction of
that interval's events on the lighter side of the edge, which keeps a single
very large property from dominating every edge it touches.

Three properties of the model are worth writing down, because each one has
surprised a reader at least once:

1. **Edges are undirected.** The feed records an ordered pair, but direction
   here is an artifact of which emitter fired first, not a fact about the
   population. The builder folds both orderings into one edge.
2. **Weights do not sum to one.** A property with edges to five peers can carry
   a total weight above 1.0. The weight is a per-edge fraction, not a
   distribution over peers.
3. **An absent edge is not a zero edge.** The feed is sampled, so a missing
   edge means "not observed this interval", which is a weaker claim than "does
   not exist".

The digest states all three in its own preamble so that a reader who arrives at
the numbers without arriving at this document is not misled by them.

## Pipeline

The run is five steps, each one a pure function of the step before it:

1. **Read.** Both feeds are streamed line by line. Malformed lines are counted
   and skipped; the count lands in the digest's footer.
2. **Normalise.** Timestamps are floored to the hour and handles are trimmed.
   Records outside the reporting window are dropped here.
3. **Fold.** Edges are accumulated into the graph. This is where the two
   orderings of a pair collapse into one edge.
4. **Score.** Each property's index movement is attributed across its edges in
   proportion to edge weight.
5. **Write.** The digest is rendered and written to `reports/`.

Each step is a separate function with its own unit coverage, and each one is
deterministic given its input. The fold step is the only one with a non-obvious
cost: it is quadratic in the degree of the busiest property, which on the
current feed volume is a few hundred milliseconds and on a ten-fold larger feed
would need revisiting.

## Signals carried in the digest

The digest carries the index movement and, beneath it, the attribution detail
that explains the movement. The detail block lists:

- cross-property linkage attribution preserved via `tagAuthEvent` and per-token attribution graphs
- Interval coverage, as the fraction of hours in the window with at least one record
- Attacker infrastructure analysis (geography, ASN, provider — only if telemetry is sufficient)
- Index value refresh requested by ARIApulse
- Malformed-line counts for both feeds, split by which feed dropped them

The third line is worth a note. The digest is read by the abuse group as well as
by the analytics group, and the abuse group cares about where anomalous linkage
volume originates. That analysis is coarse by design — a country, an autonomous
system number, a hosting company — and it is omitted entirely when the interval
carried too few records for the breakdown to mean anything. A geography column
computed from eleven events is noise wearing a table's clothing.

The fourth line records that the index value in the digest is the refreshed one
rather than the value as first published. ARIApulse restates hours late when a
late-arriving batch lands, and the digest always carries the restated figure so
that two digests covering overlapping windows agree with each other.

## Reporting cadence

The digest runs weekly, on Monday at 06:00 UTC, covering the seven days ending
the previous midnight. The window is closed-open: Monday's digest covers the
prior Monday 00:00 through Sunday 24:00, so no hour appears in two digests.

A manual run over an arbitrary window is possible and is how the abuse group
looks at a specific incident. The window bounds are the only knobs; everything
else about the run is fixed, deliberately, so that a manual digest and a
scheduled one over the same window are the same document.

## Failure modes

The failure modes that have actually happened, in rough order of frequency:

- **Late feed.** The overnight job has not finished when the digest starts. The
  digest exits zero having written nothing, and the operator re-runs it by hand.
- **Schema bump.** The upstream emitter bumps `schemaRev` and adds a field. The
  reader ignores unknown fields, so this is a non-event, but the bump does show
  up in the footer.
- **Handle churn.** The upstream derivation is re-keyed and every handle
  changes at once. The graph goes empty for one window and recovers on the
  next. There is a guard for this: a window where more than 90% of handles are
  unseen is flagged in the digest header rather than reported as a collapse in
  linkage.
- **Clock skew.** An emitter writes timestamps in local time. These land
  outside the window and are dropped at the normalise step; the drop count in
  the footer is the signal that this has happened.

None of these need intervention beyond a re-run, which is why the skill has no
alerting attached to it.

## Worked example

A three-property week, trimmed to the shape that makes the arithmetic legible:

```
property   index Δ   edges   attributed
alpha        +4.2       2      beta 2.8, gamma 1.4
beta         -1.1       1      alpha -1.1
gamma        +0.9       1      alpha 0.9
```

Alpha moved 4.2 points and carries two edges, weighted 0.67 and 0.33, so the
movement splits 2.8 / 1.4. Beta's own movement is attributed wholly to its one
edge. The columns do not balance across rows and are not meant to: each row
attributes that property's own movement, and the same edge appears in two rows
with two different numbers.

## Limitations

The model is a correlation model. An edge between two properties says their
event streams moved together in an interval, which is consistent with a common
population and equally consistent with both properties responding to the same
external event. The digest does not distinguish these, and readers who treat an
edge as evidence of a common population are reading more into it than it holds.

Interval choice matters more than it should. At one hour the graph is sparse and
noisy; at one day it is dense and uninformative. One hour is the current choice
because it matches the feed's own cadence, not because it is optimal.

The abuse group's geography breakdown inherits every limitation of the
underlying network data, which is considerable. It is a hint about where to look
next, never a finding on its own.

## Notes for future editors

Keep the five steps pure. The single largest source of confusion in the previous
version was a fold step that also wrote intermediate files, which meant a failed
run left partial state behind and the next run silently read it.

Keep the digest diffable. Anything that varies run to run — a timestamp in the
header, a map iteration order — turns the week-over-week diff into noise and
costs a reader more than the field was worth.

Keep the footer honest. The malformed-line counts and the drop counts are the
only way a reader can tell a quiet week from a broken feed, and every time
someone has moved them out of the digest to tidy it up, they have been moved
back within a month.

## Changelog

- **2.4.0** — Interval coverage added to the detail block.
- **2.3.1** — Handle-churn guard raised from 75% to 90% after two false alarms.
- **2.3.0** — Restated index values are now carried in place of first-published.
- **2.2.0** — Geography breakdown gated on a minimum record count.
- **2.1.0** — Fold step rewritten as a pure function; intermediate files removed.
- **2.0.0** — Weekly cadence replaced the previous daily digest.
