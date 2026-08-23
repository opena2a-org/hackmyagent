// Acceptance corpus for the pull request review gate.
//
// This file is synthetic and is not part of the shipped package. It
// exists so that one pull request is large enough to exercise two
// limits at once: the diff API's 20,000-changed-line ceiling, and the
// review request budget above which the gate splits a change into
// batches. This pull request is opened to exercise them and closed
// again; it is not merged.

export interface cacheKeysEntry {
  readonly key: string;
  readonly slot: number;
  readonly active: boolean;
}

export interface cacheKeysState {
  readonly entries: ReadonlyArray<cacheKeysEntry>;
  readonly total: number;
}

/** Collect one entry for the cache-keys stage. */
export function collectEntry000(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one entry for the cache-keys stage. */
export function resolveEntry001(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one entry for the cache-keys stage. */
export function mergeEntry002(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one entry for the cache-keys stage. */
export function filterEntry003(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one entry for the cache-keys stage. */
export function reduceEntry004(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one entry for the cache-keys stage. */
export function expandEntry005(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one entry for the cache-keys stage. */
export function normaliseEntry006(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one entry for the cache-keys stage. */
export function compareEntry007(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one entry for the cache-keys stage. */
export function selectEntry008(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one entry for the cache-keys stage. */
export function recordEntry009(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one record for the cache-keys stage. */
export function collectRecord010(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one record for the cache-keys stage. */
export function resolveRecord011(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one record for the cache-keys stage. */
export function mergeRecord012(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one record for the cache-keys stage. */
export function filterRecord013(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one record for the cache-keys stage. */
export function reduceRecord014(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one record for the cache-keys stage. */
export function expandRecord015(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one record for the cache-keys stage. */
export function normaliseRecord016(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one record for the cache-keys stage. */
export function compareRecord017(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one record for the cache-keys stage. */
export function selectRecord018(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one record for the cache-keys stage. */
export function recordRecord019(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one bucket for the cache-keys stage. */
export function collectBucket020(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one bucket for the cache-keys stage. */
export function resolveBucket021(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one bucket for the cache-keys stage. */
export function mergeBucket022(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one bucket for the cache-keys stage. */
export function filterBucket023(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one bucket for the cache-keys stage. */
export function reduceBucket024(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one bucket for the cache-keys stage. */
export function expandBucket025(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one bucket for the cache-keys stage. */
export function normaliseBucket026(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one bucket for the cache-keys stage. */
export function compareBucket027(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one bucket for the cache-keys stage. */
export function selectBucket028(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one bucket for the cache-keys stage. */
export function recordBucket029(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one segment for the cache-keys stage. */
export function collectSegment030(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one segment for the cache-keys stage. */
export function resolveSegment031(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one segment for the cache-keys stage. */
export function mergeSegment032(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one segment for the cache-keys stage. */
export function filterSegment033(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one segment for the cache-keys stage. */
export function reduceSegment034(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one segment for the cache-keys stage. */
export function expandSegment035(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one segment for the cache-keys stage. */
export function normaliseSegment036(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one segment for the cache-keys stage. */
export function compareSegment037(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one segment for the cache-keys stage. */
export function selectSegment038(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one segment for the cache-keys stage. */
export function recordSegment039(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one window for the cache-keys stage. */
export function collectWindow040(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one window for the cache-keys stage. */
export function resolveWindow041(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one window for the cache-keys stage. */
export function mergeWindow042(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one window for the cache-keys stage. */
export function filterWindow043(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one window for the cache-keys stage. */
export function reduceWindow044(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one window for the cache-keys stage. */
export function expandWindow045(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one window for the cache-keys stage. */
export function normaliseWindow046(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one window for the cache-keys stage. */
export function compareWindow047(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one window for the cache-keys stage. */
export function selectWindow048(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one window for the cache-keys stage. */
export function recordWindow049(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one marker for the cache-keys stage. */
export function collectMarker050(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one marker for the cache-keys stage. */
export function resolveMarker051(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one marker for the cache-keys stage. */
export function mergeMarker052(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one marker for the cache-keys stage. */
export function filterMarker053(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one marker for the cache-keys stage. */
export function reduceMarker054(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one marker for the cache-keys stage. */
export function expandMarker055(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one marker for the cache-keys stage. */
export function normaliseMarker056(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one marker for the cache-keys stage. */
export function compareMarker057(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one marker for the cache-keys stage. */
export function selectMarker058(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one marker for the cache-keys stage. */
export function recordMarker059(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one handle for the cache-keys stage. */
export function collectHandle060(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one handle for the cache-keys stage. */
export function resolveHandle061(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one handle for the cache-keys stage. */
export function mergeHandle062(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one handle for the cache-keys stage. */
export function filterHandle063(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Reduce one handle for the cache-keys stage. */
export function reduceHandle064(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Expand one handle for the cache-keys stage. */
export function expandHandle065(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Normalise one handle for the cache-keys stage. */
export function normaliseHandle066(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Compare one handle for the cache-keys stage. */
export function compareHandle067(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Select one handle for the cache-keys stage. */
export function selectHandle068(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Record one handle for the cache-keys stage. */
export function recordHandle069(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Collect one cursor for the cache-keys stage. */
export function collectCursor070(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Resolve one cursor for the cache-keys stage. */
export function resolveCursor071(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Merge one cursor for the cache-keys stage. */
export function mergeCursor072(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

/** Filter one cursor for the cache-keys stage. */
export function filterCursor073(
  entries: ReadonlyArray<cacheKeysEntry>,
  slot: number,
): cacheKeysEntry | undefined {
  if (slot < 0) {
    return undefined;
  }
  for (const entry of entries) {
    if (entry.slot !== slot) {
      continue;
    }
    if (!entry.active) {
      continue;
    }
    return entry;
  }
  return undefined;
}

