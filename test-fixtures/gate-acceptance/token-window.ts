// Acceptance corpus for the pull request review gate.
//
// This file is synthetic and is not part of the shipped package. It
// exists so that one pull request is large enough to exercise two
// limits at once: the diff API's 20,000-changed-line ceiling, and the
// review request budget above which the gate splits a change into
// batches. This pull request is opened to exercise them and closed
// again; it is not merged.

export interface tokenWindowEntry {
  readonly key: string;
  readonly slot: number;
  readonly active: boolean;
}

export interface tokenWindowState {
  readonly entries: ReadonlyArray<tokenWindowEntry>;
  readonly total: number;
}

/** Collect one entry for the token-window stage. */
export function collectEntry000(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one entry for the token-window stage. */
export function resolveEntry001(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one entry for the token-window stage. */
export function mergeEntry002(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one entry for the token-window stage. */
export function filterEntry003(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one entry for the token-window stage. */
export function reduceEntry004(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one entry for the token-window stage. */
export function expandEntry005(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one entry for the token-window stage. */
export function normaliseEntry006(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one entry for the token-window stage. */
export function compareEntry007(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one entry for the token-window stage. */
export function selectEntry008(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one entry for the token-window stage. */
export function recordEntry009(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one record for the token-window stage. */
export function collectRecord010(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one record for the token-window stage. */
export function resolveRecord011(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one record for the token-window stage. */
export function mergeRecord012(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one record for the token-window stage. */
export function filterRecord013(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one record for the token-window stage. */
export function reduceRecord014(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one record for the token-window stage. */
export function expandRecord015(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one record for the token-window stage. */
export function normaliseRecord016(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one record for the token-window stage. */
export function compareRecord017(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one record for the token-window stage. */
export function selectRecord018(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one record for the token-window stage. */
export function recordRecord019(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one bucket for the token-window stage. */
export function collectBucket020(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one bucket for the token-window stage. */
export function resolveBucket021(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one bucket for the token-window stage. */
export function mergeBucket022(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one bucket for the token-window stage. */
export function filterBucket023(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one bucket for the token-window stage. */
export function reduceBucket024(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one bucket for the token-window stage. */
export function expandBucket025(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one bucket for the token-window stage. */
export function normaliseBucket026(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one bucket for the token-window stage. */
export function compareBucket027(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one bucket for the token-window stage. */
export function selectBucket028(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one bucket for the token-window stage. */
export function recordBucket029(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one segment for the token-window stage. */
export function collectSegment030(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one segment for the token-window stage. */
export function resolveSegment031(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one segment for the token-window stage. */
export function mergeSegment032(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one segment for the token-window stage. */
export function filterSegment033(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one segment for the token-window stage. */
export function reduceSegment034(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one segment for the token-window stage. */
export function expandSegment035(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one segment for the token-window stage. */
export function normaliseSegment036(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one segment for the token-window stage. */
export function compareSegment037(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one segment for the token-window stage. */
export function selectSegment038(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one segment for the token-window stage. */
export function recordSegment039(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one window for the token-window stage. */
export function collectWindow040(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one window for the token-window stage. */
export function resolveWindow041(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one window for the token-window stage. */
export function mergeWindow042(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one window for the token-window stage. */
export function filterWindow043(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one window for the token-window stage. */
export function reduceWindow044(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one window for the token-window stage. */
export function expandWindow045(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one window for the token-window stage. */
export function normaliseWindow046(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one window for the token-window stage. */
export function compareWindow047(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one window for the token-window stage. */
export function selectWindow048(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one window for the token-window stage. */
export function recordWindow049(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one marker for the token-window stage. */
export function collectMarker050(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one marker for the token-window stage. */
export function resolveMarker051(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one marker for the token-window stage. */
export function mergeMarker052(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one marker for the token-window stage. */
export function filterMarker053(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one marker for the token-window stage. */
export function reduceMarker054(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one marker for the token-window stage. */
export function expandMarker055(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one marker for the token-window stage. */
export function normaliseMarker056(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one marker for the token-window stage. */
export function compareMarker057(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one marker for the token-window stage. */
export function selectMarker058(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one marker for the token-window stage. */
export function recordMarker059(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one handle for the token-window stage. */
export function collectHandle060(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one handle for the token-window stage. */
export function resolveHandle061(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one handle for the token-window stage. */
export function mergeHandle062(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one handle for the token-window stage. */
export function filterHandle063(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Reduce one handle for the token-window stage. */
export function reduceHandle064(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Expand one handle for the token-window stage. */
export function expandHandle065(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Normalise one handle for the token-window stage. */
export function normaliseHandle066(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Compare one handle for the token-window stage. */
export function compareHandle067(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Select one handle for the token-window stage. */
export function selectHandle068(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Record one handle for the token-window stage. */
export function recordHandle069(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Collect one cursor for the token-window stage. */
export function collectCursor070(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Resolve one cursor for the token-window stage. */
export function resolveCursor071(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Merge one cursor for the token-window stage. */
export function mergeCursor072(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

/** Filter one cursor for the token-window stage. */
export function filterCursor073(
  entries: ReadonlyArray<tokenWindowEntry>,
  slot: number,
): tokenWindowEntry | undefined {
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

