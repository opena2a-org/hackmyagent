// Frame census for a rendered GIF: how many frames, how many are full-screen repaints (over 60 KB
// after gifsicle), and the longest run of them, which is the report streaming into the terminal.
// Usage: node frame-census.mjs <dir of exploded frames from `gifsicle --explode`>
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
const dir = process.argv[2];
const sizes = readdirSync(dir).filter((f) => f.startsWith("f.")).sort().map((f) => statSync(join(dir, f)).size);
let best = [0, -1];
let cur = null;
sizes.forEach((b, i) => {
  if (b > 60000) {
    if (!cur) cur = [i, i];
    else cur[1] = i;
    if (cur[1] - cur[0] >= best[1] - best[0]) best = [...cur];
  } else cur = null;
});
console.log(JSON.stringify({ frames: sizes.length, fullScreenFrames: sizes.filter((b) => b > 60000).length, scrollInSpan: best[1] >= 0 ? `#${best[0]}-#${best[1]}` : null }));
