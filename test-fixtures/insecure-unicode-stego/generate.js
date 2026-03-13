#!/usr/bin/env node
/**
 * Generate test fixtures with actual invisible Unicode bytes.
 * These files cannot be created by normal text editing since the
 * characters are invisible.
 *
 * Usage: node generate.js
 *
 * Creates:
 *   - variation-selectors.js  (UNICODE-STEGO-001: contains U+FE00-FE0F)
 *   - tag-characters.js       (UNICODE-STEGO-001/004: contains U+E0100+ range)
 *   - tag-block-only.js       (UNICODE-STEGO-004: contains U+E0000-U+E00FF)
 *   - eval-hidden-payload.js  (UNICODE-STEGO-003: eval with invisible bytes)
 */

const fs = require('fs');
const path = require('path');

const outDir = __dirname;

// UNICODE-STEGO-001: Variation selectors (U+FE00-FE0F)
// UTF-8: EF B8 80 through EF B8 8F
const variationSelectorsContent = Buffer.concat([
  Buffer.from('// Looks like a normal file\nconst x = "hello'),
  // U+FE00 = EF B8 80
  Buffer.from([0xEF, 0xB8, 0x80]),
  // U+FE01 = EF B8 81
  Buffer.from([0xEF, 0xB8, 0x81]),
  // U+FE0F = EF B8 8F
  Buffer.from([0xEF, 0xB8, 0x8F]),
  Buffer.from('";\nconsole.log(x);\n'),
]);
fs.writeFileSync(path.join(outDir, 'variation-selectors.js'), variationSelectorsContent);

// UNICODE-STEGO-001/004: Tag characters (U+E0100-E01EF range)
// UTF-8: F3 A0 84 80 through F3 A0 87 AF
const tagCharsContent = Buffer.concat([
  Buffer.from('// Normal looking code\nconst y = "world'),
  // U+E0100 = F3 A0 84 80
  Buffer.from([0xF3, 0xA0, 0x84, 0x80]),
  // U+E0101 = F3 A0 84 81
  Buffer.from([0xF3, 0xA0, 0x84, 0x81]),
  Buffer.from('";\nconsole.log(y);\n'),
]);
fs.writeFileSync(path.join(outDir, 'tag-characters.js'), tagCharsContent);

// UNICODE-STEGO-004 only: Tag block characters (U+E0000-U+E00FF)
// UTF-8: F3 A0 80 80 through F3 A0 83 BF
const tagBlockContent = Buffer.concat([
  Buffer.from('// Innocent looking code\nconst z = "test'),
  // U+E0001 = F3 A0 80 81 (Language Tag)
  Buffer.from([0xF3, 0xA0, 0x80, 0x81]),
  // U+E0020 = F3 A0 80 A0 (Tag Space)
  Buffer.from([0xF3, 0xA0, 0x80, 0xA0]),
  Buffer.from('";\nconsole.log(z);\n'),
]);
fs.writeFileSync(path.join(outDir, 'tag-block-only.js'), tagBlockContent);

// UNICODE-STEGO-003: eval with hidden payload
// The string inside eval() has <5 visible chars but >100 bytes of invisible content
const invisiblePayload = [];
for (let i = 0; i < 40; i++) {
  // U+FE00 = EF B8 80 (3 bytes each, 40 * 3 = 120 bytes)
  invisiblePayload.push(0xEF, 0xB8, 0x80);
}
const evalContent = Buffer.concat([
  Buffer.from("// Looks harmless\neval('"),
  Buffer.from(invisiblePayload),
  Buffer.from("');\n"),
]);
fs.writeFileSync(path.join(outDir, 'eval-hidden-payload.js'), evalContent);

console.log('Generated test fixtures:');
console.log('  - variation-selectors.js  (UNICODE-STEGO-001)');
console.log('  - tag-characters.js       (UNICODE-STEGO-001/004)');
console.log('  - tag-block-only.js       (UNICODE-STEGO-004)');
console.log('  - eval-hidden-payload.js  (UNICODE-STEGO-003)');
