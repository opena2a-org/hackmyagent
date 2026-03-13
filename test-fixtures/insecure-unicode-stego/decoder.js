// Test fixture for UNICODE-STEGO-002: GlassWorm Decoder Pattern
// This file contains .codePointAt() usage with variation selector hex literals
// which is the decoder half of a GlassWorm attack

function decode(input) {
  const result = [];
  for (let i = 0; i < input.length; i++) {
    const cp = input.codePointAt(i);
    if (cp >= 0xFE00 && cp <= 0xFE0F) {
      result.push(cp - 0xFE00);
    }
    if (cp >= 0xE0100) {
      result.push(cp - 0xE0100);
    }
  }
  return String.fromCharCode(...result);
}

module.exports = { decode };
