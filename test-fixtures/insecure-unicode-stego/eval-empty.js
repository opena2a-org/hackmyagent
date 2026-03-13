// Test fixture for UNICODE-STEGO-003: Eval on Empty String
// In a real attack, the string argument to eval() would contain invisible
// Unicode characters (variation selectors, tag characters) that encode
// a malicious payload. The string appears empty to the naked eye but
// has a large byte footprint.
//
// This file is a placeholder - the actual test creates files with embedded
// invisible bytes programmatically since they cannot be represented in
// normal source code.

// Example of what the attack looks like (simplified):
// eval('') <-- the quotes contain hundreds of invisible codepoints

module.exports = {};
