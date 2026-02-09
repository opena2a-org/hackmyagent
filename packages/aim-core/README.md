# @opena2a/aim-core

[![npm version](https://img.shields.io/npm/v/@opena2a/aim-core.svg)](https://www.npmjs.com/package/@opena2a/aim-core)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Lightweight agent identity library. Ed25519 identity, local audit log, capability policy, and trust scoring. No server required.

Part of the [HackMyAgent](https://github.com/opena2a-org/hackmyagent) security toolkit.

## Install

```bash
npm install @opena2a/aim-core
```

## Quick Start

```typescript
import { AIMCore } from '@opena2a/aim-core';

// Create or load an agent identity
const aim = new AIMCore({ agentId: 'my-agent' });

// Ed25519 identity (generated and persisted automatically)
const identity = await aim.getOrCreateIdentity();
console.log(identity.publicKey); // base64-encoded Ed25519 public key

// Sign and verify messages
const signature = aim.sign(Buffer.from('hello'));
const valid = aim.verify(Buffer.from('hello'), signature);

// Audit logging
aim.logEvent({ action: 'tool_call', target: 'read_file', details: { path: '/etc/config' } });
const events = aim.readAuditLog({ limit: 10 });

// Capability policy
aim.savePolicy({
  rules: [
    { capability: 'file:read', allow: true, paths: ['/data/*'] },
    { capability: 'file:write', allow: false },
  ]
});
const allowed = aim.checkCapability('file:read', { path: '/data/report.csv' });

// Trust scoring
const trust = aim.calculateTrust();
console.log(trust.score);   // 0.0 - 1.0
console.log(trust.factors); // { identity, audit, policy, behavior }
```

## API

| Function | Description |
|----------|-------------|
| `createIdentity()` | Generate a new Ed25519 keypair |
| `loadIdentity()` | Load an existing identity from disk |
| `getOrCreateIdentity()` | Load if exists, create if not |
| `sign(data)` | Sign data with the agent's private key |
| `verify(data, signature)` | Verify a signature against the public key |
| `logEvent(event)` | Append an event to the local audit log |
| `readAuditLog(options)` | Read audit log entries |
| `loadPolicy()` | Load capability policy from disk |
| `savePolicy(policy)` | Save capability policy to disk |
| `checkCapability(cap, ctx)` | Check if a capability is allowed |
| `calculateTrust()` | Compute a trust score based on identity, audit, and policy factors |

## License

Apache-2.0
