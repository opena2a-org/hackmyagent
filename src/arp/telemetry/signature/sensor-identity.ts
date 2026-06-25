/**
 * Sensor identity (G5 producer half) — the Ed25519 key that signs every report.
 *
 * The signing key is generated once and persisted 0600; the private key NEVER
 * leaves the device. In G5 the corresponding PUBLIC key is bound to a registered
 * `telemetry:sensor` service account (server-side, already shipped) so verified
 * reports earn reputation weight. Until a sensor is registered, reports still
 * sign and ingest, at the low unverified weight.
 *
 * publicKey and signature are transmitted as lowercase hex; the registry's
 * normalizeToBase64 hex-decodes them before ed25519.Verify, so hex round-trips.
 */

import * as ed25519 from '@noble/ed25519';
import { randomUUID } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { opena2aHome, homePath, SENSOR_KEY_FILE, SENSOR_ID_FILE } from './paths';

function ensureHome(): void {
  const home = opena2aHome();
  if (!existsSync(home)) mkdirSync(home, { recursive: true });
}

/** Load (or first-time generate) the 32-byte Ed25519 private key, persisted 0600. */
export function loadSensorPrivateKey(): Uint8Array {
  const p = homePath(SENSOR_KEY_FILE);
  if (existsSync(p)) {
    const hex = readFileSync(p, 'utf8').trim();
    const buf = Buffer.from(hex, 'hex');
    if (buf.length === 32) return new Uint8Array(buf);
  }
  ensureHome();
  const priv = ed25519.utils.randomPrivateKey();
  writeFileSync(p, Buffer.from(priv).toString('hex'), { mode: 0o600 });
  return priv;
}

/**
 * Load (or first-time generate) the local sensor id (uuid). For a registered
 * sensor (G5) this MUST equal the service-account id; an operator can pin it with
 * OPENA2A_SENSOR_ID. Otherwise a stable local uuid is used (accepted unverified).
 */
export function loadSensorId(): string {
  const fromEnv = process.env.OPENA2A_SENSOR_ID;
  if (fromEnv && fromEnv.trim()) return fromEnv.trim();
  const p = homePath(SENSOR_ID_FILE);
  if (existsSync(p)) {
    const id = readFileSync(p, 'utf8').trim();
    if (id) return id;
  }
  ensureHome();
  const id = randomUUID();
  writeFileSync(p, id, { mode: 0o600 });
  return id;
}

/** Lowercase-hex Ed25519 public key (64 hex chars) for the given private key. */
export async function publicKeyHex(priv: Uint8Array): Promise<string> {
  const pub = await ed25519.getPublicKeyAsync(priv);
  return Buffer.from(pub).toString('hex');
}

/** Sign a UTF-8 canonical string with the sensor key; returns lowercase-hex sig. */
export async function signCanonicalHex(priv: Uint8Array, canonical: string): Promise<string> {
  const sig = await ed25519.signAsync(new TextEncoder().encode(canonical), priv);
  return Buffer.from(sig).toString('hex');
}
