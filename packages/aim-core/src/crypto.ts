import * as nacl from 'tweetnacl';

/** Sign data with an Ed25519 secret key */
export function sign(data: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return nacl.sign.detached(data, secretKey);
}

/** Verify an Ed25519 detached signature */
export function verify(
  data: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  return nacl.sign.detached.verify(data, signature, publicKey);
}
