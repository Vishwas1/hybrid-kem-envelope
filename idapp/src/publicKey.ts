/** Foundation public-key file (SPEC §3.1) — IDApp's stand-in for the DID document. */
import { decodeB64url } from './base64url.js';
import { MAX_KID_LENGTH, SIZES, SUITE, type Suite } from './suite.js';

export interface FoundationPublicKey {
  kid: string;
  suite: Suite;
  publicKey: Uint8Array;
}

export class PublicKeyError extends Error {
  override name = 'PublicKeyError';
}

export function validateKid(kid: unknown): asserts kid is string {
  if (typeof kid !== 'string' || kid.length === 0 || kid.length > MAX_KID_LENGTH || !/^[\x21-\x7e]+$/.test(kid)) {
    throw new PublicKeyError(`kid must be 1..${MAX_KID_LENGTH} printable ASCII chars without spaces`);
  }
}

export function parsePublicKeyFile(json: string): FoundationPublicKey {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    throw new PublicKeyError('public key file is not valid JSON');
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new PublicKeyError('public key file must be a JSON object');
  }
  const d = data as Record<string, unknown>;
  validateKid(d.kid);
  if (d.suite !== SUITE) throw new PublicKeyError(`unsupported suite: ${String(d.suite)}`);
  let publicKey: Uint8Array;
  try {
    publicKey = decodeB64url(d.publicKey, SIZES.publicKey);
  } catch {
    throw new PublicKeyError(`publicKey must be base64url of ${SIZES.publicKey} bytes`);
  }
  return { kid: d.kid, suite: SUITE, publicKey };
}
