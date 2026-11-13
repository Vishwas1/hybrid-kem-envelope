/**
 * Cipher suite constants (SPEC §2). The Noble X-Wing import lives only here.
 * Independent of server/ — derived from SPEC.md alone.
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

export const SUITE = 'XWING-HKDF-SHA256-AES256GCM' as const;
export type Suite = typeof SUITE;

export const ENVELOPE_VERSION = 1 as const;

/** X-Wing (ML-KEM-768 + X25519). */
export const xwing = ml_kem768_x25519;

/** SPEC §2.1. */
export const SIZES = {
  publicKey: 1216,
  kemCiphertext: 1120,
  encapRandomness: 64,
  salt: 32,
  aesKey: 32,
  iv: 12,
  tag: 16,
} as const;

/** SPEC §2.2. */
export const HKDF_INFO = new TextEncoder().encode(`concordium/id-source/v1/${SUITE}`);

/** SPEC §3.1. */
export const MAX_KID_LENGTH = 256;
