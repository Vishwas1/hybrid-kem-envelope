/**
 * Cipher suite constants (SPEC §2). The Noble X-Wing import lives only here so a
 * library API change touches one file.
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';

export const SUITE = 'XWING-HKDF-SHA256-AES256GCM' as const;
export type Suite = typeof SUITE;

/** X-Wing (ML-KEM-768 + X25519). */
export const xwing = ml_kem768_x25519;

/** Byte sizes from SPEC §2.1. */
export const SIZES = {
  publicKey: 1216,
  secretKey: 32,
  kemCiphertext: 1120,
  sharedSecret: 32,
  salt: 32,
  aesKey: 32,
  iv: 12,
  tag: 16,
} as const;

/** SPEC §3.1: kid is an opaque string of at most 256 chars. */
export const MAX_KID_LENGTH = 256;
