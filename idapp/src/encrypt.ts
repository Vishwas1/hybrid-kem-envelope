/** IDApp encryption of the AttributionMessage into idRequestSource (SPEC §5, §6). */
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { encodeB64url, utf8 } from './base64url.js';
import { serializeMessage, validateMessage, type AttributionMessage } from './message.js';
import type { FoundationPublicKey } from './publicKey.js';
import { ENVELOPE_VERSION, HKDF_INFO, SIZES, SUITE, xwing, type Suite } from './suite.js';

/** SPEC §5.1. */
export interface IdRequestSourceEnvelope {
  version: typeof ENVELOPE_VERSION;
  kid: string;
  encryptedData: {
    suite: Suite;
    kemCiphertext: string;
    salt: string;
    iv: string;
    ciphertext: string;
    tag: string;
  };
}

/**
 * Fixed randomness — ONLY for reproducing the SPEC Appendix A test vector.
 * Production callers must not pass this.
 */
export interface FixedRandomness {
  encap: Uint8Array; // 64 bytes
  salt: Uint8Array; // 32 bytes
  iv: Uint8Array; // 12 bytes
}

/** SPEC §5.2. */
export function buildAad(kid: string): Uint8Array {
  return utf8(JSON.stringify({ version: ENVELOPE_VERSION, kid, suite: SUITE }));
}

function checkLen(name: string, b: Uint8Array, n: number) {
  if (b.length !== n) throw new Error(`${name} must be ${n} bytes`);
}

/** SPEC §6 steps 1–8. Never logs or persists the message (step 9). */
export function encryptAttribution(
  key: FoundationPublicKey,
  message: AttributionMessage,
  fixed?: FixedRandomness,
): IdRequestSourceEnvelope {
  // 1. validate (public key was validated when parsed; re-check what matters here)
  if (key.suite !== SUITE) throw new Error('unsupported suite');
  checkLen('publicKey', key.publicKey, SIZES.publicKey);
  validateMessage(message);
  if (fixed) {
    checkLen('encap randomness', fixed.encap, SIZES.encapRandomness);
    checkLen('salt', fixed.salt, SIZES.salt);
    checkLen('iv', fixed.iv, SIZES.iv);
  }

  // 2. canonical plaintext
  const pt = serializeMessage(message);

  // 3. X-Wing encapsulation
  const { cipherText: kemCiphertext, sharedSecret } = fixed
    ? xwing.encapsulate(key.publicKey, fixed.encap)
    : xwing.encapsulate(key.publicKey);

  let aesKey: Uint8Array | undefined;
  let sealed: Uint8Array | undefined;
  try {
    // 4. HKDF-SHA-256
    const salt = fixed?.salt ?? randomBytes(SIZES.salt);
    aesKey = hkdf(sha256, sharedSecret, salt, HKDF_INFO, SIZES.aesKey);

    // 5–6. AES-256-GCM with AAD; split off the 16-byte tag
    const iv = fixed?.iv ?? randomBytes(SIZES.iv);
    sealed = gcm(aesKey, iv, buildAad(key.kid)).encrypt(pt);
    const ciphertext = sealed.subarray(0, sealed.length - SIZES.tag);
    const tag = sealed.subarray(sealed.length - SIZES.tag);

    // 7. envelope (key order per SPEC §5.1)
    return {
      version: ENVELOPE_VERSION,
      kid: key.kid,
      encryptedData: {
        suite: SUITE,
        kemCiphertext: encodeB64url(kemCiphertext),
        salt: encodeB64url(salt),
        iv: encodeB64url(iv),
        ciphertext: encodeB64url(ciphertext),
        tag: encodeB64url(tag),
      },
    };
  } finally {
    // 8. zero secrets
    sharedSecret.fill(0);
    aesKey?.fill(0);
    pt.fill(0);
  }
}

/** SPEC §5.3: base64url(UTF-8(JSON)). Safe to put in a URL query unescaped. */
export function encodeIdRequestSource(envelope: IdRequestSourceEnvelope): string {
  return encodeB64url(utf8(JSON.stringify(envelope)));
}

/** Convenience: encrypt + encode. */
export function createIdRequestSource(key: FoundationPublicKey, message: AttributionMessage): string {
  return encodeIdRequestSource(encryptAttribution(key, message));
}
