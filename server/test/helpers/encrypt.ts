/**
 * TEST-ONLY encryptor implementing SPEC §6, so server tests can produce
 * envelopes without depending on idapp/. It deliberately skips message
 * validation (so tests can encrypt invalid plaintexts) and allows fixed
 * randomness for Appendix A test vectors.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { encodeB64url } from '../../src/base64url.js';
import { buildAad, deriveAesKey } from '../../src/decrypt.js';
import { SIZES, SUITE, xwing } from '../../src/suite.js';

export interface TestEncryptOptions {
  kid: string;
  publicKey: Uint8Array;
  plaintext: Uint8Array | object; // object → JSON.stringify
  version?: number;
  suite?: string;
  encapRandomness?: Uint8Array; // 64 bytes
  salt?: Uint8Array;
  iv?: Uint8Array;
}

export interface TestEnvelope {
  version: number;
  kid: string;
  encryptedData: {
    suite: string;
    kemCiphertext: string;
    salt: string;
    iv: string;
    ciphertext: string;
    tag: string;
  };
}

export function encryptEnvelope(o: TestEncryptOptions): TestEnvelope {
  const version = o.version ?? 1;
  const suite = o.suite ?? SUITE;
  const pt = o.plaintext instanceof Uint8Array ? o.plaintext : new TextEncoder().encode(JSON.stringify(o.plaintext));

  const { cipherText, sharedSecret } = o.encapRandomness
    ? xwing.encapsulate(o.publicKey, o.encapRandomness)
    : xwing.encapsulate(o.publicKey);
  const salt = o.salt ?? randomBytes(SIZES.salt);
  const iv = o.iv ?? randomBytes(SIZES.iv);
  const key = deriveAesKey(sharedSecret, salt);
  const sealed = gcm(key, iv, buildAad(version, o.kid, suite)).encrypt(pt);
  const ct = sealed.subarray(0, sealed.length - SIZES.tag);
  const tag = sealed.subarray(sealed.length - SIZES.tag);

  return {
    version,
    kid: o.kid,
    encryptedData: {
      suite,
      kemCiphertext: encodeB64url(cipherText),
      salt: encodeB64url(salt),
      iv: encodeB64url(iv),
      ciphertext: encodeB64url(ct),
      tag: encodeB64url(tag),
    },
  };
}

export const encodeEnvelope = (env: unknown): string =>
  Buffer.from(JSON.stringify(env), 'utf8').toString('base64url');

export function encryptToIdRequestSource(o: TestEncryptOptions): string {
  return encodeEnvelope(encryptEnvelope(o));
}
