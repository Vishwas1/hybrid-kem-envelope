/**
 * TEST-ONLY decryptor (SPEC §7 happy path) so IDApp tests can prove envelopes
 * open with the matching secret key, without depending on server/.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeB64url } from '../../src/base64url.js';
import { buildAad } from '../../src/encrypt.js';
import { HKDF_INFO, SIZES, xwing } from '../../src/suite.js';

export function testDecrypt(idRequestSource: string, secretKey: Uint8Array): unknown {
  const env = JSON.parse(new TextDecoder().decode(decodeB64url(idRequestSource)));
  const ed = env.encryptedData;
  const ss = xwing.decapsulate(decodeB64url(ed.kemCiphertext, SIZES.kemCiphertext), secretKey);
  const key = hkdf(sha256, ss, decodeB64url(ed.salt, SIZES.salt), HKDF_INFO, SIZES.aesKey);
  const ct = decodeB64url(ed.ciphertext);
  const sealed = new Uint8Array(ct.length + SIZES.tag);
  sealed.set(ct);
  sealed.set(decodeB64url(ed.tag, SIZES.tag), ct.length);
  const pt = gcm(key, decodeB64url(ed.iv, SIZES.iv), buildAad(env.kid)).decrypt(sealed);
  return JSON.parse(new TextDecoder().decode(pt));
}
