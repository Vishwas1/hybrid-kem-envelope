/**
 * base64url without padding (RFC 4648 §5), SPEC §5.1.
 * Uses only standard JS (no Node Buffer) so it also runs in browsers / React Native.
 */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const LOOKUP = new Map([...ALPHABET].map((c, i) => [c, i]));

export function encodeB64url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

/** Strict decode: rejects padding, foreign characters and non-canonical trailing bits. */
export function decodeB64url(value: unknown, expectedLength?: number): Uint8Array {
  if (typeof value !== 'string' || value.length % 4 === 1) throw new Error('invalid base64url');
  const out = new Uint8Array(Math.floor((value.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (const c of value) {
    const v = LOOKUP.get(c);
    if (v === undefined) throw new Error('invalid base64url');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1; // keep only unconsumed bits (avoids 32-bit overflow)
  }
  if (acc !== 0) throw new Error('non-canonical base64url');
  if (expectedLength !== undefined && out.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${out.length}`);
  }
  return out;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
