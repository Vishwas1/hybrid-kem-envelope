/** Strict base64url without padding (RFC 4648 §5), as required by SPEC §5.1. */

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

export function encodeB64url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64url');
}

/**
 * Decodes base64url, rejecting padding, foreign characters and non-canonical
 * encodings (Node's decoder is lenient, so we round-trip to check).
 * If `expectedLength` is given, the decoded length must match exactly.
 */
export function decodeB64url(value: unknown, expectedLength?: number): Uint8Array {
  if (typeof value !== 'string' || !B64URL_RE.test(value) || value.length % 4 === 1) {
    throw new Error('invalid base64url');
  }
  const buf = Buffer.from(value, 'base64url');
  if (buf.toString('base64url') !== value) {
    throw new Error('non-canonical base64url');
  }
  if (expectedLength !== undefined && buf.length !== expectedLength) {
    throw new Error(`expected ${expectedLength} bytes, got ${buf.length}`);
  }
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}
