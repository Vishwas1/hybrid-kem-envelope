/**
 * Foundation-side decryption of `idRequestSource` (SPEC §7).
 * Checks run in the order of the SPEC §7 table; the first failure wins.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { decodeB64url } from './base64url.js';
import { validateKid } from './keys.js';
import { SIZES, SUITE, xwing } from './suite.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const ENVELOPE_VERSION = 1;
export const MESSAGE_VERSION = 1;
export const MAX_CIPHERTEXT_LENGTH = 4096;
export const HKDF_INFO = new TextEncoder().encode(`concordium/id-source/v1/${SUITE}`);

export type SourceStatus = 'verified' | 'unverified' | 'unknown';
export type Purpose = 'verification' | 'account_creation' | 'id_creation';

/** SPEC §4. */
export interface AttributionMessage {
  version: 1;
  source: string | null;
  sourceStatus: SourceStatus;
  purpose: Purpose;
  requestId: string;
}

/** SPEC §5.1 with binary fields decoded. */
export interface DecodedEnvelope {
  version: unknown; // validated in step 2
  kid: string;
  suite: unknown; // validated in step 3
  kemCiphertext: Uint8Array;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

export type DecryptErrorCode =
  | 'MALFORMED'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_SUITE'
  | 'UNKNOWN_KID'
  | 'DECRYPTION_FAILED'
  | 'INVALID_MESSAGE';

/** Messages are fixed strings: never contain key material or plaintext (SPEC §7). */
export class DecryptError extends Error {
  override name = 'DecryptError';
  constructor(
    readonly code: DecryptErrorCode,
    detail: string,
  ) {
    super(`${code}: ${detail}`);
  }
}

export type SecretKeyResolver = (kid: string) => Uint8Array | undefined;

export interface DecryptResult {
  kid: string;
  message: AttributionMessage;
}

// ---------------------------------------------------------------------------
// Step 1 — decode & structural checks (MALFORMED)
// ---------------------------------------------------------------------------

const ENVELOPE_KEYS = ['version', 'kid', 'encryptedData'];
const ENCRYPTED_DATA_KEYS = ['suite', 'kemCiphertext', 'salt', 'iv', 'ciphertext', 'tag'];

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);

/** Exactly these keys: unknown header fields would be unauthenticated, so reject them. */
function hasExactKeys(obj: Record<string, unknown>, keys: string[]): boolean {
  const actual = Object.keys(obj);
  return actual.length === keys.length && keys.every((k) => Object.hasOwn(obj, k));
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true });

function malformed(detail: string): never {
  throw new DecryptError('MALFORMED', detail);
}

function bin(value: unknown, field: string): Uint8Array {
  try {
    return decodeB64url(value);
  } catch {
    return malformed(`${field} is not valid base64url`);
  }
}

export function decodeIdRequestSource(encoded: unknown): DecodedEnvelope {
  if (typeof encoded !== 'string' || encoded.length === 0) malformed('idRequestSource must be a non-empty string');

  let json: unknown;
  try {
    json = JSON.parse(utf8Strict.decode(decodeB64url(encoded)));
  } catch {
    return malformed('idRequestSource is not base64url-encoded UTF-8 JSON');
  }

  if (!isPlainObject(json) || !hasExactKeys(json, ENVELOPE_KEYS)) malformed('envelope fields do not match SPEC §5.1');
  const ed = json.encryptedData;
  if (!isPlainObject(ed) || !hasExactKeys(ed, ENCRYPTED_DATA_KEYS)) {
    malformed('encryptedData fields do not match SPEC §5.1');
  }
  if (typeof json.version !== 'number' || !Number.isInteger(json.version)) malformed('version must be an integer');
  if (typeof ed.suite !== 'string') malformed('suite must be a string');
  try {
    validateKid(json.kid);
  } catch {
    malformed('kid is not a valid key identifier');
  }

  // Sizes are suite-specific, so they are checked later (step 4), after the suite check.
  return {
    version: json.version,
    kid: json.kid as string,
    suite: ed.suite,
    kemCiphertext: bin(ed.kemCiphertext, 'kemCiphertext'),
    salt: bin(ed.salt, 'salt'),
    iv: bin(ed.iv, 'iv'),
    ciphertext: bin(ed.ciphertext, 'ciphertext'),
    tag: bin(ed.tag, 'tag'),
  };
}

/** SPEC §7 step 4: exact sizes for SUITE (§2.1). */
function checkSuiteSizes(env: DecodedEnvelope): void {
  const fixed = [
    ['kemCiphertext', env.kemCiphertext, SIZES.kemCiphertext],
    ['salt', env.salt, SIZES.salt],
    ['iv', env.iv, SIZES.iv],
    ['tag', env.tag, SIZES.tag],
  ] as const;
  for (const [field, bytes, size] of fixed) {
    if (bytes.length !== size) malformed(`${field} must be ${size} bytes`);
  }
  if (env.ciphertext.length < 1 || env.ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
    malformed(`ciphertext must be 1..${MAX_CIPHERTEXT_LENGTH} bytes`);
  }
}

// ---------------------------------------------------------------------------
// SPEC §2.2 / §5.2 helpers
// ---------------------------------------------------------------------------

export function buildAad(version: number, kid: string, suite: string): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({ version, kid, suite }));
}

export function deriveAesKey(sharedSecret: Uint8Array, salt: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, salt, HKDF_INFO, SIZES.aesKey);
}

// ---------------------------------------------------------------------------
// Step 7 — message validation (INVALID_MESSAGE)
// ---------------------------------------------------------------------------

const MESSAGE_KEYS = ['version', 'source', 'sourceStatus', 'purpose', 'requestId'];
const SOURCE_STATUSES: readonly SourceStatus[] = ['verified', 'unverified', 'unknown'];
const PURPOSES: readonly Purpose[] = ['verification', 'account_creation', 'id_creation'];
const REQUEST_ID_BYTES = 16;
/** Lowercase LDH domain: labels 1–63 chars, no leading/trailing hyphen, total ≤ 253. */
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

function invalid(detail: string): never {
  throw new DecryptError('INVALID_MESSAGE', detail);
}

export function validateAttributionMessage(value: unknown): AttributionMessage {
  if (!isPlainObject(value) || !hasExactKeys(value, MESSAGE_KEYS)) invalid('fields do not match SPEC §4');
  const { version, source, sourceStatus, purpose, requestId } = value;

  if (version !== MESSAGE_VERSION) invalid('version must be 1');
  if (!SOURCE_STATUSES.includes(sourceStatus as SourceStatus)) invalid('unknown sourceStatus');
  if (!PURPOSES.includes(purpose as Purpose)) invalid('unknown purpose');
  if (sourceStatus === 'unknown') {
    if (source !== null) invalid('source must be null when sourceStatus is "unknown"');
  } else if (typeof source !== 'string' || !DOMAIN_RE.test(source)) {
    invalid('source must be a lowercase domain name');
  }
  try {
    decodeB64url(requestId, REQUEST_ID_BYTES);
  } catch {
    invalid(`requestId must be base64url of ${REQUEST_ID_BYTES} bytes`);
  }

  return {
    version: MESSAGE_VERSION,
    source: source as string | null,
    sourceStatus: sourceStatus as SourceStatus,
    purpose: purpose as Purpose,
    requestId: requestId as string,
  };
}

// ---------------------------------------------------------------------------
// Decrypt (SPEC §7)
// ---------------------------------------------------------------------------

export function decrypt(encoded: unknown, resolveSecretKey: SecretKeyResolver): DecryptResult {
  // 1. MALFORMED
  const env = decodeIdRequestSource(encoded);

  // 2. UNSUPPORTED_VERSION
  if (env.version !== ENVELOPE_VERSION) {
    throw new DecryptError('UNSUPPORTED_VERSION', `envelope version ${String(env.version)} is not supported`);
  }
  // 3. UNSUPPORTED_SUITE
  if (env.suite !== SUITE) throw new DecryptError('UNSUPPORTED_SUITE', 'suite is not supported');

  // 4. MALFORMED — suite-specific sizes
  checkSuiteSizes(env);

  // 5. UNKNOWN_KID (the store only holds keys of SUITE, so the suite matches)
  const secretKey = resolveSecretKey(env.kid);
  if (!secretKey) throw new DecryptError('UNKNOWN_KID', 'no private key for kid');

  // 6. DECRYPTION_FAILED
  let sharedSecret: Uint8Array | undefined;
  let aesKey: Uint8Array | undefined;
  let plaintext: Uint8Array;
  try {
    // ML-KEM uses implicit rejection: a tampered kemCiphertext yields a random
    // secret here and is caught by the GCM tag check below.
    sharedSecret = xwing.decapsulate(env.kemCiphertext, secretKey);
    aesKey = deriveAesKey(sharedSecret, env.salt);
    const aad = buildAad(ENVELOPE_VERSION, env.kid, SUITE);
    const sealed = new Uint8Array(env.ciphertext.length + SIZES.tag);
    sealed.set(env.ciphertext, 0);
    sealed.set(env.tag, env.ciphertext.length);
    plaintext = gcm(aesKey, env.iv, aad).decrypt(sealed);
  } catch {
    throw new DecryptError('DECRYPTION_FAILED', 'authentication failed');
  } finally {
    // secretKey is owned by the resolver (it may be cached), so it is not zeroed here.
    sharedSecret?.fill(0);
    aesKey?.fill(0);
  }

  // 7. INVALID_MESSAGE
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Strict.decode(plaintext));
  } catch {
    invalid('plaintext is not UTF-8 JSON');
  } finally {
    plaintext.fill(0);
  }
  return { kid: env.kid, message: validateAttributionMessage(parsed) };
}
