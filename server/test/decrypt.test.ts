import { describe, expect, it } from 'vitest';
import { decodeB64url, encodeB64url } from '../src/base64url.js';
import {
  decrypt,
  DecryptError,
  type AttributionMessage,
  type DecryptErrorCode,
  type SecretKeyResolver,
} from '../src/decrypt.js';
import { createSecretKeyResolver, generateKeyPair } from '../src/keys.js';
import { SUITE } from '../src/suite.js';
import { encodeEnvelope, encryptEnvelope, encryptToIdRequestSource, type TestEnvelope } from './helpers/encrypt.js';

const KID1 = 'did:web:foundation.example#encryption-key-1';
const KID2 = 'did:web:foundation.example#encryption-key-2';

const key1 = generateKeyPair();
const key2 = generateKeyPair();
const store = {
  keys: [
    { kid: KID1, suite: SUITE, secretKey: encodeB64url(key1.secretKey), createdAt: '2026-11-13T10:00:00.000Z' },
    { kid: KID2, suite: SUITE, secretKey: encodeB64url(key2.secretKey), createdAt: '2026-11-13T11:00:00.000Z' },
  ],
};
const resolve: SecretKeyResolver = createSecretKeyResolver(store);

const MESSAGE: AttributionMessage = {
  version: 1,
  source: 'armenianwinecellar.co.uk',
  sourceStatus: 'verified',
  purpose: 'verification',
  requestId: encodeB64url(new Uint8Array(16).fill(9)),
};

const envelope = (plaintext: Uint8Array | object = MESSAGE, extra: Partial<Parameters<typeof encryptEnvelope>[0]> = {}) =>
  encryptEnvelope({ kid: KID1, publicKey: key1.publicKey, plaintext, ...extra });

function expectCode(fn: () => unknown, code: DecryptErrorCode) {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(DecryptError);
    expect((err as DecryptError).code).toBe(code);
    return err as DecryptError;
  }
  throw new Error(`expected ${code}, but decrypt succeeded`);
}

/** Flip one bit of a binary field at the byte level (keeps base64url canonical). */
function flipByte(env: TestEnvelope, field: keyof TestEnvelope['encryptedData'], index = 0): TestEnvelope {
  const bytes = Uint8Array.from(decodeB64url(env.encryptedData[field]));
  bytes[index] = bytes[index]! ^ 0x01;
  return { ...env, encryptedData: { ...env.encryptedData, [field]: encodeB64url(bytes) } };
}

describe('decrypt — success', () => {
  it('round-trips the message and returns the kid', () => {
    const result = decrypt(encryptToIdRequestSource({ kid: KID1, publicKey: key1.publicKey, plaintext: MESSAGE }), resolve);
    expect(result).toEqual({ kid: KID1, message: MESSAGE });
  });

  it('decrypts envelopes under old and new keys after rotation', () => {
    const e1 = encryptToIdRequestSource({ kid: KID1, publicKey: key1.publicKey, plaintext: MESSAGE });
    const e2 = encryptToIdRequestSource({ kid: KID2, publicKey: key2.publicKey, plaintext: MESSAGE });
    expect(decrypt(e1, resolve).kid).toBe(KID1);
    expect(decrypt(e2, resolve).kid).toBe(KID2);
  });

  it.each([
    { sourceStatus: 'unverified', source: 'shop.example', purpose: 'account_creation' },
    { sourceStatus: 'unknown', source: null, purpose: 'id_creation' },
  ])('accepts %j', (over) => {
    const msg = { ...MESSAGE, ...over };
    expect(decrypt(encodeEnvelope(envelope(msg)), resolve).message).toEqual(msg);
  });

  it('accepts a cached resolver key across calls (does not zero it)', () => {
    const cached = Uint8Array.from(key1.secretKey);
    const cachedResolver: SecretKeyResolver = (kid) => (kid === KID1 ? cached : undefined);
    decrypt(encodeEnvelope(envelope()), cachedResolver);
    expect(decrypt(encodeEnvelope(envelope()), cachedResolver).message).toEqual(MESSAGE);
  });
});

describe('decrypt — MALFORMED', () => {
  const good = envelope();
  const ed = good.encryptedData;
  it.each<[string, unknown]>([
    ['non-string input', 42],
    ['empty string', ''],
    ['not base64url', '***'],
    ['padded base64', encodeEnvelope(good) + '='],
    ['not JSON', Buffer.from('hello').toString('base64url')],
    ['JSON array', encodeEnvelope([])],
    ['missing kid', encodeEnvelope({ version: 1, encryptedData: ed })],
    ['extra header field', encodeEnvelope({ ...good, note: 'x' })],
    ['extra encryptedData field', encodeEnvelope({ ...good, encryptedData: { ...ed, extra: 'x' } })],
    ['missing tag', encodeEnvelope({ ...good, encryptedData: { ...ed, tag: undefined } })],
    ['string version', encodeEnvelope({ ...good, version: '1' })],
    ['empty kid', encodeEnvelope({ ...good, kid: '' })],
    ['short kemCiphertext', encodeEnvelope({ ...good, encryptedData: { ...ed, kemCiphertext: encodeB64url(new Uint8Array(1119)) } })],
    ['short salt', encodeEnvelope({ ...good, encryptedData: { ...ed, salt: encodeB64url(new Uint8Array(16)) } })],
    ['long iv', encodeEnvelope({ ...good, encryptedData: { ...ed, iv: encodeB64url(new Uint8Array(16)) } })],
    ['short tag', encodeEnvelope({ ...good, encryptedData: { ...ed, tag: encodeB64url(new Uint8Array(12)) } })],
    ['empty ciphertext', encodeEnvelope({ ...good, encryptedData: { ...ed, ciphertext: '' } })],
    ['oversized ciphertext', encodeEnvelope({ ...good, encryptedData: { ...ed, ciphertext: encodeB64url(new Uint8Array(4097)) } })],
  ])('%s', (_name, input) => {
    expectCode(() => decrypt(input, resolve), 'MALFORMED');
  });
});

describe('decrypt — header checks', () => {
  it('UNSUPPORTED_VERSION', () => {
    expectCode(() => decrypt(encodeEnvelope(envelope(MESSAGE, { version: 2 })), resolve), 'UNSUPPORTED_VERSION');
  });
  it('UNSUPPORTED_SUITE', () => {
    expectCode(
      () => decrypt(encodeEnvelope(envelope(MESSAGE, { suite: 'X25519-HKDF-SHA256-AES256GCM' })), resolve),
      'UNSUPPORTED_SUITE',
    );
  });
  it('unknown suite wins over suite-specific size errors (SPEC §7 step order)', () => {
    const env = envelope(MESSAGE, { suite: 'FUTURE-SUITE' });
    const odd = { ...env, encryptedData: { ...env.encryptedData, kemCiphertext: encodeB64url(new Uint8Array(1568)) } };
    expectCode(() => decrypt(encodeEnvelope(odd), resolve), 'UNSUPPORTED_SUITE');
  });
  it('unknown version wins over size errors', () => {
    const env = envelope(MESSAGE, { version: 2 });
    const odd = { ...env, encryptedData: { ...env.encryptedData, salt: encodeB64url(new Uint8Array(5)) } };
    expectCode(() => decrypt(encodeEnvelope(odd), resolve), 'UNSUPPORTED_VERSION');
  });
  it('UNKNOWN_KID', () => {
    expectCode(() => decrypt(encodeEnvelope(envelope(MESSAGE, { kid: 'did:web:other#k' })), resolve), 'UNKNOWN_KID');
  });
});

describe('decrypt — DECRYPTION_FAILED (tampering / wrong key)', () => {
  const good = envelope();
  it.each(['kemCiphertext', 'salt', 'iv', 'ciphertext', 'tag'] as const)('flipped byte in %s', (field) => {
    expectCode(() => decrypt(encodeEnvelope(flipByte(good, field)), resolve), 'DECRYPTION_FAILED');
  });

  it('kid swapped to another known kid (AAD binding + wrong key)', () => {
    expectCode(() => decrypt(encodeEnvelope({ ...good, kid: KID2 }), resolve), 'DECRYPTION_FAILED');
  });

  it('right kid, wrong secret key', () => {
    const wrong = generateKeyPair().secretKey;
    expectCode(() => decrypt(encodeEnvelope(good), (kid) => (kid === KID1 ? wrong : undefined)), 'DECRYPTION_FAILED');
  });

  it('error message does not leak plaintext', () => {
    const err = expectCode(() => decrypt(encodeEnvelope(flipByte(good, 'tag')), resolve), 'DECRYPTION_FAILED');
    expect(err.message).not.toContain('armenianwinecellar');
  });
});

describe('decrypt — INVALID_MESSAGE', () => {
  const bytes = (s: string) => new TextEncoder().encode(s);
  it.each<[string, Uint8Array | object]>([
    ['non-UTF-8 plaintext', new Uint8Array([0xff, 0xfe, 0xfd])],
    ['non-JSON plaintext', bytes('hello')],
    ['JSON null', bytes('null')],
    ['wrong version', { ...MESSAGE, version: 2 }],
    ['extra field', { ...MESSAGE, userId: 'u1' }],
    ['missing requestId', { ...MESSAGE, requestId: undefined }],
    ['bad sourceStatus', { ...MESSAGE, sourceStatus: 'trusted' }],
    ['bad purpose', { ...MESSAGE, purpose: 'marketing' }],
    ['null source when verified', { ...MESSAGE, source: null }],
    ['non-null source when unknown', { ...MESSAGE, sourceStatus: 'unknown' }],
    ['uppercase domain', { ...MESSAGE, source: 'Ledger.com' }],
    ['domain with scheme', { ...MESSAGE, source: 'https://ledger.com' }],
    ['domain with leading hyphen label', { ...MESSAGE, source: '-ledger.com' }],
    ['requestId wrong length', { ...MESSAGE, requestId: encodeB64url(new Uint8Array(15)) }],
    ['requestId not base64url', { ...MESSAGE, requestId: 'not base64url!!!!!!!!!' }],
  ])('%s', (_name, plaintext) => {
    expectCode(() => decrypt(encodeEnvelope(envelope(plaintext)), resolve), 'INVALID_MESSAGE');
  });
});
