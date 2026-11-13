import { describe, expect, it } from 'vitest';
import { decodeB64url, encodeB64url } from '../src/base64url.js';
import { createIdRequestSource, encodeIdRequestSource, encryptAttribution } from '../src/encrypt.js';
import { createAttributionMessage, MessageError, newRequestId, serializeMessage, type AttributionMessage } from '../src/message.js';
import { parsePublicKeyFile, PublicKeyError, type FoundationPublicKey } from '../src/publicKey.js';
import { SIZES, SUITE, xwing } from '../src/suite.js';
import { testDecrypt } from './helpers/decrypt.js';

const KID = 'did:web:foundation.example#encryption-key-1';
const kp = xwing.keygen();
const KEY: FoundationPublicKey = { kid: KID, suite: SUITE, publicKey: kp.publicKey };

const MESSAGE: AttributionMessage = {
  version: 1,
  source: 'armenianwinecellar.co.uk',
  sourceStatus: 'verified',
  purpose: 'verification',
  requestId: encodeB64url(new Uint8Array(16).fill(9)),
};

const decodeEnvelope = (s: string) => JSON.parse(new TextDecoder().decode(decodeB64url(s)));

describe('base64url', () => {
  it('matches Node for all lengths 0..64', () => {
    for (let n = 0; n <= 64; n++) {
      const b = xwing.keygen().publicKey.subarray(0, n);
      const s = encodeB64url(b);
      expect(s).toBe(Buffer.from(b).toString('base64url'));
      expect(Buffer.from(decodeB64url(s)).equals(Buffer.from(b))).toBe(true);
    }
  });
  it('round-trips a full public key (no overflow on long input)', () => {
    expect(decodeB64url(encodeB64url(kp.publicKey), SIZES.publicKey)).toEqual(kp.publicKey);
  });
  it.each(['AAAA=', 'AA+A', 'AA/A', 'A', 'AB', 'AAB'])('rejects %j', (s) => {
    expect(() => decodeB64url(s)).toThrow();
  });
});

describe('createAttributionMessage', () => {
  it('generates a 22-char requestId and lower-cases the domain', () => {
    const m = createAttributionMessage({ source: 'ArmenianWineCellar.CO.UK', sourceStatus: 'verified', purpose: 'verification' });
    expect(m.source).toBe('armenianwinecellar.co.uk');
    expect(m.requestId).toHaveLength(22);
    expect(decodeB64url(m.requestId)).toHaveLength(16);
  });
  it('reuses a given requestId (retry of the same event)', () => {
    const requestId = newRequestId();
    expect(createAttributionMessage({ source: 'a.example', sourceStatus: 'unverified', purpose: 'id_creation', requestId }).requestId).toBe(requestId);
  });
  it('new events get distinct requestIds', () => {
    expect(new Set(Array.from({ length: 50 }, newRequestId)).size).toBe(50);
  });
  it.each<[string, Parameters<typeof createAttributionMessage>[0]]>([
    ['null source when verified', { source: null, sourceStatus: 'verified', purpose: 'verification' }],
    ['source when unknown', { source: 'a.example', sourceStatus: 'unknown', purpose: 'verification' }],
    ['URL instead of domain', { source: 'https://a.example', sourceStatus: 'verified', purpose: 'verification' }],
    ['bad purpose', { source: 'a.example', sourceStatus: 'verified', purpose: 'marketing' as never }],
    ['bad status', { source: 'a.example', sourceStatus: 'trusted' as never, purpose: 'verification' }],
    ['short requestId', { source: 'a.example', sourceStatus: 'verified', purpose: 'verification', requestId: 'abc' }],
  ])('rejects %s', (_n, input) => {
    expect(() => createAttributionMessage(input)).toThrow(MessageError);
  });
});

describe('serializeMessage', () => {
  it('uses the SPEC §4 key order and no whitespace', () => {
    const shuffled = { requestId: MESSAGE.requestId, purpose: MESSAGE.purpose, source: MESSAGE.source, version: 1, sourceStatus: MESSAGE.sourceStatus } as AttributionMessage;
    expect(new TextDecoder().decode(serializeMessage(shuffled))).toBe(
      `{"version":1,"source":"armenianwinecellar.co.uk","sourceStatus":"verified","purpose":"verification","requestId":"${MESSAGE.requestId}"}`,
    );
  });
});

describe('parsePublicKeyFile', () => {
  const file = (o: Record<string, unknown> = {}) =>
    JSON.stringify({ kid: KID, suite: SUITE, publicKey: encodeB64url(kp.publicKey), ...o });
  it('accepts a valid file', () => expect(parsePublicKeyFile(file()).publicKey).toEqual(kp.publicKey));
  it.each<[string, string]>([
    ['bad JSON', '{'],
    ['wrong suite', file({ suite: 'X25519-HKDF-SHA256-AES256GCM' })],
    ['short key', file({ publicKey: encodeB64url(kp.publicKey.subarray(0, 1215)) })],
    ['empty kid', file({ kid: '' })],
    ['kid with space', file({ kid: 'a b' })],
  ])('rejects %s', (_n, json) => expect(() => parsePublicKeyFile(json)).toThrow(PublicKeyError));
});

describe('encryptAttribution', () => {
  it('produces the SPEC §5.1 envelope shape, key order and field sizes', () => {
    const env = decodeEnvelope(createIdRequestSource(KEY, MESSAGE));
    expect(Object.keys(env)).toEqual(['version', 'kid', 'encryptedData']);
    expect(Object.keys(env.encryptedData)).toEqual(['suite', 'kemCiphertext', 'salt', 'iv', 'ciphertext', 'tag']);
    expect(env.version).toBe(1);
    expect(env.kid).toBe(KID);
    expect(env.encryptedData.suite).toBe(SUITE);
    expect(decodeB64url(env.encryptedData.kemCiphertext)).toHaveLength(SIZES.kemCiphertext);
    expect(decodeB64url(env.encryptedData.salt)).toHaveLength(SIZES.salt);
    expect(decodeB64url(env.encryptedData.iv)).toHaveLength(SIZES.iv);
    expect(decodeB64url(env.encryptedData.tag)).toHaveLength(SIZES.tag);
    expect(decodeB64url(env.encryptedData.ciphertext)).toHaveLength(serializeMessage(MESSAGE).length);
  });

  it('decrypts with the matching secret key to the exact message', () => {
    expect(testDecrypt(createIdRequestSource(KEY, MESSAGE), kp.secretKey)).toEqual(MESSAGE);
  });

  it('does not decrypt with another secret key', () => {
    expect(() => testDecrypt(createIdRequestSource(KEY, MESSAGE), xwing.keygen().secretKey)).toThrow();
  });

  it('binds kid via AAD: changing kid breaks decryption', () => {
    const env = encryptAttribution(KEY, MESSAGE);
    expect(() => testDecrypt(encodeIdRequestSource({ ...env, kid: 'did:web:other#k' }), kp.secretKey)).toThrow();
  });

  it('is randomized: same message gives unlinkable envelopes', () => {
    const fields = Array.from({ length: 20 }, () => encryptAttribution(KEY, MESSAGE).encryptedData);
    for (const f of ['kemCiphertext', 'salt', 'iv', 'ciphertext', 'tag'] as const) {
      expect(new Set(fields.map((e) => e[f])).size).toBe(20);
    }
  });

  it('is deterministic with fixed randomness (Appendix A support)', () => {
    const fixed = { encap: new Uint8Array(64).fill(2), salt: new Uint8Array(32).fill(3), iv: new Uint8Array(12).fill(4) };
    expect(encryptAttribution(KEY, MESSAGE, fixed)).toEqual(encryptAttribution(KEY, MESSAGE, fixed));
  });

  it('rejects wrong-sized fixed randomness', () => {
    const fixed = { encap: new Uint8Array(63), salt: new Uint8Array(32), iv: new Uint8Array(12) };
    expect(() => encryptAttribution(KEY, MESSAGE, fixed)).toThrow(/64 bytes/);
  });

  it('rejects an invalid message', () => {
    expect(() => encryptAttribution(KEY, { ...MESSAGE, source: null })).toThrow(MessageError);
  });

  it('handles sourceStatus unknown with null source', () => {
    const m = createAttributionMessage({ source: null, sourceStatus: 'unknown', purpose: 'id_creation' });
    expect(testDecrypt(createIdRequestSource(KEY, m), kp.secretKey)).toEqual(m);
  });
});

describe('encodeIdRequestSource', () => {
  it('is URL-safe and survives URLSearchParams unchanged', () => {
    const s = createIdRequestSource(KEY, MESSAGE);
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    const qs = new URLSearchParams({ idRequestSource: s }).toString();
    expect(qs).toBe(`idRequestSource=${s}`);
    expect(new URLSearchParams(qs).get('idRequestSource')).toBe(s);
  });

  it('size is about 2.6 KB (SPEC §10)', () => {
    const s = createIdRequestSource(KEY, MESSAGE);
    expect(s.length).toBeGreaterThan(2400);
    expect(s.length).toBeLessThan(2800);
  });
});
