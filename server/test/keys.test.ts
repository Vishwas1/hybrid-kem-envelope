import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decodeB64url, encodeB64url } from '../src/base64url.js';
import {
  createSecretKeyResolver,
  generateKeyPair,
  keygen,
  KeyStoreError,
  loadPrivateKeyStore,
  parsePrivateKeyStore,
  publicKeyFromSecretKey,
  validateKid,
} from '../src/keys.js';
import { SIZES, SUITE, xwing } from '../src/suite.js';

const KID1 = 'did:web:foundation.example#encryption-key-1';
const KID2 = 'did:web:foundation.example#encryption-key-2';

let dir: string;
let privateKeysPath: string;
let publicKeyPath: string;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'id-source-keys-'));
  privateKeysPath = join(dir, 'keys/private-keys.json');
  publicKeyPath = join(dir, 'exchange/foundation-public-key.json');
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const readJson = async (p: string) => JSON.parse(await readFile(p, 'utf8'));

describe('generateKeyPair', () => {
  it('produces SPEC §2.1 sizes', () => {
    const { publicKey, secretKey } = generateKeyPair();
    expect(publicKey.length).toBe(SIZES.publicKey);
    expect(secretKey.length).toBe(SIZES.secretKey);
  });

  it('is random without a seed', () => {
    const a = generateKeyPair();
    const b = generateKeyPair();
    expect(encodeB64url(a.secretKey)).not.toBe(encodeB64url(b.secretKey));
    expect(encodeB64url(a.publicKey)).not.toBe(encodeB64url(b.publicKey));
  });

  it('is deterministic with a seed (Appendix A test vector input)', () => {
    const seed = new Uint8Array(32).fill(1);
    const a = generateKeyPair(seed);
    const b = generateKeyPair(seed);
    expect(encodeB64url(a.publicKey)).toBe(encodeB64url(b.publicKey));
  });

  it('rejects a wrong-sized seed', () => {
    expect(() => generateKeyPair(new Uint8Array(31))).toThrow(KeyStoreError);
  });

  it('secret key re-derives the public key', () => {
    const { publicKey, secretKey } = generateKeyPair();
    expect(encodeB64url(publicKeyFromSecretKey(secretKey))).toBe(encodeB64url(publicKey));
  });
});

describe('validateKid', () => {
  it.each(['', ' ', 'has space', 'tab\there', 'x'.repeat(257), 'ünicode', 42, null])(
    'rejects %j',
    (kid) => expect(() => validateKid(kid)).toThrow(KeyStoreError),
  );
  it('accepts a DID URL and 256 chars', () => {
    expect(() => validateKid(KID1)).not.toThrow();
    expect(() => validateKid('x'.repeat(256))).not.toThrow();
  });
});

describe('keygen', () => {
  it('writes private store and public key file per SPEC §3', async () => {
    const now = new Date('2026-11-13T10:00:00.000Z');
    const result = await keygen({ kid: KID1, privateKeysPath, publicKeyPath, now });
    expect(result.totalKeys).toBe(1);

    const pub = await readJson(publicKeyPath);
    expect(Object.keys(pub)).toEqual(['kid', 'suite', 'publicKey']);
    expect(pub.kid).toBe(KID1);
    expect(pub.suite).toBe(SUITE);
    expect(decodeB64url(pub.publicKey).length).toBe(SIZES.publicKey);

    const store = await readJson(privateKeysPath);
    expect(store.keys).toHaveLength(1);
    expect(store.keys[0]).toMatchObject({ kid: KID1, suite: SUITE, createdAt: now.toISOString() });

    // Stored secret matches the published public key.
    const sk = decodeB64url(store.keys[0].secretKey, SIZES.secretKey);
    expect(encodeB64url(publicKeyFromSecretKey(sk))).toBe(pub.publicKey);
  });

  it('writes the private store with mode 0600', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    const { mode } = await stat(privateKeysPath);
    expect(mode & 0o777).toBe(0o600);
  });

  it('does not leave temp files behind', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    const { readdir } = await import('node:fs/promises');
    expect(await readdir(join(dir, 'keys'))).toEqual(['private-keys.json']);
  });

  it('rotation appends a key, keeps the old one, and publishes the new one', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    const pub1 = await readJson(publicKeyPath);
    const result = await keygen({ kid: KID2, privateKeysPath, publicKeyPath });
    expect(result.totalKeys).toBe(2);

    const store = await loadPrivateKeyStore(privateKeysPath);
    expect(store.keys.map((k) => k.kid)).toEqual([KID1, KID2]);

    const pub2 = await readJson(publicKeyPath);
    expect(pub2.kid).toBe(KID2);
    expect(pub2.publicKey).not.toBe(pub1.publicKey);

    // Old key still usable for envelopes encrypted before rotation.
    const resolve = createSecretKeyResolver(store);
    const sk1 = resolve(KID1)!;
    expect(encodeB64url(publicKeyFromSecretKey(sk1))).toBe(pub1.publicKey);
  });

  it('rejects a duplicate kid and leaves files untouched', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    const before = [await readFile(privateKeysPath, 'utf8'), await readFile(publicKeyPath, 'utf8')];
    await expect(keygen({ kid: KID1, privateKeysPath, publicKeyPath })).rejects.toThrow(/already exists/);
    expect([await readFile(privateKeysPath, 'utf8'), await readFile(publicKeyPath, 'utf8')]).toEqual(before);
  });

  it('rejects an invalid kid before touching disk', async () => {
    await expect(keygen({ kid: '', privateKeysPath, publicKeyPath })).rejects.toThrow(KeyStoreError);
    await expect(stat(privateKeysPath)).rejects.toThrow();
  });

  it('refuses to overwrite a corrupt private store', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    await writeFile(privateKeysPath, '{ not json');
    await expect(keygen({ kid: KID2, privateKeysPath, publicKeyPath })).rejects.toThrow(/not valid JSON/);
    expect(await readFile(privateKeysPath, 'utf8')).toBe('{ not json');
  });

  it('published key works end to end with X-Wing encapsulate/decapsulate', async () => {
    await keygen({ kid: KID1, privateKeysPath, publicKeyPath });
    const pub = await readJson(publicKeyPath);
    const { cipherText, sharedSecret } = xwing.encapsulate(decodeB64url(pub.publicKey, SIZES.publicKey));
    expect(cipherText.length).toBe(SIZES.kemCiphertext);
    const sk = createSecretKeyResolver(await loadPrivateKeyStore(privateKeysPath))(KID1)!;
    expect(encodeB64url(xwing.decapsulate(cipherText, sk))).toBe(encodeB64url(sharedSecret));
  });
});

describe('parsePrivateKeyStore', () => {
  const entry = (over: Record<string, unknown> = {}) => ({
    kid: KID1,
    suite: SUITE,
    secretKey: encodeB64url(new Uint8Array(32).fill(7)),
    createdAt: '2026-11-13T10:00:00.000Z',
    ...over,
  });
  const parse = (keys: unknown[]) => () => parsePrivateKeyStore(JSON.stringify({ keys }));

  it('accepts a valid store', () => expect(parse([entry()])().keys).toHaveLength(1));
  it('rejects missing keys array', () => expect(() => parsePrivateKeyStore('{}')).toThrow(KeyStoreError));
  it('rejects wrong suite', () => expect(parse([entry({ suite: 'X25519-HKDF-SHA256-AES256GCM' })])).toThrow(/suite/));
  it('rejects wrong secret length', () =>
    expect(parse([entry({ secretKey: encodeB64url(new Uint8Array(31)) })])).toThrow(/secretKey/));
  it('rejects padded base64', () => expect(parse([entry({ secretKey: 'AAAA=' })])).toThrow(/secretKey/));
  it('rejects bad createdAt', () => expect(parse([entry({ createdAt: 'yesterday' })])).toThrow(/createdAt/));
  it('rejects duplicate kids', () => expect(parse([entry(), entry()])).toThrow(/duplicate kid/));
});

describe('createSecretKeyResolver', () => {
  it('returns undefined for unknown kid', () => {
    expect(createSecretKeyResolver({ keys: [] })('nope')).toBeUndefined();
  });
});
