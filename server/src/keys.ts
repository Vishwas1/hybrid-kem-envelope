/**
 * Foundation key management (SPEC §3).
 *
 * - private-keys.json holds every key ever generated (rotation keeps old keys
 *   so envelopes encrypted under them still decrypt).
 * - foundation-public-key.json holds only the current key, for IDApp.
 */
import { mkdir, readFile, rename, writeFile, chmod } from 'node:fs/promises';
import { dirname } from 'node:path';
import { decodeB64url, encodeB64url } from './base64url.js';
import { MAX_KID_LENGTH, SIZES, SUITE, xwing, type Suite } from './suite.js';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** SPEC §3.2 entry. */
export interface PrivateKeyEntry {
  kid: string;
  suite: Suite;
  secretKey: string; // base64url, 32 bytes
  createdAt: string; // ISO-8601
}

export interface PrivateKeyStore {
  keys: PrivateKeyEntry[];
}

/** SPEC §3.1. */
export interface PublicKeyFile {
  kid: string;
  suite: Suite;
  publicKey: string; // base64url, 1216 bytes
}

export class KeyStoreError extends Error {
  override name = 'KeyStoreError';
}

/**
 * Generates an X-Wing key pair. `seed` (32 bytes) is only for deterministic
 * test vectors — production callers must omit it so Noble uses its CSPRNG.
 */
export function generateKeyPair(seed?: Uint8Array): KeyPair {
  if (seed !== undefined && seed.length !== SIZES.secretKey) {
    throw new KeyStoreError(`seed must be ${SIZES.secretKey} bytes`);
  }
  const { publicKey, secretKey } = seed ? xwing.keygen(seed) : xwing.keygen();
  return { publicKey, secretKey };
}

/** The X-Wing secret key is the 32-byte seed, so the public key is re-derivable. */
export function publicKeyFromSecretKey(secretKey: Uint8Array): Uint8Array {
  return xwing.keygen(secretKey).publicKey;
}

export function validateKid(kid: unknown): asserts kid is string {
  if (typeof kid !== 'string' || kid.length === 0 || kid.length > MAX_KID_LENGTH) {
    throw new KeyStoreError(`kid must be a non-empty string of at most ${MAX_KID_LENGTH} chars`);
  }
  // Printable ASCII only: keeps the AAD / JSON unambiguous and avoids log injection.
  if (!/^[\x21-\x7e]+$/.test(kid)) {
    throw new KeyStoreError('kid must contain only printable ASCII without spaces');
  }
}

function validateEntry(entry: unknown, index: number): PrivateKeyEntry {
  const where = `keys[${index}]`;
  if (typeof entry !== 'object' || entry === null) throw new KeyStoreError(`${where} is not an object`);
  const e = entry as Record<string, unknown>;
  try {
    validateKid(e.kid);
  } catch (err) {
    throw new KeyStoreError(`${where}.kid: ${(err as Error).message}`);
  }
  if (e.suite !== SUITE) throw new KeyStoreError(`${where}.suite is not ${SUITE}`);
  try {
    decodeB64url(e.secretKey, SIZES.secretKey);
  } catch (err) {
    throw new KeyStoreError(`${where}.secretKey: ${(err as Error).message}`);
  }
  if (typeof e.createdAt !== 'string' || Number.isNaN(Date.parse(e.createdAt))) {
    throw new KeyStoreError(`${where}.createdAt is not an ISO date`);
  }
  return { kid: e.kid as string, suite: SUITE, secretKey: e.secretKey as string, createdAt: e.createdAt };
}

export function parsePrivateKeyStore(json: string): PrivateKeyStore {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    throw new KeyStoreError('private key store is not valid JSON');
  }
  if (typeof data !== 'object' || data === null || !Array.isArray((data as { keys?: unknown }).keys)) {
    throw new KeyStoreError('private key store must be an object with a "keys" array');
  }
  const keys = (data as { keys: unknown[] }).keys.map(validateEntry);
  const seen = new Set<string>();
  for (const k of keys) {
    if (seen.has(k.kid)) throw new KeyStoreError(`duplicate kid in private key store: ${k.kid}`);
    seen.add(k.kid);
  }
  return { keys };
}

/** Returns an empty store if the file does not exist yet. */
export async function loadPrivateKeyStore(path: string): Promise<PrivateKeyStore> {
  let json: string;
  try {
    json = await readFile(path, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { keys: [] };
    throw err;
  }
  return parsePrivateKeyStore(json);
}

/** Atomic write (temp file + rename) so a crash never leaves a half-written key file. */
async function writeFileAtomic(path: string, content: string, mode: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, content, { mode });
  await chmod(tmp, mode); // writeFile's mode is subject to umask
  await rename(tmp, path);
}

export async function savePrivateKeyStore(path: string, store: PrivateKeyStore): Promise<void> {
  await writeFileAtomic(path, JSON.stringify(store, null, 2) + '\n', 0o600);
}

export async function writePublicKeyFile(path: string, file: PublicKeyFile): Promise<void> {
  // Key order fixed per SPEC §3.1.
  const ordered: PublicKeyFile = { kid: file.kid, suite: file.suite, publicKey: file.publicKey };
  await writeFileAtomic(path, JSON.stringify(ordered, null, 2) + '\n', 0o644);
}

export interface KeygenOptions {
  kid: string;
  privateKeysPath: string;
  publicKeyPath: string;
  /** Test-vector use only. */
  seed?: Uint8Array;
  now?: Date;
}

export interface KeygenResult {
  kid: string;
  publicKeyFile: PublicKeyFile;
  totalKeys: number;
}

/**
 * Generates a new key, appends it to the private store and makes it the
 * current public key (SPEC §3.2 rotation). The private store is written
 * before the public file, so the published key always has a stored secret.
 */
export async function keygen(opts: KeygenOptions): Promise<KeygenResult> {
  validateKid(opts.kid);
  const store = await loadPrivateKeyStore(opts.privateKeysPath);
  if (store.keys.some((k) => k.kid === opts.kid)) {
    throw new KeyStoreError(`kid already exists: ${opts.kid}`);
  }

  const { publicKey, secretKey } = generateKeyPair(opts.seed);
  const entry: PrivateKeyEntry = {
    kid: opts.kid,
    suite: SUITE,
    secretKey: encodeB64url(secretKey),
    createdAt: (opts.now ?? new Date()).toISOString(),
  };
  secretKey.fill(0);

  const updated: PrivateKeyStore = { keys: [...store.keys, entry] };
  await savePrivateKeyStore(opts.privateKeysPath, updated);

  const publicKeyFile: PublicKeyFile = { kid: opts.kid, suite: SUITE, publicKey: encodeB64url(publicKey) };
  await writePublicKeyFile(opts.publicKeyPath, publicKeyFile);

  return { kid: opts.kid, publicKeyFile, totalKeys: updated.keys.length };
}

/**
 * kid → secret key lookup used by decryption (SPEC §7 step 4).
 * Returns undefined for an unknown kid.
 */
export function createSecretKeyResolver(store: PrivateKeyStore): (kid: string) => Uint8Array | undefined {
  const byKid = new Map(store.keys.map((k) => [k.kid, k]));
  return (kid) => {
    const entry = byKid.get(kid);
    return entry ? decodeB64url(entry.secretKey, SIZES.secretKey) : undefined;
  };
}
