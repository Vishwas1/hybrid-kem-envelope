/**
 * Foundation CLI.
 *
 *   npm run keygen  -- --kid <kid> [--keys <path>] [--public <path>]
 *   npm run decrypt -- [--in <path>] [--keys <path>]
 *
 * Defaults (relative to the server/ folder):
 *   --keys   keys/private-keys.json
 *   --public ../exchange/foundation-public-key.json
 *   --in     ../exchange/id-request-source.txt
 *
 * decrypt prints {"kid", "message"} as JSON on success. On failure it prints
 * the SPEC §7 error code to stderr and exits with code 1.
 */
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { readFile } from 'node:fs/promises';
import { createSecretKeyResolver, keygen, KeyStoreError, loadPrivateKeyStore } from './keys.js';
import { decrypt, DecryptError } from './decrypt.js';

const SERVER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_PRIVATE_KEYS = resolve(SERVER_DIR, 'keys/private-keys.json');
const DEFAULT_PUBLIC_KEY = resolve(SERVER_DIR, '../exchange/foundation-public-key.json');
const DEFAULT_INPUT = resolve(SERVER_DIR, '../exchange/id-request-source.txt');

const USAGE = `Usage:
  keygen  --kid <kid> [--keys <private-keys.json>] [--public <foundation-public-key.json>]
  decrypt [--in <id-request-source.txt>] [--keys <private-keys.json>]`;

async function runKeygen(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      kid: { type: 'string' },
      keys: { type: 'string', default: DEFAULT_PRIVATE_KEYS },
      public: { type: 'string', default: DEFAULT_PUBLIC_KEY },
    },
    strict: true,
  });
  if (!values.kid) {
    console.error(USAGE);
    return 2;
  }
  const result = await keygen({
    kid: values.kid,
    privateKeysPath: resolve(values.keys),
    publicKeyPath: resolve(values.public),
  });
  console.log(`Generated key ${result.kid} (${result.publicKeyFile.suite})`);
  console.log(`  private store: ${resolve(values.keys)} (${result.totalKeys} key(s))`);
  console.log(`  public key:    ${resolve(values.public)}`);
  return 0;
}

async function runDecrypt(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      in: { type: 'string', default: DEFAULT_INPUT },
      keys: { type: 'string', default: DEFAULT_PRIVATE_KEYS },
    },
    strict: true,
  });
  const store = await loadPrivateKeyStore(resolve(values.keys));
  if (store.keys.length === 0) throw new KeyStoreError(`no keys in ${resolve(values.keys)}; run keygen first`);
  const encoded = (await readFile(resolve(values.in), 'utf8')).trim();

  const result = decrypt(encoded, createSecretKeyResolver(store));
  console.log(JSON.stringify(result, null, 2));
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  switch (command) {
    case 'keygen':
      return runKeygen(rest);
    case 'decrypt':
      return runDecrypt(rest);
    default:
      console.error(USAGE);
      return 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    if (err instanceof DecryptError || err instanceof KeyStoreError) console.error(`Error: ${err.message}`);
    else console.error(err);
    process.exit(1);
  },
);
