/**
 * IDApp CLI.
 *
 *   npm run encrypt -- --status verified --source armenianwinecellar.co.uk --purpose verification
 *   npm run encrypt -- --status unknown --purpose id_creation
 *
 * Options:
 *   --status      verified | unverified | unknown            (required)
 *   --source      merchant domain (omit when --status unknown)
 *   --purpose     verification | account_creation | id_creation (required)
 *   --request-id  reuse an existing requestId (retry of the same event)
 *   --public      default ../exchange/foundation-public-key.json
 *   --out         default ../exchange/id-request-source.txt
 *   --idp-url     default https://idp.example/authorize (only for the printed example URL)
 *
 * Per SPEC §6 step 9 the plaintext message is never printed.
 */
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createAttributionMessage, MessageError, PURPOSES, SOURCE_STATUSES, type Purpose, type SourceStatus } from './message.js';
import { parsePublicKeyFile, PublicKeyError } from './publicKey.js';
import { createIdRequestSource } from './encrypt.js';

const IDAPP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_PUBLIC_KEY = resolve(IDAPP_DIR, '../exchange/foundation-public-key.json');
const DEFAULT_OUT = resolve(IDAPP_DIR, '../exchange/id-request-source.txt');

const USAGE = `Usage:
  encrypt --status <${SOURCE_STATUSES.join('|')}> [--source <domain>] --purpose <${PURPOSES.join('|')}>
          [--request-id <id>] [--public <file>] [--out <file>] [--idp-url <url>]`;

class UsageError extends Error {}

async function runEncrypt(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    options: {
      status: { type: 'string' },
      source: { type: 'string' },
      purpose: { type: 'string' },
      'request-id': { type: 'string' },
      public: { type: 'string', default: DEFAULT_PUBLIC_KEY },
      out: { type: 'string', default: DEFAULT_OUT },
      'idp-url': { type: 'string', default: 'https://idp.example/authorize' },
    },
    strict: true,
  });

  const status = values.status as SourceStatus | undefined;
  if (!status || !SOURCE_STATUSES.includes(status)) throw new UsageError('--status is required');
  if (!values.purpose || !PURPOSES.includes(values.purpose as Purpose)) throw new UsageError('--purpose is required');
  if (status === 'unknown' && values.source !== undefined) throw new UsageError('--source must be omitted when --status unknown');
  if (status !== 'unknown' && values.source === undefined) throw new UsageError('--source is required');

  const key = parsePublicKeyFile(await readFile(resolve(values.public), 'utf8'));
  const message = createAttributionMessage({
    source: values.source ?? null,
    sourceStatus: status,
    purpose: values.purpose as Purpose,
    ...(values['request-id'] !== undefined ? { requestId: values['request-id'] } : {}),
  });
  const idRequestSource = createIdRequestSource(key, message);

  const out = resolve(values.out);
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, idRequestSource + '\n');

  const url = new URL(values['idp-url']);
  url.search = new URLSearchParams({
    scope: 'identity',
    response_type: 'code',
    redirect_uri: 'https://idapp.example/callback',
    state: '…',
    idRequestSource,
  }).toString();

  console.log(`Encrypted to ${key.kid}`);
  console.log(`  written to:            ${out}`);
  console.log(`  idRequestSource size:  ${idRequestSource.length} chars`);
  console.log(`  example authorize URL: ${url.toString().length} chars`);
  console.log(`    ${url.toString().slice(0, 140)}…`);
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command !== 'encrypt') {
    console.error(USAGE);
    return 2;
  }
  return runEncrypt(rest);
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err: unknown) => {
    if (err instanceof UsageError) console.error(`Error: ${err.message}\n${USAGE}`);
    else if (err instanceof MessageError || err instanceof PublicKeyError) console.error(`Error: ${err.message}`);
    else console.error(err);
    process.exit(1);
  },
);
