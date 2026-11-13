/** AttributionMessage (SPEC §4): construction, validation and canonical serialization. */
import { randomBytes } from '@noble/hashes/utils.js';
import { decodeB64url, encodeB64url, utf8 } from './base64url.js';

export type SourceStatus = 'verified' | 'unverified' | 'unknown';
export type Purpose = 'verification' | 'account_creation' | 'id_creation';

export const SOURCE_STATUSES: readonly SourceStatus[] = ['verified', 'unverified', 'unknown'];
export const PURPOSES: readonly Purpose[] = ['verification', 'account_creation', 'id_creation'];

export interface AttributionMessage {
  version: 1;
  source: string | null;
  sourceStatus: SourceStatus;
  purpose: Purpose;
  requestId: string;
}

export class MessageError extends Error {
  override name = 'MessageError';
}

const REQUEST_ID_BYTES = 16;
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** 16 CSPRNG bytes, base64url (22 chars). Reuse it when retrying the same attribution event. */
export function newRequestId(): string {
  return encodeB64url(randomBytes(REQUEST_ID_BYTES));
}

export function validateMessage(m: AttributionMessage): void {
  if (m.version !== 1) throw new MessageError('version must be 1');
  if (!SOURCE_STATUSES.includes(m.sourceStatus)) throw new MessageError('unknown sourceStatus');
  if (!PURPOSES.includes(m.purpose)) throw new MessageError('unknown purpose');
  if (m.sourceStatus === 'unknown') {
    if (m.source !== null) throw new MessageError('source must be null when sourceStatus is "unknown"');
  } else if (typeof m.source !== 'string' || !DOMAIN_RE.test(m.source)) {
    throw new MessageError('source must be a lowercase domain name');
  }
  try {
    decodeB64url(m.requestId, REQUEST_ID_BYTES);
  } catch {
    throw new MessageError(`requestId must be base64url of ${REQUEST_ID_BYTES} bytes`);
  }
}

export interface MessageInput {
  source: string | null;
  sourceStatus: SourceStatus;
  purpose: Purpose;
  /** Pass the previous value when retrying the same event; omit for a new event. */
  requestId?: string;
}

/**
 * Builds a validated message. Domains are case-insensitive, so `source` is
 * lower-cased; anything else invalid is rejected rather than "fixed".
 */
export function createAttributionMessage(input: MessageInput): AttributionMessage {
  const m: AttributionMessage = {
    version: 1,
    source: typeof input.source === 'string' ? input.source.toLowerCase() : input.source,
    sourceStatus: input.sourceStatus,
    purpose: input.purpose,
    requestId: input.requestId ?? newRequestId(),
  };
  validateMessage(m);
  return m;
}

/** SPEC §4 canonical serialization: fixed key order, no extra fields, no whitespace. */
export function serializeMessage(m: AttributionMessage): Uint8Array {
  return utf8(
    JSON.stringify({
      version: m.version,
      source: m.source,
      sourceStatus: m.sourceStatus,
      purpose: m.purpose,
      requestId: m.requestId,
    }),
  );
}
