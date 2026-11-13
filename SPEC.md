# SPEC — Post-Quantum ID Source Attribution Envelope

**Status:** Draft v0.1 (POC) · **Date:** 2026-11-13
**Based on:** *ID Source Tracking* proposal v0.3, Steps 3 and 6. Decision log, 12/11/2026: "Try Noble for post-quantum encryption/decryption".

This document is the **only contract** between the two POC modules, `idapp/` and `server/`. The modules share no code. Each one implements this spec on its own.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

---

## 1. Scope and roles

| Role | Module | Responsibilities |
| --- | --- | --- |
| **Foundation** | `server/` | Generates and stores key pairs, publishes the public key, and decrypts `idRequestSource` values. |
| **IDApp** | `idapp/` | Builds the `AttributionMessage`, encrypts it to the Foundation's public key, and emits the encoded `idRequestSource`. |

**Out of scope for this POC:**
- Publishing the key through a DID document or JWKS. A JSON file stands in for it (§3).
- The IdP. The encoded value goes straight from IDApp to the server.
- Verified Domain checks. `sourceStatus` is supplied as input.
- Deduplication and aggregation.

## 2. Cipher suite

Suite identifier: **`XWING-HKDF-SHA256-AES256GCM`**

| Component | Algorithm | Library |
| --- | --- | --- |
| KEM | **X-Wing** (ML-KEM-768 + X25519 hybrid, draft-connolly-cfrg-xwing-kem) | `@noble/post-quantum` → `ml_kem768_x25519` from `@noble/post-quantum/hybrid.js` |
| KDF | HKDF-SHA-256 (RFC 5869) | `@noble/hashes` → `hkdf`, `sha256` |
| AEAD | AES-256-GCM | `@noble/ciphers` → `gcm` |
| RNG | CSPRNG | `randomBytes` from `@noble/hashes/utils.js` |

Pinned versions: `@noble/post-quantum@0.7.1`, `@noble/hashes@2.4.0`, `@noble/ciphers@2.4.0`.

### 2.1 Sizes (bytes)

| Value | Size | Notes |
| --- | --- | --- |
| X-Wing public key | 1216 | |
| X-Wing secret key | 32 | This is a seed. The full key is expanded from it on each call. |
| X-Wing KEM ciphertext | 1120 | |
| X-Wing shared secret | 32 | |
| HKDF salt | 32 | Random for each message. |
| AES-GCM key | 32 | Output of HKDF. |
| AES-GCM IV (nonce) | 12 | Random for each message. |
| AES-GCM tag | 16 | |

### 2.2 Key derivation

```
aesKey = HKDF-SHA-256(
  ikm  = sharedSecret,                                              // 32 B from X-Wing
  salt = salt,                                                      // 32 B random
  info = UTF-8("concordium/id-source/v1/XWING-HKDF-SHA256-AES256GCM"),
  L    = 32
)
```

Every message uses a fresh X-Wing encapsulation, which makes `aesKey` unique to each message. A random IV therefore cannot collide under the same key. The IV MUST still be generated randomly.

## 3. Key files

### 3.1 Public key: `exchange/foundation-public-key.json`

This file stands in for the Foundation DID document. IDApp is configured with it.

```json
{
  "kid": "did:web:foundation.example#encryption-key-1",
  "suite": "XWING-HKDF-SHA256-AES256GCM",
  "publicKey": "<base64url, 1216 bytes>"
}
```

- `kid` is an opaque string, at most 256 chars. A DID URL is RECOMMENDED so the format can move to DID later.
- IDApp MUST reject the file if `suite` is not one it supports, or if `publicKey` does not decode to exactly 1216 bytes.

### 3.2 Private keys: `server/keys/private-keys.json` (secret, never shared)

```json
{
  "keys": [
    {
      "kid": "did:web:foundation.example#encryption-key-1",
      "suite": "XWING-HKDF-SHA256-AES256GCM",
      "secretKey": "<base64url, 32 bytes>",
      "createdAt": "2026-11-13T10:00:00.000Z"
    }
  ]
}
```

- **Rotation:** keygen *appends* a new entry and overwrites the public-key file with the new `kid`. Old entries MUST be kept so that envelopes encrypted under them still decrypt.
- `kid` values MUST be unique in this file.
- The file SHOULD be written with mode `0600` and MUST NOT be committed. In the POC it is git-ignored.

## 4. AttributionMessage (plaintext)

```json
{
  "version": 1,
  "source": "armenianwinecellar.co.uk",
  "sourceStatus": "verified",
  "purpose": "verification",
  "requestId": "q3Xf0b9yQ1uY8m2k7Lr4Vg"
}
```

| Field | Type | Rule |
| --- | --- | --- |
| `version` | integer | MUST be `1`. |
| `source` | string \| null | A lowercase domain name, 1–253 chars. MUST be `null` if and only if `sourceStatus` is `"unknown"`. |
| `sourceStatus` | enum | `"verified"`, `"unverified"` or `"unknown"`. |
| `purpose` | enum | `"verification"`, `"account_creation"` or `"id_creation"`. |
| `requestId` | string | base64url of **16** bytes from a CSPRNG (22 chars). IDApp generates it. A retry of the same attribution event MUST reuse it. A new event MUST get a new one. |

**Serialization:** UTF-8 of `JSON.stringify` with **keys in exactly the order above**, no extra fields and no whitespace. The decryptor MUST reject unknown fields, missing fields and values that fail these rules (`INVALID_MESSAGE`).

## 5. Envelope (`idRequestSource`)

### 5.1 Structure

```json
{
  "version": 1,
  "kid": "did:web:foundation.example#encryption-key-1",
  "encryptedData": {
    "suite": "XWING-HKDF-SHA256-AES256GCM",
    "kemCiphertext": "<base64url, 1120 bytes>",
    "salt": "<base64url, 32 bytes>",
    "iv": "<base64url, 12 bytes>",
    "ciphertext": "<base64url, same length as plaintext>",
    "tag": "<base64url, 16 bytes>"
  }
}
```

- Every binary field is **base64url without padding** (RFC 4648 §5).
- Keys MUST be serialized in the order shown, at both levels.
- The envelope MUST contain exactly these fields at both levels. Extra fields would not be covered by the AAD (§5.2), so the decryptor MUST reject them (`MALFORMED`).
- `version` is the envelope format version. It is separate from `AttributionMessage.version`.

### 5.2 Associated data (AAD)

The header fields are bound to the ciphertext:

```
AAD = UTF-8( JSON.stringify({ "version": <version>, "kid": <kid>, "suite": <suite> }) )
```

Keys appear in exactly that order with no whitespace. A change to `version`, `kid` or `suite` makes tag verification fail.

### 5.3 Wire encoding

```
idRequestSource = base64url_nopad( UTF-8( JSON.stringify(envelope) ) )
```

The result is passed as the `idRequestSource` query parameter of the OIDC authorize request. It contains only the characters `[A-Za-z0-9_-]`, so URL encoding leaves it unchanged.

## 6. Encrypt (IDApp)

Inputs: the public-key file (§3.1) and an `AttributionMessage` (§4).

1. Validate the public-key file (§3.1) and the message (§4). On failure, abort.
2. `pt = serialize(message)` (§4).
3. `{ cipherText: kemCiphertext, sharedSecret } = ml_kem768_x25519.encapsulate(publicKey)`
4. `salt = randomBytes(32)`, then `aesKey = HKDF(...)` as defined in §2.2.
5. `aad` as defined in §5.2, using `version = 1`, the file's `kid` and `suite`.
6. `iv = randomBytes(12)`, then `ct||tag = AES-256-GCM(aesKey, iv, aad).encrypt(pt)`. The output's last 16 bytes are `tag`, and the rest is `ciphertext`.
7. Build the envelope (§5.1) and encode it (§5.3).
8. Zero `sharedSecret`, `aesKey` and `pt` with `fill(0)`.
9. MUST NOT log or persist the plaintext message.

## 7. Decrypt (Foundation)

Input: the encoded `idRequestSource`, plus a resolver from `kid` to secret key (§3.2).

Run the checks in order and stop at the first failure:

| # | Check | Error on failure |
| --- | --- | --- |
| 1 | base64url decode, UTF-8 decode, JSON parse. Exactly the fields from §5.1 are present (no extra fields) with the correct types: `version` is an integer, `kid` is valid per §3.1, `suite` is a string, and every binary field is valid base64url. | `MALFORMED` |
| 2 | `version === 1` | `UNSUPPORTED_VERSION` |
| 3 | `encryptedData.suite === "XWING-HKDF-SHA256-AES256GCM"` | `UNSUPPORTED_SUITE` |
| 4 | Binary fields decode to the exact sizes for this suite (§2.1). The `ciphertext` length is between 1 and 4096 bytes. These checks come after the suite check because sizes depend on the suite. | `MALFORMED` |
| 5 | The resolver returns a secret key for `kid`, and that key's `suite` matches. | `UNKNOWN_KID` |
| 6 | `sharedSecret = ml_kem768_x25519.decapsulate(kemCiphertext, secretKey)`. Derive `aesKey` (§2.2), rebuild the AAD (§5.2), then AES-GCM decrypt `ciphertext||tag`. | `DECRYPTION_FAILED` |
| 7 | Parse the plaintext and validate it against §4. | `INVALID_MESSAGE` |

On success, return the `AttributionMessage` and the `kid` that was used.

Notes:
- ML-KEM decapsulation does not fail on a tampered `kemCiphertext`. It returns a pseudo-random secret instead (implicit rejection). Tampering therefore shows up as `DECRYPTION_FAILED` at step 6.
- Error messages MUST NOT contain key material or plaintext.

## 8. Security properties

| Property | How it is achieved |
| --- | --- |
| Only the Foundation can read the message. | The message is encrypted under a key derived from an X-Wing encapsulation to the Foundation's public key. |
| Post-quantum confidentiality | ML-KEM-768 (FIPS 203). |
| Hybrid safety | X-Wing combines ML-KEM-768 with X25519, so the message stays confidential as long as either one is unbroken. |
| Unlinkability (the IdP cannot group requests by merchant) | Every message gets a fresh encapsulation, salt and IV, so identical messages produce unrelated ciphertexts. The ciphertext *length* still reveals the length of `source` (see §10). |
| Integrity of the payload and header | The AES-GCM tag covers the ciphertext and the AAD (`version`, `kid`, `suite`). |
| Key rotation | `kid` in the header, together with retained old private keys (§3.2). |

Not provided: sender authentication. Anyone with the public key can create a valid envelope, which matches v0.3. Trust in the `source` value comes from IDApp's domain verification, not from this envelope.

## 9. Changes from proposal v0.3

| v0.3 | This spec | Reason |
| --- | --- | --- |
| X25519 ECDH with an ephemeral key pair | X-Wing KEM (ML-KEM-768 + X25519) | Post-quantum decision, 12/11/2026 |
| `encryptedData.ephemeralPublicKey` (JWK) | `encryptedData.kemCiphertext` (base64url) | With a KEM, the transmitted value is a ciphertext, not a public key. |
| Suite `X25519-HKDF-SHA256-AES256GCM` | `XWING-HKDF-SHA256-AES256GCM` | KEM change |
| Example attribution message missing a comma; `source` always set | Strict schema; `source` is `null` when status is `unknown` | Defines behaviour for the `unknown` case. |
| Key published in a DID document (`did:web`) | JSON file (§3.1) | DID publishing is outside the POC scope. A DID verification-method format for ML-KEM/X-Wing is a separate, open decision. |

## 10. Open points / known limitations

1. **URL size.** Base64url is applied twice: once to the binary fields and again to the whole JSON. With the 1120-byte KEM ciphertext, the encoded `idRequestSource` is about **2.6 KB**, which is within common URL limits of 8 KB or more. If this turns out to be a problem, a compact binary envelope (single encoding) can cut it to about 1.8 KB.
   *Measured (2026-11-13, server POC):* **2,588 characters** for a `verified` message with `source = "armenianwinecellar.co.uk"` (24 chars) and `kid = "did:web:foundation.example#encryption-key-2"` (43 chars). Each extra character in `source` adds about 1.8 characters, because it is encoded twice. Each extra character in `kid` adds about 1.3, because it is encoded once.
2. **Length leakage.** The ciphertext length reveals the length of `source`. Padding the plaintext to a fixed size (for example 512 bytes) would hide it. This is not done in v0.1.
3. **DID representation** of an X-Wing public key, whether as a JWK `kty` or a Multikey multicodec, is not standardized. It is tracked separately under the decision-log item "Assess contributing an open-source DID verification-method specification".

## Appendix A — Test vector

The vector will be generated once both modules are implemented, using deterministic inputs:

| Input | Value |
| --- | --- |
| keygen seed (32 B) | `0x01` × 32 |
| encapsulation randomness (64 B) | `0x02` × 64 |
| salt (32 B) | `0x03` × 32 |
| iv (12 B) | `0x04` × 12 |
| kid | `did:web:foundation.example#encryption-key-1` |
| message | the example in §4 |

Expected output: *the public key, envelope and encoded `idRequestSource` will be filled in after implementation*. Both modules MUST reproduce it in their tests: IDApp byte-for-byte on encrypt, and the server on decrypt.
