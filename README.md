# ID Source Tracking: Post-Quantum Encryption POC

This POC shows how IDApp can encrypt an **attribution message** so that only the Foundation can read it. The message records which merchant domain started an identity creation and why. Encryption uses post-quantum cryptography from [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).

- **Algorithm:** X-Wing (ML-KEM-768 + X25519 hybrid), then HKDF-SHA-256, then AES-256-GCM.
- **Spec:** [SPEC.md](SPEC.md) is the only contract between the two modules.
- **Background:** *ID Source Tracking* proposal v0.3, and the decision-log entry of 12/11/2026.

**Scope:** key generation, encryption and decryption only. Out of scope: DID, the IdP, domain verification and aggregation.

## Layout

```
SPEC.md     Envelope format, algorithms, error codes
server/     Foundation: key generation + decryption
idapp/      IDApp: builds and encrypts the attribution message
exchange/   Files passed between the two (created at runtime)
```

`server/` and `idapp/` are independent packages that share no code.

## Setup

Requires **Node.js 20+**.

```bash
cd server && npm install && cd ..
cd idapp  && npm install && cd ..
```

## Run the demo

All commands start from the project root.

### 1. Foundation generates a key pair

```bash
cd server
npm run keygen -- --kid 'did:web:foundation.example#encryption-key-1'
cd ..
```

| File | Contents |
| --- | --- |
| `server/keys/private-keys.json` | Private keys. Secret, git-ignored, mode `0600`. |
| `exchange/foundation-public-key.json` | Current public key, read by IDApp. |

### 2. IDApp encrypts an attribution message

```bash
cd idapp
npm run encrypt -- --status verified --source armenianwinecellar.co.uk --purpose verification
cd ..
```

This writes the encoded `idRequestSource` to `exchange/id-request-source.txt` and prints its size and an example IdP authorize URL. The plaintext message is never printed.

### 3. Foundation decrypts it

```bash
cd server
npm run decrypt
cd ..
```

Expected output:

```json
{
  "kid": "did:web:foundation.example#encryption-key-1",
  "message": {
    "version": 1,
    "source": "armenianwinecellar.co.uk",
    "sourceStatus": "verified",
    "purpose": "verification",
    "requestId": "<random, 22 chars>"
  }
}
```

## More scenarios

**Unknown source.** Leave out `--source`. The decrypted `source` will be `null`.
```bash
cd idapp  && npm run encrypt -- --status unknown --purpose id_creation && cd ..
cd server && npm run decrypt && cd ..
```

**Key rotation.** Generate a second key, then encrypt and decrypt again. Envelopes created under the earlier key still decrypt, because old private keys are kept.
```bash
cd server && npm run keygen -- --kid 'did:web:foundation.example#encryption-key-2' && cd ..
```

**Tampering.** Change any character in the middle of `exchange/id-request-source.txt`, then run `npm run decrypt` in `server/`. It fails with `DECRYPTION_FAILED` or `MALFORMED`.

**Retry of the same event.** Pass `--request-id <id>` to `encrypt` to reuse an earlier `requestId`.

**Start over.**
```bash
rm -rf server/keys exchange
```

## CLI reference

| Command (run inside the folder) | Options |
| --- | --- |
| `server: npm run keygen --` | `--kid <kid>` (required), `--keys <file>`, `--public <file>` |
| `server: npm run decrypt --` | `--in <file>` (default `../exchange/id-request-source.txt`), `--keys <file>` |
| `idapp: npm run encrypt --` | `--status verified\|unverified\|unknown`, `--source <domain>` (omit if `unknown`), `--purpose verification\|account_creation\|id_creation`, `--request-id <id>`, `--public <file>`, `--out <file>`, `--idp-url <url>` |

Decryption error codes ([SPEC §7](SPEC.md#7-decrypt-foundation)): `MALFORMED`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE`, `UNKNOWN_KID`, `DECRYPTION_FAILED` and `INVALID_MESSAGE`.

## Tests

```bash
cd server && npm test && npm run typecheck && cd ..
cd idapp  && npm test && npm run typecheck && cd ..
```

## Notes

- An encoded `idRequestSource` is about **2.6 KB**, and the example authorize URL is about 2.7 KB ([SPEC §10](SPEC.md#10-open-points--known-limitations)).
- `exchange/foundation-public-key.json` stands in for a Foundation DID document. DID publishing is outside this POC's scope.
