# ID Source Tracking



# v0.1

### 1\. Vision
Enable **transparent and scalable attribution of identity creation across the Concordium ecosystem**, so every identity issuance can be associated with the wallet, application, or use case that initiated the demand.

This creates the foundation for Concordium to understand **where identity adoption originates, which integrations generate identity-verification costs, and how those costs can eventually be allocated sustainably across ecosystem participants.**
### 2\. Problem Statement
The Concordium Foundation currently bears the cost of identity verification performed by Identity Providers. As more wallets, merchants, and applications integrate Concordium identity, the number of identity creation requests—and therefore the associated IdP costs—will increase.

Today, when an identity is created, there is insufficient information to determine **what initiated the identity creation and which ecosystem integration drove it**. For example, an identity may have been created directly through IDApp, during account creation in a wallet, or because a merchant requested identity verification.
Without this source attribution, Concordium cannot reliably understand **who is driving identity issuance, why identities are being created, or how the resulting costs should be attributed.**
### 3\. Business Value
*   **Sustainable Cost Attribution**
    *   Creates the foundation for moving from Foundation-funded identity verification toward a model where identity issuance costs can eventually be attributed to the wallets, merchants, applications, or other ecosystem participants generating the demand.
*   **Measure Ecosystem Adoption**
    *   Provides visibility into which wallets, applications, integrations, and identity use cases are actually driving new identity creation, allowing Concordium to measure adoption based on real identity issuance activity.
*   **Enable Data-Driven Commercial Models**
    *   Creates attribution data that can support future commercial models with IdPs and ecosystem participants—for example, usage-based charging, partner billing, cost-sharing arrangements, or other identity-as-a-service models—without requiring such a billing model to be implemented as part of the initial source-tracking feature.

## Solution
**Foundation is the generator and owner of the attribution secrets**, rather than relying on merchants to generate/reveal them later.

*   Foundation generates a set of random, one-time secrets/tokens and allocates them to a merchant, e.g. Ledger.
*   When Ledger initiates an ID creation flow, it passes one of these tokens into the flow.
*   The token itself is not recorded publicly. A hash/commitment derived from it is eventually recorded on-chain as part of the ID/account creation process. (may be IDApp or by IDP)
*   Since Foundation generated the token, it already knows that `token X → Ledger`. When it later sees the corresponding hash on-chain, it can independently attribute that event to Ledger. Ledger does not need to voluntarily reveal anything later.
*   The IdP/IDApp only needs to handle the opaque token/hash and does not need to know which merchant it represents.

This could give us the separation we are looking for:
*   **Foundation knows:** this ID creation originated from Ledger.
*   **Foundation does not need to know:** which real-world user created the ID.
*   **IdP knows:** which user it is issuing the ID to.
*   **IdP does not know:** which merchant the opaque attribution value represents.
*   **Public blockchain observers:** only see an opaque hash/commitment.

# v0.2

### 1\. Vision
Enable **transparent and scalable attribution of identity creation across the Concordium ecosystem**, so every identity issuance can be associated with the wallet, application, or use case that initiated the demand.

This creates the foundation for Concordium to understand **where identity adoption originates, which integrations generate identity-verification costs, and how those costs can eventually be allocated sustainably across ecosystem participants.**
### 2\. Problem Statement
The Concordium Foundation currently **_bears the cost of identity_** verification performed by Identity Providers. As more wallets, merchants, and applications integrate Concordium identity, the number of identity creation requests—and therefore the associated IdP costs—will increase.

Today, when an identity is created, there is **_insufficient information_** to determine **what initiated the identity creation and which ecosystem integration drove it**. For example, an identity may have been created directly through IDApp, during account creation in a wallet, or because a merchant requested identity verification.

Without this source attribution, Concordium cannot reliably understand **who is driving identity issuance, why identities are being created, or how the resulting costs should be attributed.**
### 3\. Business Value
*   **Sustainable Cost Attribution**
    *   Creates the foundation for moving from Foundation-funded identity verification toward a model where identity issuance costs can eventually be attributed to the wallets, merchants, applications, or other ecosystem participants generating the demand.
*   **Measure Ecosystem Adoption**
    *   Provides visibility into which wallets, applications, integrations, and identity use cases are actually driving new identity creation, allowing Concordium to measure adoption based on real identity issuance activity.
*   **Enable Data-Driven Commercial Models**
    *   Creates attribution data that can support future commercial models with IdPs and ecosystem participants—for example, usage-based charging, partner billing, cost-sharing arrangements, or other identity-as-a-service models—without requiring such a billing model to be implemented as part of the initial source-tracking feature.

## Proposed Solution — Privacy-Preserving ID Source Tracking
## Design Goal
Reliably determine which merchant/service originated a successful identity creation, while preserving the separation between the user's identity and the originating merchant.
The desired privacy boundary is:
*   Foundation can determine **which merchant generated the ID creation demand**, but not which user.
*   IDP can identify **the user receiving the identity**, but not which merchant initiated the flow.
*   Attribution should not depend on the merchant self-reporting its usage.
## Proposed Solution
Use the **verified merchant domain as the source identifier** and encrypt it before sending it to the IdP.
### Step 1 — Merchant Initiates the Flow
The user starts an [verify-access flow](https://concordium.atlassian.net/wiki/x/AQDOeg) from a merchant, for example [`ledger.com`](http://ledger.com). If the user needs to create a new identity, the merchant redirects/hands off the user to IDApp while preserving the originating merchant context.
### Step 2 — IDApp Verifies the Source Domain
IDApp [determines the originating domain](https://concordium.atlassian.net/wiki/spaces/CSS/pages/2533392388/Verified+Domain+Registry#Phase-1%3A-DKIM-style-Signature-Verification) and verifies that it is a **Verified Domain**. This ensures that the source information used for attribution is not simply a merchant-provided claim and that a malicious service cannot attribute its requests to another merchant.
At this point, IDApp knows that the request genuinely originated from a domain such as [`ledger.com`](http://ledger.com).
### Step 3 — IDApp Encrypts the Source

Once IDApp has verified the originating merchant domain, it creates a small **attribution message** and encrypts it so that only the Foundation can read it.
#### 3.1 Build the Attribution Message
IDApp constructs a message containing the minimum information required for attribution.
For example:

```json
attributionMessage = {
  "version": 1,
  "source": "ledger.com",
  "purpose": "verification",
  "requestId": "<random-request-id>"
}
```

Where:
*   `source` is the verified merchant domain.
*   `purpose` identifies the flow that caused the ID creation, for example `verification`, `account_creation`, or `id_creation`.
*   `requestId` is a cryptographically random, one-time value generated locally by **IDApp** for this attribution event.
The random value should not be generated by the merchant. IDApp generates it after verifying the source, so the merchant cannot control or reuse the value.
Its main purpose is to make each attribution event unique and provide an identifier that can be used for deduplication/retry handling if required.

#### 3.2 Retrieve the Foundation Public Key
The Foundation publishes an encryption key through its **DID Document**.
IDApp is configured with the Foundation DID, for example:

```plain
did:ccd:foundation
```

IDApp resolves this DID through the Foundation's wallet proxy and retrieves the DID Document.
A DID Document can expose public-key material through verification methods, including representations such as `publicKeyJwk`; DID Core also defines `keyAgreement` specifically for cryptographic key-agreement relationships.

```json
{
  "id": "did:ccd:foundation",
  "keyAgreement": [
    "did:ccd:foundation#encryption-key-2"
  ],
  "verificationMethod": [
    {
      "id": "did:ccd:foundation#encryption-key-2",
      "controller": "did:ccd:foundation",
      "type": "JsonWebKey",
      "publicKeyJwk": {
        "...": "..."
      }
    }
  ]
}
```

Using a DID rather than hard-coding a public key gives the Foundation a clean mechanism for **key rotation**. IDApp continues resolving the same Foundation DID, while the DID Document can point to the current active encryption key.

The encrypted attribution record should also carry the selected key identifier, such as:

```bash
kid = did:ccd:foundation#encryption-key-2
```

so Foundation knows which private key must be used for decryption after a rotation.

#### 3.3 Encrypt the Attribution Message
IDApp encrypts the attribution message using the **Foundation's public key** retrieved from its DID Document.
The exact encryption algorithm will be selected during implementation. The important requirement is that the encryption is **randomized**, meaning encrypting the same attribution message multiple times produces different ciphertexts.
For example:

```scss
Encrypt(FoundationPublicKey, attributionMessage) → ciphertext
```

Even when multiple requests originate from [`ledger.com`](http://ledger.com):

```css
ledger.com → ciphertext A
ledger.com → ciphertext B
ledger.com → ciphertext C
```

the ciphertexts must be different and unlinkable.
The value passed to the IdP can have a simple structure:

```json
idRequestSource = {
  "version": 1,
  "kid": "did:ccd:foundation#encryption-key-2",
  "encryptedData": "<encrypted-attribution-message>"
}
```

Where:
*   `version` identifies the format of the encrypted attribution data.
*   `kid` identifies which Foundation public key was used, allowing Foundation to select the corresponding private key after key rotation.
*   `encryptedData` contains the encrypted attribution message.

After decryption, only the Foundation can recover the original attribution message:

```json
attributionMessage = {
  "version": 1,
  "source": "ledger.com",
  "purpose": "verification",
  "requestId": "<unique-request-id>"
}
```

The specific encryption algorithm, encoding format, and cryptographic parameters can be decided during implementation once the overall solution is approved
### Step 4 — Encrypted Attribution is Sent to the IdP
IDApp already initiates identity creation by constructing the **OIDC authorization request** to the selected IdP.
The encrypted attribution data can be added to this request as an additional parameter for example:

```json
idRequestSource = {
  "version": 1,
  "kid": "did:ccd:foundation#encryption-key-2",
  "encryptedData": "<encrypted-attribution-message>"
}
```

This object can be encoded, for example using Base64URL, and passed through the existing identity creation URL as `idRequestSource`.
Conceptually:

```javascript
export async function createIdentityRequest(
  idObjectRequest: Versioned<IdObjectRequestV1>,
  baseUrl: string,
  idRequestSource: EncryptedIdRequestSource
) {
  const params = {
    scope: 'identity',
    response_type: 'code',
    redirect_uri: getRedirectUri(),
    state: JSON.stringify({ idObjectRequest }),

    // Opaque attribution metadata.
    // The IdP cannot decrypt the merchant/source information.
    idRequestSource: base64UrlEncode(
      JSON.stringify(idRequestSource)
    ),
  }

  const searchParams = new URLSearchParams(params)
  return `${baseUrl}?${searchParams.toString()}`
}
```

The resulting authorization request is conceptually:

```erlang
https://<idp>/authorize
  ?scope=identity
  &response_type=code
  &redirect_uri=...
  &state=...
  &idRequestSource=<encoded-encrypted-attribution>
```

IDP can perform its normal identity verification and issuance process, but cannot decrypt the attribution value or determine that the request originated from [`ledger.com`](http://ledger.com).
### Step 5 — IdP Records Successful Identity Issuance
The IdP can decode the outer `idRequestSource` structure to read metadata such as `version` and `kid`, but `encryptedData` remains opaque.
For example, the IdP may see:

```json
idRequestSource = {
  "version": 1,
  "kid": "did:ccd:foundation#encryption-key-2",
  "encryptedData": "eyJ..."
}
```

but cannot recover the original attribution message:

```json
attributionMessage = {
  "source": "ledger.com",
  "purpose": "verification",
  "requestId": "..."
}
```

If the identity is successfully created, the IdP records the opaque attribution value as a **successful identity issuance event**.
Where possible, this attribution record should be stored separately from user-identifying information. The purpose is to record that an identity was successfully issued for the corresponding opaque attribution value, not to create a persistent user-to-source relationship.
### Step 6 — IdP Reports Attribution and Foundation Aggregates
The IdP periodically sends the `idRequestSource` values associated with **successfully issued identities** to the Foundation. No user-identifying information needs to be included in this report.
For each `idRequestSource`, the Foundation performs the following steps:
#### Step 1 - Read the `idRequestSource`
Foundation receives the encoded `idRequestSource` and decodes the outer structure:

```json
{
  "version": 1,
  "kid": "did:ccd:foundation#encryption-key-2",
  "encryptedData": "<encrypted-attribution-message>"
}
```

At this stage, the Foundation has the key identifier and encrypted attribution message, but no user information from the IdP.
#### Step 2 - Identify the Decryption Key
Foundation reads `kid` to determine which encryption key was originally used by IDApp:

```bash
kid = did:ccd:foundation#encryption-key-2
```

Foundation then selects the corresponding private key from its key-management system.
Keeping `kid` with each record is important for **key rotation**: records encrypted using an older public key can still be decrypted using the corresponding retained private key.
#### Step 3 - Decrypt the Attribution Message
Foundation decrypts `encryptedData` using the private key corresponding to `kid`.
After successful decryption, Foundation recovers the original attribution message:

```json
{
  "version": 1,
  "source": "ledger.com",
  "purpose": "verification",
  "requestId": "<unique-request-id>"
}
```

This tells Foundation that the successful identity creation originated from [`ledger.com`](http://ledger.com) and was triggered by a verification flow.
#### Step 4 - Aggregate the Results
Foundation processes the decrypted records and aggregates successful identity creations by source and, if required, purpose.
For example:

```haskell
ledger.com
  verification      → 4,500
  account_creation  →   500
  -------------------------
  Total             → 5,000 successful ID creations
```

The Foundation therefore obtains the information required for **source attribution, usage analysis, and future cost allocation**, while the IdP does not reveal which individual users correspond to those attribution records.

## Knowledge Boundaries

| Stakeholder | Knows User | Knows Merchant | Can persistently link User ↔ Merchant |
| ---| ---| ---| --- |
| Merchant | Depends on merchant flow | Yes | Potentially |
| IDApp | Has ID context | Yes, transiently | Should not persist attribution linkage |
| IdP | Yes | No | No |
| Foundation | No | Yes | No |
| Public/Blockchain | No additional data | No | No |

## Challenges
### Verified Domain Dependency
Source attribution is only reliable if IDApp can establish the originating merchant domain. The **Verified Domain** mechanism therefore becomes a dependency of this solution.
Behaviour for unverified domains still needs to be defined—for example, whether attribution is ignored, marked as unverified, or the flow itself is restricted.
### Foundation Key Management
Foundation must securely manage the private keys used to decrypt attribution records. Loss of a key could make pending records undecryptable, while compromise of a key could expose merchant attribution information.
Appropriate key storage, backup/recovery, access control, and rotation procedures therefore need to be established.
### Key Rotation and Pending Records
The Foundation public key may change over time. IDApp should retrieve the active key dynamically, and each `idRequestSource` should include a `kid` identifying the key used for encryption.
When a key is rotated, Foundation must retain the previous private key for a defined grace period because IdPs may still hold attribution records encrypted with that key.
Historical data does **not** need to be re-encrypted. Once Foundation receives an attribution record, it can decrypt it and store the resulting attribution data in its own database.
### Retries and Duplicate Counting
A single identity creation flow may be retried or an attribution record may be reported more than once.
Foundation needs a mechanism to prevent duplicate counting. The unique `requestId` included in the attribution message can potentially be used for deduplication.
### Non-IDApp Identity Creation
The proposed solution assumes that IDApp participates in the flow and can verify the originating domain and encrypt the attribution message.
Flows such as:
`Wallet → IdP`
do not have IDApp performing these responsibilities and therefore require a separate mechanism or an extension of this design.
## Trade-offs
### IDApp Becomes Privacy-Sensitive
IDApp temporarily has access to both the user's identity context and the originating merchant domain.
The design therefore relies on IDApp treating this information as **transient context** and not unnecessarily persisting or logging the user-to-merchant relationship.
### Foundation Becomes a Trusted Attribution Party
Foundation holds the private key and can therefore decrypt merchant attribution information.
This is intentional because Foundation needs merchant-level attribution for reporting and potential cost allocation. However, the architecture explicitly trusts Foundation to protect this information and not combine it with other data that could identify individual users.
### Reliance on IdP Reporting
The IdP provides the signal that identity creation was successfully completed.
Although the IdP cannot determine which merchant the encrypted attribution represents, Foundation still relies on the IdP to correctly and completely report successful attribution records.
### Additional Operational Complexity
The solution introduces additional infrastructure and operational responsibilities, including DID/public-key discovery, encryption in IDApp, private-key management, key rotation, IdP attribution storage/reporting, and Foundation-side decryption and aggregation.

This complexity is accepted in exchange for preventing the IdP from learning the merchant while preventing Foundation from receiving user-identifying information.

# v0.3

# Privacy-Preserving ID Source Tracking v0.2

## 1\. Vision

Enable **transparent and scalable attribution of identity creation across the Concordium ecosystem**, so every identity issuance can be associated with the wallet, application, or use case that initiated the demand.

This creates the foundation for Concordium to understand **where identity adoption originates, which integrations generate identity-verification costs, and how those costs can eventually be allocated sustainably across ecosystem participants.**

## 2\. Problem Statement

The Concordium Foundation currently **_bears the cost of identity_** verification performed by Identity Providers. As more wallets, merchants, and applications integrate Concordium identity, the number of identity creation requests—and therefore the associated IdP costs—will increase.

Today, when an identity is created, there is\*\*\* insufficient information\*\*\* to determine **what initiated the identity creation and which ecosystem integration drove it**. For example, an identity may have been created directly through IDApp, during account creation in a wallet, or because a merchant requested identity verification.

Without this source attribution, Concordium cannot reliably understand **who is driving identity issuance, why identities are being created, or how the resulting costs should be attributed.**

## 3\. Business Value

*   **Sustainable Cost Attribution**
    *   Creates the foundation for moving from Foundation-funded identity verification toward a model where identity issuance costs can eventually be attributed to the wallets, merchants, applications, or other ecosystem participants generating the demand.
*   **Measure Ecosystem Adoption**
    *   Provides visibility into which wallets, applications, integrations, and identity use cases are actually driving new identity creation, allowing Concordium to measure adoption based on real identity issuance activity.
*   **Enable Data-Driven Commercial Models**
    *   Creates attribution data that can support future commercial models with IdPs and ecosystem participants—for example, usage-based charging, partner billing, cost-sharing arrangements, or other identity-as-a-service models—without requiring such a billing model to be implemented as part of the initial source-tracking feature.

## Proposed Solution — Privacy-Preserving ID Source Tracking

## Design Goals

Reliably determine which merchant/service originated a successful identity creation, while preserving the separation between the user's identity and the originating merchant.

The desired privacy boundary is:

*   Foundation can determine **which merchant generated the ID creation demand**, but not which user.
*   IDP can identify **the user receiving the identity**, but not which merchant initiated the flow.
*   Attribution should not depend on the merchant self-reporting its usage.

## Proposed Solution

Use the **verified merchant domain as the source identifier** and encrypt it before sending it to the IdP.
### Step 1 — Merchant Initiates the Flow 
The user starts the [verify-access flow](https://concordium.atlassian.net/wiki/x/AQDOeg) from a merchant, for example [`armenianwinecellar.co.uk`](http://armenianwinecellar.co.uk). If the user needs to create a new identity, the merchant redirects/hands off the user to IDApp while preserving the originating merchant context.

### Step 2 — IDApp Verifies the Source Domain

IDApp [determines the originating domain](https://concordium.atlassian.net/wiki/spaces/CSS/pages/2533392388/Verified+Domain+Registry#Phase-1%3A-DKIM-style-Signature-Verification) and verifies that it is a **Verified Domain**. This ensures that the source information used for attribution is not simply a merchant-provideyud claim and that a malicious service cannot attribute its requests to another merchant.

At this point, IDApp knows that the request genuinely originated from a domain such as [`armenianwinecellar.co.uk`](http://armenianwinecellar.co.uk).

### Step 3 — IDApp Encrypts the Source

Once IDApp has verified the originating merchant domain, it creates a small **attribution message** and encrypts it so that only the Foundation can read it.

#### 3.1 Build the Attribution Message

IDApp constructs a message containing the minimum information required for attribution.

For example:

```json
attributionMessage = {
  "version": 1,
  "source": "armenianwinecellar.co.uk",
  "sourceStatus": "verified",
  "purpose": "verification",
  "requestId": "<random-request-id>"
}
```

Where:
*   `source` is the verified merchant domain.
*   `purpose` identifies the flow that caused the ID creation, for example `verification`, `account_creation`, or `id_creation`.
*   `requestId` is a cryptographically random identifier generated locally by IDApp for each attribution event. A sufficiently long, securely generated random string is sufficient; UUID v4 is one possible implementation, but is not required. Furthermore, The IDApp must reuse the same `requestId` when retrying the same attribution event and generate a new identifier for each new event. This allows the Foundation to identify duplicate reports and avoid counting the same event more than once. It should not be generated by the merchant. IDApp generates it after verifying the source, so the merchant cannot control or reuse the value. Its main purpose is to make each attribution event unique and provide an identifier that can be used for deduplication/retry handling if required.
*   `sourceStatus`:

| sourceStatus | Meaning |
| ---| --- |
| `verified` | IDApp successfully verified the domain using the Verified Domain mechanism. |
| `unverified` | A domain is available, but IDApp could not verify it. |
| `unknown` | IDApp cannot determine the originating domain. |

#### 3.2 Retrieve the Foundation Public Key

The Foundation publishes an encryption key through its **DID Document** hosted at a well-known HTTPS location on its official domain.
IDApp is configured with the trusted document URL, for example:
`https://<foundation-domain>/.well-known/did.json`
For this web-hosted approach, the document uses a DID of the form `did:web:<foundation-domain>`.

IDApp retrieves the DID Document directly from this location over HTTPS, checks that its `id` matches the expected Foundation DID, and selects the public key designated for attribution encryption under `keyAgreement`.

The document exposes the public-key material through a verification method using `publicKeyJwk`. The following example is illustrative; the encryption algorithm and corresponding JWK fields will be finalized during implementation:

```json
{
  "id": "did:web:<foundation-domain>",
  "keyAgreement": [
    "did:web:<foundation-domain>#encryption-key-2"
  ],
  "verificationMethod": [
    {
      "id": "did:web:<foundation-domain>#encryption-key-2",
      "controller": "did:web:<foundation-domain>",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "BASE64URL_ENCODED_PUBLIC_KEY"
      }
    }
  ]
}
```

This initial approach relies on the configured Foundation domain and HTTPS to authenticate the document.

**Key rotation** is supported by updating the published document with a new public key and a new key identifier, without changing the document URL. IDApp retrieves the current key from this stable location rather than hard-coding the public key. Any cached document must be refreshed according to a defined cache policy.

The encrypted attribution record carries the selected verification method’s `id` as `kid`, for example:

```gherkin
kid = did:web:<foundation-domain>#encryption-key-2
```

This allows Foundation to select the corresponding private key for decryption after a rotation. Foundation must retain previous private keys for a defined grace period to decrypt pending attribution records encrypted with older keys.

#### 3.3 Encrypt the Attribution Message

IDApp encrypts the attribution message using the **Foundation’s public key** retrieved from its DID Document.

The encryption uses the following components:

| Component | Purpose |
| ---| --- |
| X25519 | Establishes a shared secret using IDApp’s temporary private key and Foundation’s public key. |
| HKDF-SHA-256 | Derives a symmetric encryption key from the shared secret. |
| AES-256-GCM | Encrypts the attribution message using the derived key and provides integrity protection. |

These components should be used through a reviewed encryption construction or library. 

**Encryption in IDApp**
For each new encryption, IDApp: 
1. Generates a fresh, temporary X25519 key pair.
2. Combines its temporary private key with Foundation’s public key to calculate a shared secret.
3. Uses HKDF-SHA-256 to derive a 256-bit symmetric encryption key.
4. Encrypts the attribution message using AES-256-GCM with a fresh 96-bit nonce and a 128-bit authentication tag.
5. Includes its temporary public key and the parameters required for decryption in the encrypted envelope. The temporary private key and derived secrets are discarded after use.

The envelope’s version, encryption-suite identifier and `kid` are bound to the ciphertext through authenticated associated data.
The encryption is **randomized**: independently encrypting the same attribution message produces different ciphertexts. This prevents the IdP from identifying repeated merchant sources by comparing ciphertext values alone; it does not eliminate correlation through other metadata.

For example:

```scss
Encrypt(FoundationPublicKey, attributionMessage) → ciphertext
```

Even when multiple requests originate from [`armenianwinecellar.co.uk`](http://armenianwinecellar.co.uk):

```css
armenianwinecellar.co.uk → ciphertext A
armenianwinecellar.co.uk → ciphertext B
armenianwinecellar.co.uk → ciphertext C 
```

the ciphertexts must be different and unlinkable.
The value passed to the IdP has the following illustrative structure: 

```json
idRequestSource = {
  "version": 1,
  "kid": "did:web:foundation#encryption-key-2",
  "encryptedData": {
    "suite": "X25519-HKDF-SHA256-AES256GCM",
    "ephemeralPublicKey": {
      "kty": "OKP",
      "crv": "X25519",
      "x": "<base64url-encoded-temporary-public-key>"
    },
    "salt": "<base64url-encoded-HKDF-salt>",
    "iv": "<base64url-encoded-AES-GCM-nonce>",
    "ciphertext": "<base64url-encoded-ciphertext>",
    "tag": "<base64url-encoded-authentication-tag>"
  }
}
```

Where:
*   `version` identifies the format of the encrypted attribution data.
*   `kid` identifies which Foundation public key was used, allowing Foundation to select the corresponding private key after key rotation.
*   `encryptedData` contains the encrypted attribution message.
    *   **suite** identifies the agreed cryptographic construction. The value above is illustrative.
    *   **ephemeralPublicKey** is IDApp’s temporary public key, which Foundation needs to calculate the same shared secret.
    *   **salt** is the public salt used by HKDF.
    *   **iv** is the AES-GCM nonce, which must never be reused with the same symmetric key.
    *   **ciphertext** contains the encrypted attribution message.
    *   **tag** allows Foundation to detect modification of the ciphertext or authenticated associated data.

The temporary public key, salt and nonce are not secrets and can travel with the ciphertext.

After decryption, only the Foundation can recover the original attribution message:

```json
attributionMessage = {
  "version": 1,
  "source": "armenianwinecellar.co.uk",
  "purpose": "verification",
  "sourceStatus": "verified"
  "requestId": "<unique-request-id>"
}
```

### Step 4 — Encrypted Attribution is Sent to the IdP

IDApp already initiates identity creation by constructing the **OIDC authorization request** to the selected IdP. The encrypted attribution data can be added to this request as an additional parameter for example:

```json
idRequestSource = {
  "version": 1,
  "kid": "did:web:foundation#encryption-key-2",
  "encryptedData": "<encrypted-attribution-message>"
}
```

This object can be encoded, for example using Base64URL, and passed through the existing identity creation URL as `idRequestSource`.
Conceptually:

```plain
export async function createIdentityRequest(
  idObjectRequest: Versioned<IdObjectRequestV1>,
  baseUrl: string,
  idRequestSource: EncryptedIdRequestSource
) {
  const params = {
    scope: 'identity',
    response_type: 'code',
    redirect_uri: getRedirectUri(),
    state: JSON.stringify({ idObjectRequest }),

    // Opaque attribution metadata.
    // The IdP cannot decrypt the merchant/source information.
    idRequestSource: base64UrlEncode(
      JSON.stringify(idRequestSource)
    ),
  }

  const searchParams = new URLSearchParams(params)
  return `${baseUrl}?${searchParams.toString()}`
}
```

The resulting authorization request is conceptually:

```plain
https://<idp>/authorize
  ?scope=identity
  &response_type=code
  &redirect_uri=...
  &state=...
  &idRequestSource=<encoded-encrypted-attribution>
```

IDP can perform its normal identity verification and issuance process, but cannot decrypt the attribution value or determine that the request originated from [`armenianwinecellar.co.uk`](http://armenianwinecellar.co.uk).
### Step 5 — IdP Records Successful Identity Issuance

The IdP can decode the outer `idRequestSource` structure to read metadata such as `version` and `kid`, but `encryptedData` remains opaque. 
For example, the IdP may see:

```json
idRequestSource = {
  "version": 1,
  "kid": "did:web:foundation#encryption-key-2",
  "encryptedData": "eyJ..."
}
```

but cannot recover the original attribution message:

```json
attributionMessage = {
  "source": "armenianwinecellar.co.uk",
  "purpose": "verification",
  "sourceStatus": "verified"
  "requestId": "..."
}
```

If the identity is successfully created, the IdP records the opaque attribution value as a **successful identity issuance event**.

Where possible, this attribution record should be stored separately from user-identifying information. The purpose is to record that an identity was successfully issued for the corresponding opaque attribution value, not to create a persistent user-to-source relationship.

### Step 6 — IdP Reports Attribution and Foundation Aggregates

The IdP periodically sends the `idRequestSource` values associated with **successfully issued identities** to the Foundation. No user-identifying information needs to be included in this report.

For each `idRequestSource`, the Foundation performs the following steps:

#### Step 1 - Read the `idRequestSource`

Foundation receives the encoded `idRequestSource` and decodes the outer structure:

```json
{
  "version": 1,
  "kid": "did:web:foundation#encryption-key-2",
  "encryptedData": "<encrypted-attribution-message>"
}
```

At this stage, the Foundation has the key identifier and encrypted attribution message, but no user information from the IdP.

#### Step 2 - Identify the Decryption Key

Foundation reads `kid` to determine which encryption key was originally used by IDApp:

```bash
kid = did:web:foundation#encryption-key-2
```

Foundation then selects the corresponding private key from its key-management system.

Keeping `kid` with each record is important for **key rotation**: records encrypted using an older public key can still be decrypted using the corresponding retained private key.

#### Step 3 - Decrypt the Attribution Message

Foundation selects the private key identified by `kid` and combines it with IDApp’s temporary public key to calculate the same shared secret. It then applies HKDF-SHA-256 with the same parameters to derive the symmetric key.

Foundation uses that key to verify the AES-GCM authentication tag and decrypt the message. If verification fails, the record is rejected.

After successful decryption, Foundation recovers the original attribution message:

```json
{
  "version": 1,
  "source": "armenianwinecellar.co.uk",
  "purpose": "verification",
  "sourceStatus": "verified",
  "requestId": "<unique-request-id>"
}
```

This tells Foundation that the successful identity creation originated from [`armenianwinecellar.co.uk`](http://armenianwinecellar.co.uk) and was triggered by a verification flow.

#### Step 4 - Aggregate the Results

Foundation processes the decrypted records and aggregates successful identity creations by source and, if required, purpose.

For example:

```haskell
armenianwinecellar.co.uk
  verification      → 4,500
  account_creation  →   500
  -------------------------
  Total             → 5,000 successful ID creations
```

The Foundation therefore obtains the information required for **source attribution, usage analysis, and future cost allocation**, while the IdP does not reveal which individual users correspond to those attribution records.

## Knowledge Boundaries

|  |  |  |  |
| ---| ---| ---| --- |
| Stakeholder | Knows User | Knows Merchant | Can persistently link User ↔ Merchant |
| Merchant | Depends on merchant flow | Yes | Potentially |
| IDApp | Has ID context | Yes, transiently | Should not persist attribution linkage |
| IdP | Yes | No | No |
| Foundation | No | Yes | No |
| Public/Blockchain | No additional data | No | No |

## Challenges

### Verified Domain Dependency

Source attribution is only reliable if IDApp can establish the originating merchant domain. The **Verified Domain** mechanism therefore becomes a dependency of this solution.

Behaviour for unverified domains still needs to be defined—for example, whether attribution is ignored, marked as unverified, or the flow itself is restricted.

### Foundation Key Management

Foundation must securely manage the private keys used to decrypt attribution records. Loss of a key could make pending records undecryptable, while compromise of a key could expose merchant attribution information.

Appropriate key storage, backup/recovery, access control, and rotation procedures therefore need to be established.

### Key Rotation and Pending Records

The Foundation public key may change over time. IDApp should retrieve the active key dynamically, and each `idRequestSource` should include a `kid` identifying the key used for encryption.

When a key is rotated, Foundation must retain the previous private key for a defined grace period because IdPs may still hold attribution records encrypted with that key.

Historical data does **not** need to be re-encrypted. Once Foundation receives an attribution record, it can decrypt it and store the resulting attribution data in its own database.

### Retries and Duplicate Counting

A single identity creation flow may be retried or an attribution record may be reported more than once.

Foundation needs a mechanism to prevent duplicate counting. The unique `requestId` included in the attribution message can potentially be used for deduplication.

### Non-IDApp Identity Creation

The proposed solution assumes that IDApp participates in the flow and can verify the originating domain and encrypt the attribution message.

Flows such as:

`Wallet → IdP`

do not have IDApp performing these responsibilities and therefore require a separate mechanism or an extension of this design.

## Trade-offs

### IDApp Becomes Privacy-Sensitive

IDApp temporarily has access to both the user's identity context and the originating merchant domain.

The design therefore relies on IDApp treating this information as **transient context** and not unnecessarily persisting or logging the user-to-merchant relationship.

### Foundation Becomes a Trusted Attribution Party

Foundation holds the private key and can therefore decrypt merchant attribution information.

This is intentional because Foundation needs merchant-level attribution for reporting and potential cost allocation. However, the architecture explicitly trusts Foundation to protect this information and not combine it with other data that could identify individual users.

### Reliance on IdP Reporting

The IdP provides the signal that identity creation was successfully completed.

Although the IdP cannot determine which merchant the encrypted attribution represents, Foundation still relies on the IdP to correctly and completely report successful attribution records.

### Additional Operational Complexity

The solution introduces additional infrastructure and operational responsibilities, including DID/public-key discovery, encryption in IDApp, private-key management, key rotation, IdP attribution storage/reporting, and Foundation-side decryption and aggregation.

This complexity is accepted in exchange for preventing the IdP from learning the merchant while preventing Foundation from receiving user-identifying information.

# Decision Log

| Date | Version | Item | Decided By |
| ---| ---| ---| --- |
| 16/09/2026 | v0.1 | [Aligned on problem](https://concordium.slack.com/archives/C08JX93QR25/p1789556545419409) statement mentioned in v0.1 | Pete |
| 17/09/2026 | v0.1 | Don't use hashes or Foundation-issued merchant secrets for attribution. Instead, let IDApp establish the trusted source domain and encrypt that source information so only the Foundation can read it. | Andy |
|  | v0.3 | The decision is to figure out post quantum encryption mechanism like ML-KEM and find possible libraries to implement it. | Andy |
| 12/11/2026 | v0.3 | Try Noble for post-quantum encryption/decryption.<br>Assess contributing an open-source DID verification-method specification.<br>Propose a non-DID alternative if that contribution would take too long.<br> | Andy |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

# Transcibes



# Call with Andy on 17th Sept

\[00:00:01.200 --> 00:00:05.600\] And then it's going to pick up this piece of context and then it's going to say create an ID.
\[00:00:05.600 --> 00:00:13.680\] And when you've created the ID, then it's going to send you back to their site to do the verification.
\[00:00:13.680 --> 00:00:22.640\] Is that how we're thinking about it working at the moment anyway?
\[00:00:22.640 --> 00:00:32.560\] Um That was the whole point of your your like mini app wherever it's called app play.
\[00:00:32.560 --> 00:00:33.360\] Right?
\[00:00:33.360 --> 00:00:54.720\] Yeah, so in app click uh we ask user to I mean when the user clicks on the website uh a new uh I mean yeah basically a metadata gets hand off to the ID app.
\[00:00:55.360 --> 00:01:00.480\] Basically applies clip is a way of communication of some information, that's it.
\[00:01:00.640 --> 00:01:04.479\] Yeah, so this is the information it's communicating.
\[00:01:04.480 --> 00:01:12.000\] And it will use that information when it creates the ID and then it will use that information to go back to the initial website.
\[00:01:12.000 --> 00:01:18.800\] So if they didn't provide the secret, we then it's not going to go back to the website.
\[00:01:23.680 --> 00:01:33.759\] You mean the ID app uh do not respond uh uh to their website is that what you meant?
\[00:01:33.760 --> 00:01:55.360\] Like Yeah this is this is the this is what we need to figure out is how we're not the middleman but also that they have to do it I feel like verified domain is gonna be the easiest way of doing it.
\[00:01:55.840 --> 00:02:09.199\] Because if we do verified domain then we've we've guaranteed that they are connecting and then what we take a hash to the domain name.
\[00:02:09.199 --> 00:02:16.160\] That's what we send to the IDP.
\[00:02:16.160 --> 00:02:32.160\] But then I guess the IDP if they know that Yeah ledger is the domain they can come up with the hash themselves and look through their records.
\[00:02:32.240 --> 00:02:49.120\] Yeah because if how many went to ledger Yeah, I mean uh we can I mean in this case IDP can always uh link between uh the domain and the user, right?
\[00:02:49.120 --> 00:02:52.080\] Because they they technically have both information.
\[00:02:52.080 --> 00:03:02.080\] That hash has does not serve the purpose because they can always uh hit Yeah, but whichever way we do it then it would have to be unique for each request.
\[00:03:02.080 --> 00:03:06.240\] And if it's unique for each request, someone's gotta be able to tie it back.
\[00:03:06.240 --> 00:03:07.760\] Yeah.
\[00:03:07.760 --> 00:03:10.160\] So that's no good either.
\[00:03:18.800 --> 00:03:22.240\] So if if the flow starts from uh go away.
\[00:03:22.240 --> 00:03:24.400\] I think of course do you know.
\[00:03:24.400 --> 00:03:27.680\] Mm-hmm.
\[00:03:36.560 --> 00:03:48.800\] We encrypt the hash at a random value using the public key of something the IDP doesn't know the private key to.
\[00:03:48.800 --> 00:03:57.040\] And then the only one that can decrypt that is the one that's got the private key.
\[00:03:57.040 --> 00:03:58.560\] And that's us.
\[00:04:01.920 --> 00:04:13.120\] So that IDP gets a value that looks random to them but when they give us back all the values we can decrypt them to find out where they're from.
\[00:04:13.120 --> 00:04:24.320\] How does that sound but who encrypts uh okay anybody can encrypt the ID app ID app can encrypt right?
\[00:04:24.320 --> 00:04:26.720\] So ID app knows about the website.
\[00:04:26.720 --> 00:04:34.080\] ID app uh let's say it is a verified domain, so IDF know for sure that is coming from the right per uh domain.
\[00:04:34.080 --> 00:04:58.240\] Then IDF encrypts the uh you know domain or and with a along with a random number and then it sends to IDP IDP does not cannot uh decode that decryptor uh and also it cannot uh you know because it's not a hash so it cannot have no a ways to find out.
\[00:04:58.240 --> 00:05:07.200\] And then so IDP keeps storing this information like along with the user probably uh do they have a table or something like where they can store?
\[00:05:07.200 --> 00:05:16.080\] Uh well mean they're storing they're storing a bunch of stuff about the user, but I'd say they don't store it with the user.
\[00:05:16.080 --> 00:05:24.960\] They just store whether the ID was created successfully or not and that special request string that they got.
\[00:05:25.120 --> 00:05:25.680\] Sure.
\[00:05:25.680 --> 00:05:28.640\] Then I think uh there's no and then they give it to us.
\[00:05:28.880 --> 00:05:33.920\] And when they give it to us we can then count them.
\[00:05:34.000 --> 00:05:37.360\] So as long as we have the pri public private key.
\[00:05:37.360 --> 00:05:40.800\] We the ones with the pub private key.
\[00:05:40.800 --> 00:05:41.840\] Okay.
\[00:05:41.840 --> 00:05:51.600\] The only uh issue would be that I mean I mean general issue related to key rotations and all.
\[00:05:51.600 --> 00:06:11.520\] So probably we can uh uh the con foundation can host a DID and link all of the you know public keys over there and that that DID can be kept in the um ID app and ID app can use one of the verification method to probably serve it up of um from a yeah.
\[00:06:11.520 --> 00:06:17.920\] From my wallet connects and the ID app just needs to know what the public key they're gonna use to encrypt this is.
\[00:06:18.160 --> 00:06:20.800\] That can be served from the wallet proxy.
\[00:06:20.800 --> 00:06:22.000\] Yeah.
\[00:06:30.400 --> 00:06:33.360\] So ID app knows about the website.
\[00:06:33.360 --> 00:06:38.240\] ID app uh the website does not need to generate any random number or anything like that, right?
\[00:06:38.560 --> 00:06:39.280\] Nope.
\[00:06:39.600 --> 00:06:44.400\] And uh so the ID app knows about the website, IDF encrypts it.
\[00:06:44.400 --> 00:06:48.320\] Uh IDP does not could not uh link between these two.
\[00:06:48.320 --> 00:06:55.520\] Uh Concordium Foundation also could not link like uh between the user and the domain.
\[00:06:55.520 --> 00:06:59.440\] It can it can only know about because we get this.
\[00:06:59.440 --> 00:07:02.080\] It was transient in the ID app and not recorded.
\[00:07:02.080 --> 00:07:08.960\] We get it from the IDP, a list of these, and we don't know who they're associated with.
\[00:07:08.960 --> 00:07:13.280\] When we decrypt them then we find out which websites and we can count the websites.
\[00:07:13.280 --> 00:07:13.760\] Nice.
\[00:07:13.760 --> 00:07:20.320\] And at the same time you don't need to trust merchants uh for you know Exactly.
\[00:07:20.320 --> 00:07:28.320\] Because if they try and fake the domain, the idea app's gonna flag that bit.
\[00:07:28.320 --> 00:07:32.640\] When it comes to when will it flag that?
\[00:07:34.800 --> 00:07:35.680\] Nice.
\[00:07:35.680 --> 00:07:41.440\] So let's so which means that first we need to work on the domain verify domain feature.
\[00:07:41.440 --> 00:07:46.560\] That can now Andy what is the motivation for them to verify a domain?
\[00:07:46.560 --> 00:07:48.320\] To get that check mark, right?
\[00:07:48.960 --> 00:07:52.880\] To get the check mark in the ID app.
\[00:07:52.960 --> 00:07:57.840\] And so that we will return customers to them when they've created an ID.
\[00:07:58.000 --> 00:08:02.400\] Because if it's not a verified domain, why would we send it back?
\[00:08:02.560 --> 00:08:04.240\] Could be a scammer.
\[00:08:05.440 --> 00:08:07.360\] Makes sense.
\[00:08:08.640 --> 00:08:09.680\] Yeah.
\[00:08:11.600 --> 00:08:15.040\] Sure, uh let me write it down.
\[00:08:15.040 --> 00:08:21.600\] Uh then probably we'll have uh more visibility on if there any uh other edge case that we might have missed.
\[00:08:21.760 --> 00:08:23.520\] Sounds good.
\[00:08:23.520 --> 00:08:24.880\] Okay Okay.
\[00:08:24.880 --> 00:08:25.600\] Sure.
\[00:08:25.600 --> 00:08:27.920\] Alright, so these two things are on my plate.
\[00:08:27.920 --> 00:08:49.920\] I will tomorrow uh sit with uh money to first sort this list out and we will try to release this tomorrow and then uh next week I will work on uh again work on this solution of source tracking.

* * *

And then it's going to pick up this piece of context and then it's going to say create an ID. And when you've created the ID, then it's going to send you back to their site to do the verification. Is that how we're thinking about it working at the moment anyway? Um That was the whole point of your your like mini app wherever it's called app play. Right? Yeah, so in app click uh we ask user to I mean when the user clicks on the website uh a new uh I mean yeah basically a metadata gets hand off to the ID app. Basically applies clip is a way of communication of some information, that's it. Yeah, so this is the information it's communicating. And it will use that information when it creates the ID and then it will use that information to go back to the initial website. So if they didn't provide the secret, we then it's not going to go back to the website. You mean the ID app uh do not respond uh uh to their website is that what you meant? Like Yeah this is this is the this is what we need to figure out is how we're not the middleman but also that they have to do it I feel like verified domain is gonna be the easiest way of doing it.

Because if we do verified domain then we've we've guaranteed that they are connecting and then what we take a hash to the domain name. That's what we send to the IDP. But then I guess the IDP if they know that Yeah ledger is the domain they can come up with the hash themselves and look through their records. Yeah because if how many went to ledger Yeah, I mean uh we can I mean in this case IDP can always uh link between uh the domain and the user, right? Because they they technically have both information. That hash has does not serve the purpose because they can always uh hit Yeah, but whichever way we do it then it would have to be unique for each request. And if it's unique for each request, someone's gotta be able to tie it back. Yeah. So that's no good either. So if if the flow starts from uh go away. I think of course do you know. Mm-hmm. We encrypt the hash at a random value using the public key of something the IDP doesn't know the private key to.

And then the only one that can decrypt that is the one that's got the private key. And that's us. So that IDP gets a value that looks random to them but when they give us back all the values we can decrypt them to find out where they're from. How does that sound but who encrypts uh okay anybody can encrypt the ID app ID app can encrypt right? So ID app knows about the website. ID app uh let's say it is a verified domain, so IDF know for sure that is coming from the right per uh domain. Then IDF encrypts the uh you know domain or and with a along with a random number and then it sends to IDP IDP does not cannot uh decode that decryptor uh and also it cannot uh you know because it's not a hash so it cannot have no a ways to find out. And then so IDP keeps storing this information like along with the user probably uh do they have a table or something like where they can store? Uh well mean they're storing they're storing a bunch of stuff about the user, but I'd say they don't store it with the user. They just store whether the ID was created successfully or not and that special request string that they got.

Sure. Then I think uh there's no and then they give it to us. And when they give it to us we can then count them. So as long as we have the pri public private key. We the ones with the pub private key. Okay. The only uh issue would be that I mean I mean general issue related to key rotations and all. So probably we can uh uh the con foundation can host a DID and link all of the you know public keys over there and that that DID can be kept in the um ID app and ID app can use one of the verification method to probably serve it up of um from a yeah. From my wallet connects and the ID app just needs to know what the public key they're gonna use to encrypt this is. That can be served from the wallet proxy. Yeah. So ID app knows about the website. ID app uh the website does not need to generate any random number or anything like that, right? Nope. And uh so the ID app knows about the website, IDF encrypts it. Uh IDP does not could not uh link between these two. Uh Concordium Foundation also could not link like uh between the user and the domain. It can it can only know about because we get this. It was transient in the ID app and not recorded. We get it from the IDP, a list of these, and we don't know who they're associated with.

When we decrypt them then we find out which websites and we can count the websites. Nice. And at the same time you don't need to trust merchants uh for you know Exactly. Because if they try and fake the domain, the idea app's gonna flag that bit. When it comes to when will it flag that? Nice. So let's so which means that first we need to work on the domain verify domain feature. That can now Andy what is the motivation for them to verify a domain? To get that check mark, right? To get the check mark in the ID app. And so that we will return customers to them when they've created an ID. Because if it's not a verified domain, why would we send it back? Could be a scammer. Makes sense. Yeah. Sure, uh let me write it down. Uh then probably we'll have uh more visibility on if there any uh other edge case that we might have missed. Sounds good. Okay Okay. Sure. Alright, so these two things are on my plate. I will tomorrow uh sit with uh money to first sort this list out and we will try to release this tomorrow and then uh next week I will work on uh again work on this solution of source tracking.