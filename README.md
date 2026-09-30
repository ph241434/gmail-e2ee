
## Status

Phase 1 complete. Phase 2 public-key import/export and fingerprint verification complete.

Implemented:
- AES-GCM message encryption
- RSA-OAEP session-key wrapping
- RSA-PSS sender signatures
- deterministic message serialization
- tamper/wrong-key failure handling
- SPKI public-key import/export using PEM text
- SHA-256 public-key fingerprints with session-only verification state
- 29 automated tests

Not yet implemented:
- Gmail integration
- browser extension APIs
- persistent key storage
- persistent contact and trust storage

# Gmail E2EE Crypto Proof of Concept

[![CI](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml)

This is an educational end-to-end encryption proof of concept intended to eventually integrate with Gmail. The project deliberately stays local: no Gmail integration, Google APIs, OAuth flow, extension APIs, key server, or persistent private-key storage.

The goal is to prove the core cryptographic flow:

```text
plaintext -> hybrid encryption -> signed encrypted package -> verification -> decryption -> original plaintext
```

## Architecture

The demo models two users:

- Pavel, the sender, owns an RSA-PSS signing key pair.
- Alice, the recipient, owns an RSA-OAEP encryption key pair.

For each encrypted message:

1. The plaintext is encoded as UTF-8.
2. A fresh AES-GCM 256-bit session key is generated.
3. A fresh 96-bit AES-GCM nonce is generated with `crypto.getRandomValues()`.
4. AES-GCM encrypts the plaintext. The authentication tag is included in the Web Crypto ciphertext output.
5. Alice's RSA-OAEP public key wraps the per-message AES session key.
6. The unsigned package fields are serialized deterministically.
7. Pavel's RSA-PSS private key signs that deterministic byte representation.
8. The final package is returned as text-safe Base64 fields.

On decrypt:

1. The version and Base64 fields are validated.
2. The signature payload is recreated deterministically.
3. Pavel's RSA-PSS public key verifies the signature.
4. If verification fails, decryption stops immediately.
5. Alice's RSA-OAEP private key unwraps the AES session key.
6. AES-GCM decrypts and authenticates the ciphertext.
7. The plaintext bytes are decoded as UTF-8.

## Algorithms Used

- AES-GCM encrypts the actual message body with a 256-bit symmetric key.
- RSA-OAEP with SHA-256 protects the per-message AES key.
- RSA-PSS with SHA-256 authenticates the sender.
- SHA-256 is used by RSA-OAEP and RSA-PSS through the Web Crypto API.
- Web Crypto provides vetted implementations and secure randomness.

The project never implements AES, RSA, hashing, or randomness manually.

## Public Key Sharing

Alice's public encryption key and Pavel's public signature-verification key can be exported and imported as standard SPKI public keys. SPKI bytes are Base64-encoded between `BEGIN PUBLIC KEY` and `END PUBLIC KEY` PEM markers so the keys can be shared as text.

Imports assign the key's application role explicitly instead of trusting the serialized data to select it:

- Recipient encryption keys import as RSA-OAEP with SHA-256 and only `wrapKey` usage.
- Sender verification keys import as RSA-PSS with SHA-256 and only `verify` usage.

Private keys are never exported. They remain non-extractable and live only in browser memory. Importing a public key proves only that the text is valid key material; it does not verify who owns the key.

## Fingerprints and Session Trust

The app derives each public-key fingerprint by hashing its canonical SPKI bytes with SHA-256. Fingerprints are displayed as 32 uppercase, colon-separated hexadecimal bytes so they can be compared through a separate trusted channel such as an in-person conversation or an established call.

The local demo requires an explicit fingerprint-comparison acknowledgment before an Alice key can encrypt or a Pavel key can verify signatures. That verification state:

- is tied to the exact fingerprint
- resets whenever the corresponding PEM text changes or another key is imported
- exists only in browser memory for the current session
- is not saved as a contact or durable identity assertion

A matching fingerprint can support identity verification only when the comparison channel itself is trustworthy. The application cannot determine key ownership automatically.

## Message Format

Encrypted messages use version `1`:

```ts
interface EncryptedMessage {
  version: 1;
  encryptedSessionKey: string;
  nonce: string;
  ciphertext: string;
  signature: string;
}
```

Binary values are encoded as Base64. The signature covers the deterministic serialization of:

```text
version
encryptedSessionKey
nonce
ciphertext
```

The signature does not sign arbitrary `JSON.stringify()` output.

## Threat Model

The intended future system protects message content from the transport provider. In a Gmail version, plaintext should be encrypted before it enters Gmail and decrypted only on the recipient endpoint.

This does not automatically hide:

- sender email
- recipient email
- timestamps
- message size
- email routing metadata
- subject lines unless they are separately encrypted

## Security Limitations

- This is an educational project, not production cryptographic software.
- Cryptographic primitives are provided by Web Crypto; custom cryptographic algorithms are intentionally avoided.
- Private keys only live in browser memory.
- Private keys are non-extractable and are not included in public-key export.
- Secure long-term private-key storage has not been implemented.
- Fingerprint verification depends on a separate trusted comparison channel.
- Verified status is session-only; persistent contact and trust management have not been implemented.
- Importing a key or viewing its fingerprint alone does not establish its owner's identity.
- Gmail integration has not been implemented.
- Browser-extension APIs have not been implemented.

## Local Demo

Install dependencies, run the checks, then start Vite:

```bash
npm install
npm run typecheck
npm test
npm run dev
```

Open the Vite URL and use:

1. Generate Demo Keys
2. Copy the shareable Alice and Pavel public-key PEM values, or paste and import public keys for those roles.
3. Compare each SHA-256 fingerprint through a separate trusted channel and acknowledge the match.
4. Encrypt
5. Decrypt

The default sender message is `Meet me at 4 PM.` Empty messages are allowed and tested.

## Project Structure

```text
src/
  crypto/
    aes.ts
    encoding.ts
    keyGeneration.ts
    publicKeyFingerprint.ts
    publicKeySerialization.ts
    rsaEncryption.ts
    signatures.ts
  message/
    encryptedMessage.ts
    serialization.ts
  demo.ts
  main.ts
  style.css
  trust/
    publicKeyTrust.ts
tests/
  crypto.test.ts
  publicKeyFingerprint.test.ts
  publicKeySerialization.test.ts
```

## Phase 2 Candidates

- Add local private-key persistence with a serious protection model.
- Add persistent contact and trust storage with explicit key-change handling.
- Define how encrypted subjects and metadata should work.
- Begin browser-extension architecture planning without touching Gmail yet.
