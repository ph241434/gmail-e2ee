# Gmail E2EE Crypto Proof of Concept

[![CI](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml/badge.svg)](https://github.com/ph241434/gmail-e2ee/actions/workflows/ci.yml)

## Status

Phase 1 complete. Phase 2 public-key verification, encrypted local private-key persistence, and persistent contacts with key-change detection implemented.

Implemented:
- AES-GCM message encryption
- RSA-OAEP session-key wrapping
- RSA-PSS sender signatures
- deterministic message serialization
- tamper/wrong-key failure handling
- SPKI public-key import/export using PEM text
- SHA-256 public-key fingerprints with session verification or saved contact trust
- passphrase-protected private-key persistence in IndexedDB
- persistent contacts, role-specific trust, verification timestamps, and key-change history
- stale-update rejection and stored-trust checks before crypto operations
- 85 automated tests

Not yet implemented:
- Gmail integration
- browser extension APIs

This is an educational end-to-end encryption proof of concept intended to eventually integrate with Gmail. The project deliberately stays local: no Gmail integration, Google APIs, OAuth flow, extension APIs, or key server.

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

Public-key import does not expose private-key material. Importing a public key proves only that the text is valid key material; it does not verify who owns the key.

## Local Private-Key Vault

The optional local vault persists encrypted private keys in IndexedDB for this browser origin. It never stores the vault passphrase.

When a vault is created:

1. Web Crypto generates the two RSA key pairs as extractable only for the wrapping operation.
2. PBKDF2-HMAC-SHA-256 derives an AES-256-GCM wrapping key from the passphrase, a fresh 128-bit salt, and 600,000 iterations.
3. Web Crypto `wrapKey()` encrypts each PKCS#8 private key with a separate fresh 96-bit AES-GCM IV.
4. AES-GCM additional authenticated data binds each wrapped key to the vault version, its application role, and its public-key fingerprint.
5. Only the versioned encrypted vault, public keys, fingerprints, salt, IVs, and KDF metadata are written to IndexedDB.
6. The application receives newly unwrapped private keys that are non-extractable and restricted to `unwrapKey` or `sign` usage.

Unlock validates the vault structure and public-key fingerprints before unwrapping. A wrong passphrase, altered wrapped key, substituted public key, or swapped role record produces the same generic unlock failure. Creating a new vault replaces the single saved vault only after the new encrypted value is ready.

The passphrase policy requires 12 to 1,024 characters. The minimum is a guardrail, not a measure of passphrase strength or a recovery mechanism.

The main vault control follows its current state: create, unlock, lock, or clear temporary keys. Lock releases active key references, clears session trust and message fields, and preserves the encrypted vault for a later unlock. This is an application reset, not a guarantee of secure memory erasure in JavaScript.

Temporary key generation, vault replacement, and vault deletion are available under **Advanced key options**. Temporary keys do not modify the saved vault. Replacement and deletion require confirmation.

## Fingerprints and Contact Trust

The app derives each public-key fingerprint by hashing its canonical SPKI bytes with SHA-256. Fingerprints are displayed as 32 uppercase, colon-separated hexadecimal bytes so they can be compared through a separate trusted channel such as an in-person conversation or an established call.

The demo requires a fingerprint-comparison acknowledgment before a recipient key can encrypt or a sender key can verify signatures. For an unsaved key, that verification state:

- is tied to the exact fingerprint
- resets whenever the corresponding PEM text changes or another key is imported
- exists only in browser memory for the current session
- is not automatically saved as a contact

To persist a decision, open **Public key text**, enter a contact name and email, and select **Save as contact**. New contacts always start unverified. Compare the fingerprint through a separate trusted channel and select the verification checkbox to save that decision. On a later visit, unlock the vault and choose the contact from **Saved contact** to restore its exact key and saved trust.

Each contact can contain an encryption key and a separate signature-verification key. Adding one role does not verify the other. With a contact selected, **Import** updates that contact's key for the corresponding role:

- The same canonical key preserves its existing decision, even if PEM whitespace differs.
- A different fingerprint produces a visible **Key changed** warning, clears verification, and blocks that role until explicitly reverified.
- Returning to an older fingerprint also requires fresh verification.
- **Verification history** records prior and replacement fingerprints, change timestamps, and the prior key's verification timestamp when it was verified.
- Changing the contact email clears both roles' verification. Editing the display name alone does not.

Contacts use the separate `gmail-e2ee-contacts` IndexedDB database. The existing `gmail-e2ee` encrypted vault format and database are unchanged. Lock clears active selections and session trust but retains saved contacts. Deleting or replacing a vault does not delete contacts, and deleting a contact does not delete the vault.

Contact writes use revision checks to reject stale changes from another tab. Before encryption or signature verification, the app re-reads the selected contact and stops if its key, email identity, or saved trust no longer matches. Refresh the page to pick up contacts added or removed elsewhere. This detects local record changes; there is no remote key-discovery service.

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
- Vault private keys are encrypted at rest, but an attacker who can run code in this origin while the vault is unlocked may still use them.
- Vault creation temporarily requires extractable Web Crypto keys so `wrapKey()` can protect their PKCS#8 representation. Extractable private keys are not returned to the application or stored.
- Unlocked private keys are non-extractable and are not included in public-key export.
- PBKDF2 slows passphrase guessing but cannot make a weak passphrase strong.
- There is no passphrase recovery, key backup, migration, or multi-device synchronization.
- Clearing site data loses the saved vault. Browser deletion is not claimed to provide forensic secure erasure.
- Replacing the saved vault makes the previous private keys unavailable through the application.
- Fingerprint verification depends on a separate trusted comparison channel.
- Saved contact names, emails, public keys, and trust metadata are stored locally without encryption. They are not protected by the private-key vault passphrase.
- Contact trust records and key-change history are not signed or tamper-proof against a malicious local user or code running in this origin.
- Saved verification records a user's fingerprint comparison, not proof of email ownership or a certificate authority assertion.
- Historical fingerprints are recorded, but old public-key material is not retained for automatic historical signature verification.
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

1. Enter a passphrase and select **Create vault**, or open **Advanced key options** to use temporary keys.
2. On a later visit, enter the same passphrase and select **Unlock**. Select **Lock** to end the active key session.
3. Open **Public key text** under Alice or Pavel to copy or import a public key when needed.
4. Optionally save each loaded key as a contact, then compare its fingerprint through a separate trusted channel and acknowledge the match.
5. Encrypt.
6. Decrypt.

The default sender message is `Meet me at 4 PM.` Empty messages are allowed and tested.

The raw encrypted JSON, package fields, and tamper control are available under **Encrypted package details**. Public-key text and advanced controls are collapsed by default; fingerprints and verification controls remain visible.

See [the project report](docs/PROJECT-REPORT.md) for the complete architecture, implemented features, verification results, and remaining roadmap.

## Project Structure

```text
src/
  contacts/
    contact.ts
  crypto/
    aes.ts
    encoding.ts
    keyGeneration.ts
    privateKeyVault.ts
    publicKeyFingerprint.ts
    publicKeySerialization.ts
    rsaEncryption.ts
    signatures.ts
  message/
    encryptedMessage.ts
    serialization.ts
  demo.ts
  main.ts
  storage/
    contactStorage.ts
    privateKeyVaultStorage.ts
  style.css
  trust/
    publicKeyTrust.ts
  ui/
    contactController.ts
    keySession.ts
tests/
  contacts.test.ts
  crypto.test.ts
  publicKeyFingerprint.test.ts
  publicKeySerialization.test.ts
  privateKeyVault.test.ts
  privateKeyVaultStorage.test.ts
  keySession.test.ts
```

## Next Milestones

- Add encrypted key backup, recovery, and a deliberate rotation/revocation protocol.
- Define how encrypted subjects and metadata should work.
- Begin browser-extension architecture planning without touching Gmail yet.
