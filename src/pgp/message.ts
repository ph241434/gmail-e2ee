import * as openpgp from "openpgp";
import { normalizeFingerprint, OPENPGP_CONFIG } from "./keys";

export class MessageEncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageEncryptionError";
  }
}

export type DecryptFailureReason =
  | "malformed"       // not an OpenPGP message
  | "not-for-you"     // not encrypted to any of the reader's keys
  | "damaged"         // failed integrity checks
  | "unsigned"        // decrypted, but carries no signature
  | "unknown-signer"  // signed by a key that is not among the expected signers
  | "bad-signature";  // names an expected signer, but the signature does not verify

export class MessageDecryptionError extends Error {
  constructor(
    message: string,
    readonly reason: DecryptFailureReason = "damaged",
    /** Key IDs the message claims to be signed with, when known. */
    readonly signerKeyIds: string[] = []
  ) {
    super(message);
    this.name = "MessageDecryptionError";
  }
}

export interface DecryptedMessage {
  text: string;
  /** Primary-key fingerprint of the verified signer. */
  signerFingerprint: string;
}

/**
 * Signs, then encrypts. The signature sits inside the encrypted data, so it cannot be
 * stripped and replaced by someone who only holds the ciphertext. The sender's own key
 * is always a recipient, so sent mail stays readable.
 */
export async function encryptMessage(
  text: string,
  recipients: openpgp.PublicKey[],
  sender: openpgp.PrivateKey
): Promise<string> {
  const senderPublic = sender.toPublic();
  const encryptionKeys = uniqueByFingerprint([...recipients, senderPublic]);
  try {
    return await openpgp.encrypt({
      message: await openpgp.createMessage({ text }),
      encryptionKeys,
      signingKeys: sender,
      format: "armored",
      config: OPENPGP_CONFIG
    });
  } catch {
    throw new MessageEncryptionError("Unable to encrypt for these recipients. Check that their keys are valid.");
  }
}

/**
 * Decrypts and requires a valid signature from one of `expectedSigners`.
 * Plaintext is never returned unless the signature verified. `recipient` may list
 * several keys (the current key and retired ones); whichever the message names is used.
 */
export async function decryptMessage(
  armoredMessage: string,
  recipient: openpgp.PrivateKey | openpgp.PrivateKey[],
  expectedSigners: openpgp.PublicKey[]
): Promise<DecryptedMessage> {
  const message = await readArmoredMessage(armoredMessage);
  let result: Awaited<ReturnType<typeof openpgp.decrypt<string>>>;
  try {
    // Signatures are checked below rather than with expectSigned, so a failure can say
    // why. The decrypted text stays inside this function unless a signature verifies.
    result = await openpgp.decrypt({
      message,
      decryptionKeys: recipient,
      verificationKeys: expectedSigners,
      format: "utf8",
      config: OPENPGP_CONFIG
    }) as typeof result;
  } catch (error) {
    const detail = error instanceof Error ? error.message : "";
    throw /session key|decryption key|No (?:valid )?decryption/i.test(detail)
      ? new MessageDecryptionError("This message is not encrypted to your key.", "not-for-you")
      : new MessageDecryptionError("The message failed integrity checks or could not be decrypted.", "damaged");
  }
  if (result.signatures.length === 0) {
    throw new MessageDecryptionError("The message is not signed, so its sender cannot be confirmed.", "unsigned");
  }
  let namesExpectedSigner = false;
  for (const signature of result.signatures) {
    const signer = expectedSigners.find((key) => key.getKeys(signature.keyID).length > 0);
    if (!signer) continue;
    namesExpectedSigner = true;
    try {
      await signature.verified;
    } catch {
      continue;
    }
    return { text: result.data, signerFingerprint: normalizeFingerprint(signer.getFingerprint()) };
  }
  const signerKeyIds = result.signatures.map((signature) => signature.keyID.toHex().toUpperCase());
  throw namesExpectedSigner
    ? new MessageDecryptionError("The signature does not match the message.", "bad-signature", signerKeyIds)
    : new MessageDecryptionError("The message is not signed by the expected sender.", "unknown-signer", signerKeyIds);
}

/** Lists the key IDs a message is encrypted to, without decrypting it. */
export async function getMessageRecipientKeyIds(armoredMessage: string): Promise<string[]> {
  const message = await readArmoredMessage(armoredMessage);
  return message.getEncryptionKeyIDs().map((keyId) => keyId.toHex().toUpperCase());
}

/** Key IDs (primary and subkeys) that identify this key in a message header. */
export function getKeyIds(key: openpgp.PublicKey): string[] {
  return key.getKeyIDs().map((keyId) => keyId.toHex().toUpperCase());
}

async function readArmoredMessage(armoredMessage: string): Promise<openpgp.Message<string>> {
  try {
    return await openpgp.readMessage({ armoredMessage: armoredMessage.trim(), config: OPENPGP_CONFIG });
  } catch {
    throw new MessageDecryptionError("Enter a valid armored OpenPGP message.", "malformed");
  }
}

function uniqueByFingerprint(keys: openpgp.PublicKey[]): openpgp.PublicKey[] {
  const seen = new Set<string>();
  return keys.filter((key) => {
    const fingerprint = key.getFingerprint();
    if (seen.has(fingerprint)) return false;
    seen.add(fingerprint);
    return true;
  });
}
