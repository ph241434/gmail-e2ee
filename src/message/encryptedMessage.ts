import {
  decryptWithAesGcm,
  generateAesGcmKey,
  generateAesGcmNonce,
  AES_GCM_NONCE_LENGTH_BYTES,
  encryptWithAesGcm
} from "../crypto/aes";
import {
  base64ToArrayBuffer,
  bytesToBase64,
  bytesToText,
  textToBytes
} from "../crypto/encoding";
import {
  unwrapAesKeyWithRsaOaep,
  wrapAesKeyWithRsaOaep
} from "../crypto/rsaEncryption";
import { signBytes, verifySignature } from "../crypto/signatures";
import { serializeForSignature } from "./serialization";

export const ENCRYPTED_MESSAGE_VERSION = 1;

export interface UnsignedEncryptedMessage {
  version: typeof ENCRYPTED_MESSAGE_VERSION;
  encryptedSessionKey: string;
  nonce: string;
  ciphertext: string;
}

export interface EncryptedMessage extends UnsignedEncryptedMessage {
  signature: string;
}

export class UnsupportedMessageVersionError extends Error {
  constructor(version: number) {
    super(`Unsupported encrypted message version: ${version}.`);
    this.name = "UnsupportedMessageVersionError";
  }
}

export class MessageFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MessageFormatError";
  }
}

export class SignatureVerificationError extends Error {
  constructor() {
    super("Encrypted message signature verification failed.");
    this.name = "SignatureVerificationError";
  }
}

export class SessionKeyRecoveryError extends Error {
  constructor() {
    super("Unable to recover the AES session key with the recipient private key.");
    this.name = "SessionKeyRecoveryError";
  }
}

export class AuthenticatedDecryptionError extends Error {
  constructor() {
    super("AES-GCM authentication failed or ciphertext was invalid.");
    this.name = "AuthenticatedDecryptionError";
  }
}

export async function encryptMessage(
  plaintext: string,
  recipientPublicKey: CryptoKey,
  senderSigningPrivateKey: CryptoKey
): Promise<EncryptedMessage> {
  const plaintextBytes = textToBytes(plaintext);
  const aesKey = await generateAesGcmKey();
  const nonce = generateAesGcmNonce();
  const ciphertext = await encryptWithAesGcm(plaintextBytes, aesKey, nonce);
  const encryptedSessionKey = await wrapAesKeyWithRsaOaep(aesKey, recipientPublicKey);

  const unsignedMessage: UnsignedEncryptedMessage = {
    version: ENCRYPTED_MESSAGE_VERSION,
    encryptedSessionKey: bytesToBase64(encryptedSessionKey),
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext)
  };

  const signaturePayload = serializeForSignature(unsignedMessage);
  const signature = await signBytes(signaturePayload, senderSigningPrivateKey);

  return {
    ...unsignedMessage,
    signature: bytesToBase64(signature)
  };
}

export async function decryptMessage(
  encryptedMessage: EncryptedMessage,
  recipientPrivateKey: CryptoKey,
  senderSigningPublicKey: CryptoKey
): Promise<string> {
  if (encryptedMessage.version !== ENCRYPTED_MESSAGE_VERSION) {
    throw new UnsupportedMessageVersionError(encryptedMessage.version);
  }

  const encryptedSessionKey = decodeField(
    encryptedMessage.encryptedSessionKey,
    "encryptedSessionKey"
  );
  const nonce = new Uint8Array(decodeField(encryptedMessage.nonce, "nonce"));
  const ciphertext = decodeField(encryptedMessage.ciphertext, "ciphertext");
  const signature = decodeField(encryptedMessage.signature, "signature");

  if (nonce.byteLength !== AES_GCM_NONCE_LENGTH_BYTES) {
    throw new MessageFormatError("AES-GCM nonce must be 12 bytes.");
  }

  const unsignedMessage: UnsignedEncryptedMessage = {
    version: encryptedMessage.version,
    encryptedSessionKey: encryptedMessage.encryptedSessionKey,
    nonce: encryptedMessage.nonce,
    ciphertext: encryptedMessage.ciphertext
  };
  const signaturePayload = serializeForSignature(unsignedMessage);
  const isSignatureValid = await verifySignature(
    signaturePayload,
    signature,
    senderSigningPublicKey
  );

  if (!isSignatureValid) {
    throw new SignatureVerificationError();
  }

  let aesKey: CryptoKey;
  try {
    aesKey = await unwrapAesKeyWithRsaOaep(encryptedSessionKey, recipientPrivateKey);
  } catch {
    throw new SessionKeyRecoveryError();
  }

  try {
    const plaintextBytes = await decryptWithAesGcm(ciphertext, aesKey, nonce);
    return bytesToText(plaintextBytes);
  } catch {
    throw new AuthenticatedDecryptionError();
  }
}

function decodeField(value: string, fieldName: keyof EncryptedMessage): ArrayBuffer {
  try {
    return base64ToArrayBuffer(value);
  } catch {
    throw new MessageFormatError(`Encrypted message field "${fieldName}" is not valid Base64.`);
  }
}
