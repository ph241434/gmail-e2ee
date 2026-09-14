import { textToBytes } from "../crypto/encoding";
import type { UnsignedEncryptedMessage } from "./encryptedMessage";

export function serializeForSignature(
  message: UnsignedEncryptedMessage
): Uint8Array<ArrayBuffer> {
  const canonicalPayload = [
    `version:${message.version}`,
    `encryptedSessionKey:${message.encryptedSessionKey}`,
    `nonce:${message.nonce}`,
    `ciphertext:${message.ciphertext}`
  ].join("\n");

  return textToBytes(canonicalPayload);
}
