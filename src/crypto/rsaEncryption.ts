export async function wrapAesKeyWithRsaOaep(
  aesKey: CryptoKey,
  recipientPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.wrapKey(
    "raw",
    aesKey,
    recipientPublicKey,
    {
      name: "RSA-OAEP"
    }
  );
}

export async function unwrapAesKeyWithRsaOaep(
  encryptedSessionKey: ArrayBuffer,
  recipientPrivateKey: CryptoKey
): Promise<CryptoKey> {
  return crypto.subtle.unwrapKey(
    "raw",
    encryptedSessionKey,
    recipientPrivateKey,
    {
      name: "RSA-OAEP"
    },
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["decrypt"]
  );
}
