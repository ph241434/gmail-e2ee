export const RSA_MODULUS_LENGTH_BITS = 2048;
export const RSA_PUBLIC_EXPONENT: Uint8Array<ArrayBuffer> = new Uint8Array([1, 0, 1]);

export async function generateRecipientEncryptionKeyPair(
  extractable = false
): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS_LENGTH_BITS,
      publicExponent: RSA_PUBLIC_EXPONENT,
      hash: "SHA-256"
    },
    extractable,
    ["wrapKey", "unwrapKey"]
  );
}

export async function generateSenderSigningKeyPair(
  extractable = false
): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: RSA_MODULUS_LENGTH_BITS,
      publicExponent: RSA_PUBLIC_EXPONENT,
      hash: "SHA-256"
    },
    extractable,
    ["sign", "verify"]
  );
}
