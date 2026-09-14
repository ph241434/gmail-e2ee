export const RSA_MODULUS_LENGTH_BITS = 2048;
export const RSA_PUBLIC_EXPONENT: Uint8Array<ArrayBuffer> = new Uint8Array([1, 0, 1]);

export async function generateRecipientEncryptionKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: RSA_MODULUS_LENGTH_BITS,
      publicExponent: RSA_PUBLIC_EXPONENT,
      hash: "SHA-256"
    },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

export async function generateSenderSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: RSA_MODULUS_LENGTH_BITS,
      publicExponent: RSA_PUBLIC_EXPONENT,
      hash: "SHA-256"
    },
    false,
    ["sign", "verify"]
  );
}
