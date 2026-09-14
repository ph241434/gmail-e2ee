export const RSA_PSS_SALT_LENGTH_BYTES = 32;

export async function signBytes(
  data: BufferSource,
  senderPrivateKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.sign(
    {
      name: "RSA-PSS",
      saltLength: RSA_PSS_SALT_LENGTH_BYTES
    },
    senderPrivateKey,
    data
  );
}

export async function verifySignature(
  data: BufferSource,
  signature: BufferSource,
  senderPublicKey: CryptoKey
): Promise<boolean> {
  return crypto.subtle.verify(
    {
      name: "RSA-PSS",
      saltLength: RSA_PSS_SALT_LENGTH_BYTES
    },
    senderPublicKey,
    signature,
    data
  );
}
