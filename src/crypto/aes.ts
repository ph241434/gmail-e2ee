export const AES_GCM_KEY_LENGTH_BITS = 256;
export const AES_GCM_NONCE_LENGTH_BYTES = 12;

export async function generateAesGcmKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: AES_GCM_KEY_LENGTH_BITS
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export function generateAesGcmNonce(): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(new ArrayBuffer(AES_GCM_NONCE_LENGTH_BYTES));
  crypto.getRandomValues(nonce);
  return nonce;
}

export async function encryptWithAesGcm(
  plaintext: BufferSource,
  key: CryptoKey,
  nonce: BufferSource
): Promise<ArrayBuffer> {
  return crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce
    },
    key,
    plaintext
  );
}

export async function decryptWithAesGcm(
  ciphertext: BufferSource,
  key: CryptoKey,
  nonce: BufferSource
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce
    },
    key,
    ciphertext
  );
}
