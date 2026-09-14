export function bytesToBase64(data: BufferSource): string {
  const bytes = toUint8Array(data);
  let binary = "";
  const chunkSize = 0x8000;

  for (let index = 0; index < bytes.length; index += chunkSize) {
    const chunk = bytes.subarray(index, index + chunkSize);
    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}

export function base64ToArrayBuffer(value: string): ArrayBuffer {
  if (!isValidBase64(value)) {
    throw new Error("Value is not valid Base64.");
  }

  const binary = atob(value);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return buffer;
}

export function textToBytes(value: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(value);
}

export function bytesToText(value: BufferSource): string {
  return new TextDecoder().decode(toUint8Array(value));
}

export function toUint8Array(data: BufferSource): Uint8Array<ArrayBuffer> {
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }

  return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
}

function isValidBase64(value: string): boolean {
  if (value.length === 0 || value.length % 4 !== 0) {
    return false;
  }

  return /^[A-Za-z0-9+/]*={0,2}$/.test(value);
}
