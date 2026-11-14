import type { IdentityVault } from "../pgp/identityVault";

// Separate from the RSA prototype's "gmail-e2ee" database so switching branches never mixes formats.
const DATABASE_NAME = "gmail-e2ee-openpgp";
const DATABASE_VERSION = 1;
const VAULT_STORE_NAME = "identity-vault";
const DEFAULT_VAULT_KEY = "default";

export class IdentityVaultStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdentityVaultStorageError";
  }
}

export async function saveIdentityVault(
  vault: IdentityVault,
  indexedDb: IDBFactory = indexedDB
): Promise<void> {
  const database = await openDatabase(indexedDb);

  try {
    const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
    const completed = waitForTransaction(transaction);
    transaction.objectStore(VAULT_STORE_NAME).put(vault, DEFAULT_VAULT_KEY);
    await completed;
  } catch {
    throw new IdentityVaultStorageError("Unable to save the identity vault.");
  } finally {
    database.close();
  }
}

export async function loadIdentityVault(
  indexedDb: IDBFactory = indexedDB
): Promise<unknown | undefined> {
  const database = await openDatabase(indexedDb);

  try {
    const transaction = database.transaction(VAULT_STORE_NAME, "readonly");
    const completed = waitForTransaction(transaction);
    const request = transaction.objectStore(VAULT_STORE_NAME).get(DEFAULT_VAULT_KEY);
    const vault = await waitForRequest(request);
    await completed;
    return vault;
  } catch {
    throw new IdentityVaultStorageError("Unable to load the identity vault.");
  } finally {
    database.close();
  }
}

export async function deleteIdentityVault(
  indexedDb: IDBFactory = indexedDB
): Promise<void> {
  const database = await openDatabase(indexedDb);

  try {
    const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
    const completed = waitForTransaction(transaction);
    transaction.objectStore(VAULT_STORE_NAME).delete(DEFAULT_VAULT_KEY);
    await completed;
  } catch {
    throw new IdentityVaultStorageError("Unable to delete the identity vault.");
  } finally {
    database.close();
  }
}

async function openDatabase(indexedDb: IDBFactory): Promise<IDBDatabase> {
  try {
    return await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDb.open(DATABASE_NAME, DATABASE_VERSION);

      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(VAULT_STORE_NAME)) {
          database.createObjectStore(VAULT_STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("IndexedDB upgrade was blocked."));
    });
  } catch {
    throw new IdentityVaultStorageError("Unable to open local identity storage.");
  }
}

function waitForRequest<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function waitForTransaction(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}
