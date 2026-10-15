import type { PrivateKeyVault } from "../crypto/privateKeyVault";

const DATABASE_NAME = "gmail-e2ee";
const DATABASE_VERSION = 1;
const VAULT_STORE_NAME = "private-key-vault";
const DEFAULT_VAULT_KEY = "default";

export class PrivateKeyVaultStorageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrivateKeyVaultStorageError";
  }
}

export async function savePrivateKeyVault(
  vault: PrivateKeyVault,
  indexedDb: IDBFactory = indexedDB
): Promise<void> {
  const database = await openDatabase(indexedDb);

  try {
    const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
    const completed = waitForTransaction(transaction);
    transaction.objectStore(VAULT_STORE_NAME).put(vault, DEFAULT_VAULT_KEY);
    await completed;
  } catch {
    throw new PrivateKeyVaultStorageError("Unable to save the private-key vault.");
  } finally {
    database.close();
  }
}

export async function loadPrivateKeyVault(
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
    throw new PrivateKeyVaultStorageError("Unable to load the private-key vault.");
  } finally {
    database.close();
  }
}

export async function deletePrivateKeyVault(
  indexedDb: IDBFactory = indexedDB
): Promise<void> {
  const database = await openDatabase(indexedDb);

  try {
    const transaction = database.transaction(VAULT_STORE_NAME, "readwrite");
    const completed = waitForTransaction(transaction);
    transaction.objectStore(VAULT_STORE_NAME).delete(DEFAULT_VAULT_KEY);
    await completed;
  } catch {
    throw new PrivateKeyVaultStorageError("Unable to delete the private-key vault.");
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
    throw new PrivateKeyVaultStorageError("Unable to open local private-key storage.");
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
