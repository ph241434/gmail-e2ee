import {
  ContactError,
  normalizeContactDetails,
  normalizeContactKey,
  parseContact,
  validateContactKeyMaterial,
  type Contact,
  type ContactKeyRole
} from "../contacts/contact";

const DATABASE_NAME = "gmail-e2ee-contacts";
const STORE_NAME = "contacts";

export class ContactConflictError extends ContactError {
  constructor() {
    super("This contact changed in another tab. Select it again before continuing.");
    this.name = "ContactConflictError";
  }
}

export class ContactStore {
  constructor(private readonly factory: IDBFactory = indexedDB) {}

  async list(): Promise<Contact[]> {
    const records = await this.read((store) => store.getAll());
    const contacts = await Promise.all(records.map((record: unknown) => validateContactKeyMaterial(parseContact(record))));
    return contacts.sort((left, right) => left.name.localeCompare(right.name) || left.email.localeCompare(right.email));
  }

  async get(id: string): Promise<Contact> {
    const record = await this.read((store) => store.get(id));
    if (record === undefined) throw new ContactError("This contact no longer exists. Select another contact.");
    return validateContactKeyMaterial(parseContact(record));
  }

  async create(name: string, email: string, role: ContactKeyRole, pem: string): Promise<Contact> {
    const details = normalizeContactDetails(name, email);
    const key = await normalizeContactKey(role, pem);
    const now = new Date().toISOString();
    const contact: Contact = {
      version: 1, id: crypto.randomUUID(), ...details, revision: 1,
      createdAt: now, updatedAt: now,
      keys: { [role]: {
        publicKeyPem: key.publicKeyPem, fingerprint: key.fingerprint,
        status: "unverified", firstSeenAt: now, verifiedAt: null, changes: []
      } }
    };
    await this.write(contact.id, null, () => contact);
    return contact;
  }

  async updateKey(id: string, revision: number, role: ContactKeyRole, pem: string): Promise<Contact> {
    const contact = await this.current(id, revision);
    const normalized = await normalizeContactKey(role, pem);
    const previous = contact.keys[role];
    // Matching key material preserves the decision, regardless of PEM whitespace.
    if (previous?.fingerprint === normalized.fingerprint) {
      await this.write(id, revision, () => ({ ...contact, revision: revision + 1 }));
      return { ...contact, revision: revision + 1 };
    }
    const now = new Date().toISOString();
    const updated: Contact = {
      ...contact, revision: revision + 1, updatedAt: now,
      keys: { ...contact.keys, [role]: {
        publicKeyPem: normalized.publicKeyPem, fingerprint: normalized.fingerprint,
        status: previous ? "changed" : "unverified", firstSeenAt: now, verifiedAt: null,
        changes: previous ? [...previous.changes, {
          previousFingerprint: previous.fingerprint, fingerprint: normalized.fingerprint,
          changedAt: now, previousVerifiedAt: previous.verifiedAt
        }] : []
      } }
    };
    await this.write(id, revision, () => updated);
    return updated;
  }

  async setVerified(id: string, revision: number, role: ContactKeyRole, fingerprint: string, verified: boolean): Promise<Contact> {
    const contact = await this.current(id, revision);
    const key = contact.keys[role];
    if (!key || key.fingerprint !== fingerprint) {
      throw new ContactError("The contact key changed. Compare its current fingerprint before verification.");
    }
    const now = new Date().toISOString();
    const updated: Contact = {
      ...contact, revision: revision + 1, updatedAt: now,
      keys: { ...contact.keys, [role]: {
        ...key, status: verified ? "verified" : key.status === "changed" ? "changed" : "unverified",
        verifiedAt: verified ? now : null
      } }
    };
    await this.write(id, revision, () => updated);
    return updated;
  }

  async updateDetails(id: string, revision: number, name: string, email: string): Promise<Contact> {
    const contact = await this.current(id, revision);
    const details = normalizeContactDetails(name, email);
    const keys = { ...contact.keys };
    if (details.email !== contact.email) {
      for (const role of ["encryption", "verification"] as const) {
        const key = keys[role];
        if (key) keys[role] = { ...key, status: "unverified", verifiedAt: null };
      }
    }
    const updated = { ...contact, ...details, keys, updatedAt: new Date().toISOString(), revision: revision + 1 };
    await this.write(id, revision, () => updated);
    return updated;
  }

  async delete(id: string, revision: number): Promise<void> {
    await this.current(id, revision);
    await this.write(id, revision, () => undefined);
  }

  private async current(id: string, revision: number): Promise<Contact> {
    const current = await this.get(id);
    if (current.revision !== revision) throw new ContactConflictError();
    return current;
  }

  private async read<T>(requestFor: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const database = await this.open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, "readonly");
        const request = requestFor(transaction.objectStore(STORE_NAME));
        transaction.oncomplete = () => resolve(request.result);
        transaction.onerror = () => reject(new ContactError("Unable to read saved contacts."));
        transaction.onabort = () => reject(new ContactError("Contact read was interrupted."));
      });
    } finally {
      database.close();
    }
  }

  private async write(id: string, revision: number | null, next: () => Contact | undefined): Promise<void> {
    const database = await this.open();
    try {
      await new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, "readwrite");
        const store = transaction.objectStore(STORE_NAME);
        const request = store.get(id);
        let failure: Error | undefined;
        request.onsuccess = () => {
          try {
            const current = request.result === undefined ? undefined : parseContact(request.result);
            if (revision === null ? current !== undefined : current?.revision !== revision) throw new ContactConflictError();
            const updated = next();
            if (updated) store.put(parseContact(updated));
            else store.delete(id);
          } catch (error) {
            failure = error instanceof Error ? error : new ContactError("Unable to update contact.");
            transaction.abort();
          }
        };
        transaction.oncomplete = () => resolve();
        transaction.onerror = (event) => {
          const error = (event.target as IDBRequest).error ?? transaction.error;
          failure ??= error?.name === "ConstraintError"
            ? new ContactError("A contact with this email already exists. Select it to add or update its key.")
            : new ContactError("Unable to save the contact.");
        };
        transaction.onabort = () => reject(failure ?? new ContactError("Contact update was interrupted."));
      });
    } finally {
      database.close();
    }
  }

  private async open(): Promise<IDBDatabase> {
    try {
      return await new Promise<IDBDatabase>((resolve, reject) => {
        const request = this.factory.open(DATABASE_NAME, 1);
        let blocked = false;
        request.onupgradeneeded = () => {
          const store = request.result.createObjectStore(STORE_NAME, { keyPath: "id" });
          store.createIndex("email", "email", { unique: true });
        };
        request.onblocked = () => { blocked = true; reject(new ContactError("Contact storage is blocked by another tab.")); };
        request.onsuccess = () => {
          if (blocked) request.result.close();
          else resolve(request.result);
        };
        request.onerror = () => reject(request.error);
      });
    } catch {
      throw new ContactError("Unable to open local contact storage.");
    }
  }
}
