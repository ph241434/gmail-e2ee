import { isVerifiedContactKey, normalizeContactKey, type Contact, type ContactKeyRole } from "../contacts/contact";
import { ContactStore } from "../storage/contactStorage";
import { markPublicKeyUnverified, markPublicKeyVerified } from "../trust/publicKeyTrust";
import type { KeySession } from "./keySession";

interface ContactView {
  prefix: "alice" | "pavel";
  contact?: Contact;
  select: HTMLSelectElement;
  name: HTMLInputElement;
  email: HTMLInputElement;
  save: HTMLButtonElement;
  remove: HTMLButtonElement;
  warning: HTMLParagraphElement;
  history: HTMLDivElement;
}

interface ContactUiActions {
  run: (message: string, action: () => Promise<void>) => Promise<void>;
  changed: () => void;
  status: (message: string) => void;
  confirm: (title: string, message: string) => Promise<boolean>;
}

export class ContactController {
  private readonly store = new ContactStore();
  private readonly views: Record<ContactKeyRole, ContactView>;
  private contacts: Contact[] = [];
  private ready = false;
  private busy = false;

  constructor(private readonly session: KeySession, private readonly actions: ContactUiActions) {
    this.views = {
      encryption: this.mount("alice", "encryption"),
      verification: this.mount("pavel", "verification")
    };
  }

  async initialize(): Promise<void> {
    await this.reloadList();
    this.ready = true;
    this.render();
  }

  resetBindings(): void {
    for (const view of Object.values(this.views)) {
      view.contact = undefined;
      view.select.value = "";
      view.name.value = "";
      view.email.value = "";
    }
    this.render();
  }

  setBusy(busy: boolean): void {
    this.busy = busy;
    this.render();
  }

  statusLabel(role: ContactKeyRole, verified: boolean): string {
    const view = this.views[role];
    const key = view.contact?.keys[role];
    if (key?.status === "changed" && key.fingerprint === this.fingerprint(role)) return "Key changed";
    return verified ? view.contact ? "Verified contact" : "Verified this session" : "Unverified";
  }

  async importKey(role: ContactKeyRole, pem: string): Promise<void> {
    const view = this.views[role];
    if (view.contact) {
      const updated = await this.store.updateKey(view.contact.id, view.contact.revision, role, pem);
      await this.applyToBindings(updated, role);
      await this.reloadList();
      this.actions.status(updated.keys[role]?.status === "changed"
        ? "Contact key changed. Compare the new fingerprint before using it."
        : "Contact key loaded. Its saved verification applies only to this fingerprint.");
    } else {
      const key = await normalizeContactKey(role, pem);
      this.setKey(role, key.publicKey, key.fingerprint);
      this.actions.status("Public key imported. Compare its fingerprint before use.");
    }
    this.actions.changed();
  }

  async setVerified(role: ContactKeyRole, verified: boolean): Promise<void> {
    const view = this.views[role];
    const trust = role === "encryption" ? this.session.recipientTrust : this.session.senderTrust;
    const fingerprint = this.fingerprint(role);
    if (!trust || !fingerprint) return;
    // A failed persistence operation must not leave a verified in-memory decision.
    if (role === "encryption") this.session.recipientTrust = markPublicKeyUnverified(trust);
    else this.session.senderTrust = markPublicKeyUnverified(trust);
    this.actions.changed();
    if (view.contact) {
      const updated = await this.store.setVerified(view.contact.id, view.contact.revision, role, fingerprint, verified);
      await this.applyToBindings(updated);
      await this.reloadList();
      this.actions.status(verified ? "Contact fingerprint verified and saved." : "Contact verification cleared.");
    } else {
      const next = verified ? markPublicKeyVerified(trust) : markPublicKeyUnverified(trust);
      if (role === "encryption") this.session.recipientTrust = next;
      else this.session.senderTrust = next;
      this.actions.status(verified ? "Fingerprint verified for this session." : "Fingerprint verification cleared.");
    }
    this.actions.changed();
  }

  async checkBeforeUse(role: ContactKeyRole): Promise<void> {
    const view = this.views[role];
    if (!view.contact) return;
    let current: Contact;
    try {
      current = await this.store.get(view.contact.id);
    } catch (error) {
      this.setKey(role);
      this.actions.changed();
      throw error;
    }
    const stale = !isVerifiedContactKey(current, role, this.fingerprint(role)) || current.email !== view.contact.email;
    await this.applyToBindings(current);
    this.actions.changed();
    if (stale) throw new Error("Contact key or verification changed. Review its current fingerprint before use.");
  }

  private mount(prefix: "alice" | "pavel", role: ContactKeyRole): ContactView {
    document.getElementById(`${prefix}-contact-picker`)!.innerHTML = `
      <label for="${prefix}-contact">Saved contact</label>
      <select id="${prefix}-contact" disabled><option value="">Unsaved key</option></select>
      <p id="${prefix}-key-warning" class="key-warning" role="alert" hidden></p>`;
    document.getElementById(`${prefix}-contact-editor`)!.innerHTML = `
      <form id="${prefix}-contact-form" class="contact-form">
        <div><label for="${prefix}-contact-name">Contact name</label>
          <input id="${prefix}-contact-name" type="text" maxlength="80" required></div>
        <div><label for="${prefix}-contact-email">Contact email</label>
          <input id="${prefix}-contact-email" type="email" maxlength="254" required></div>
        <div class="button-row">
          <button id="${prefix}-save-contact" class="secondary-button" type="submit" disabled>Save as contact</button>
          <button id="${prefix}-delete-contact" class="danger-button" type="button" hidden>Delete contact</button>
        </div>
      </form>
      <details class="contact-history"><summary>Verification history</summary>
        <div id="${prefix}-contact-history"></div></details>`;
    const view: ContactView = {
      prefix,
      select: document.getElementById(`${prefix}-contact`) as HTMLSelectElement,
      name: document.getElementById(`${prefix}-contact-name`) as HTMLInputElement,
      email: document.getElementById(`${prefix}-contact-email`) as HTMLInputElement,
      save: document.getElementById(`${prefix}-save-contact`) as HTMLButtonElement,
      remove: document.getElementById(`${prefix}-delete-contact`) as HTMLButtonElement,
      warning: document.getElementById(`${prefix}-key-warning`) as HTMLParagraphElement,
      history: document.getElementById(`${prefix}-contact-history`) as HTMLDivElement
    };
    view.select.addEventListener("change", () => {
      const id = view.select.value;
      this.setKey(role);
      view.contact = undefined;
      this.actions.changed();
      void this.actions.run("Loading contact...", async () => {
        if (id) await this.apply(role, await this.store.get(id));
        else this.clearView(role);
        this.actions.changed();
        this.actions.status(id ? "Contact loaded." : "Using an unsaved public key.");
      }).then(() => view.select.focus());
    });
    document.getElementById(`${prefix}-contact-form`)!.addEventListener("submit", (event) => {
      event.preventDefault();
      void this.actions.run("Saving contact...", async () => {
        if (view.contact) {
          const updated = await this.store.updateDetails(view.contact.id, view.contact.revision, view.name.value, view.email.value);
          await this.applyToBindings(updated);
        } else {
          if (!this.fingerprint(role)) throw new Error("Import a public key before saving this contact.");
          const pem = (document.getElementById(`${prefix}-public-key`) as HTMLTextAreaElement).value;
          await this.apply(role, await this.store.create(view.name.value, view.email.value, role, pem));
        }
        await this.reloadList();
        this.actions.changed();
        this.actions.status("Contact saved. A new contact or changed email requires fingerprint verification.");
      }).then(() => view.save.focus());
    });
    view.remove.addEventListener("click", async () => {
      const contact = view.contact;
      if (!contact || !await this.actions.confirm("Delete contact?", `Delete ${contact.name} and its saved keys, trust, and key-change history?`)) return;
      await this.actions.run("Deleting contact...", async () => {
        await this.store.delete(contact.id, contact.revision);
        for (const otherRole of ["encryption", "verification"] as const) {
          if (this.views[otherRole].contact?.id === contact.id) this.clearView(otherRole);
        }
        await this.reloadList();
        this.actions.changed();
        this.actions.status("Contact deleted. Active trust for that contact was cleared.");
      });
      view.select.focus();
    });
    return view;
  }

  private async apply(role: ContactKeyRole, contact: Contact): Promise<void> {
    const view = this.views[role];
    const saved = contact.keys[role];
    const normalized = saved ? await normalizeContactKey(role, saved.publicKeyPem) : undefined;
    view.contact = contact;
    view.select.value = contact.id;
    view.name.value = contact.name;
    view.email.value = contact.email;
    (document.getElementById(`${view.prefix}-public-key`) as HTMLTextAreaElement).value = saved?.publicKeyPem ?? "";
    this.setKey(role, normalized?.publicKey, normalized?.fingerprint);
    if (saved?.status === "verified") {
      if (role === "encryption") this.session.recipientTrust = markPublicKeyVerified(this.session.recipientTrust!);
      else this.session.senderTrust = markPublicKeyVerified(this.session.senderTrust!);
    }
    this.render();
  }

  private async applyToBindings(contact: Contact, forceRole?: ContactKeyRole): Promise<void> {
    for (const role of ["encryption", "verification"] as const) {
      const view = this.views[role];
      if (view.contact?.id !== contact.id) continue;
      // Preserve an edited PEM draft in the other role instead of restoring its saved trust.
      if (role === forceRole || (this.fingerprint(role) && this.fingerprint(role) === view.contact.keys[role]?.fingerprint)) {
        await this.apply(role, contact);
      } else {
        view.contact = contact;
        view.name.value = contact.name;
        view.email.value = contact.email;
      }
    }
    this.render();
  }

  private clearView(role: ContactKeyRole): void {
    const view = this.views[role];
    view.contact = undefined;
    view.select.value = "";
    view.name.value = "";
    view.email.value = "";
    (document.getElementById(`${view.prefix}-public-key`) as HTMLTextAreaElement).value = "";
    this.setKey(role);
    this.render();
  }

  private async reloadList(): Promise<void> {
    this.contacts = await this.store.list();
    for (const view of Object.values(this.views)) {
      view.select.replaceChildren(new Option("Unsaved key", ""));
      for (const contact of this.contacts) view.select.add(new Option(`${contact.name} (${contact.email})`, contact.id));
      view.select.value = view.contact?.id ?? "";
    }
  }

  private render(): void {
    for (const role of ["encryption", "verification"] as const) {
      const view = this.views[role];
      const key = view.contact?.keys[role];
      const changed = key?.status === "changed" && key.fingerprint === this.fingerprint(role);
      view.select.disabled = this.busy || !this.ready;
      view.name.disabled = this.busy || !this.ready;
      view.email.disabled = this.busy || !this.ready;
      view.save.disabled = this.busy || !this.ready || (!view.contact && !this.fingerprint(role));
      view.save.textContent = view.contact ? "Save contact details" : "Save as contact";
      view.remove.hidden = !view.contact;
      view.remove.disabled = this.busy;
      view.warning.hidden = !changed;
      view.warning.textContent = changed ? "Key changed. Compare this fingerprint again before use." : "";
      document.getElementById(`${view.prefix}-key-name`)!.textContent = view.contact?.name ?? (role === "encryption" ? "Alice" : "Pavel");
      document.getElementById(`${view.prefix}-verification-label`)!.textContent =
        `I compared this fingerprint with ${view.contact?.name ?? (role === "encryption" ? "Alice" : "Pavel")} through a separate trusted channel.`;
      view.history.replaceChildren();
      const summary = document.createElement("p");
      summary.textContent = key ? `First seen: ${key.firstSeenAt}. Verified: ${key.verifiedAt ?? "not verified"}.` : "No saved key for this role.";
      view.history.append(summary);
      for (const change of key?.changes ?? []) {
        const item = document.createElement("p");
        item.textContent = `${change.changedAt}: ${change.previousFingerprint} -> ${change.fingerprint}. Previous verification: ${change.previousVerifiedAt ?? "unverified"}.`;
        view.history.append(item);
      }
    }
  }

  private fingerprint(role: ContactKeyRole): string | undefined {
    return role === "encryption" ? this.session.recipientFingerprint : this.session.senderFingerprint;
  }

  private setKey(role: ContactKeyRole, key?: CryptoKey, fingerprint?: string): void {
    if (role === "encryption") this.session.setRecipientKey(key, fingerprint);
    else this.session.setSenderKey(key, fingerprint);
  }
}
