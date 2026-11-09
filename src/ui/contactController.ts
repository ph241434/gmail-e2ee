import type * as openpgp from "openpgp";
import { isVerifiedContactKey, normalizeContactKey, type Contact } from "../contacts/contact";
import { formatFingerprint } from "../pgp/keys";
import { ContactStore } from "../storage/contactStorage";
import { markPublicKeyUnverified, markPublicKeyVerified } from "../trust/publicKeyTrust";
import type { KeySession } from "./keySession";

/** Which binding a card controls: the key we encrypt to, or the signer we require. */
export type BindingSlot = "recipient" | "sender";

const SLOTS = ["recipient", "sender"] as const;
const DEFAULT_NAMES: Record<BindingSlot, string> = { recipient: "Recipient", sender: "Sender" };

interface ContactView {
  slot: BindingSlot;
  contact?: Contact;
  select: HTMLSelectElement;
  name: HTMLInputElement;
  email: HTMLInputElement;
  save: HTMLButtonElement;
  remove: HTMLButtonElement;
  warning: HTMLParagraphElement;
  history: HTMLDivElement;
  keyText: HTMLTextAreaElement;
}

interface ContactUiActions {
  run: (message: string, action: () => Promise<void>) => Promise<void>;
  changed: () => void;
  status: (message: string) => void;
  confirm: (title: string, message: string) => Promise<boolean>;
}

export class ContactController {
  private readonly store = new ContactStore();
  private readonly views: Record<BindingSlot, ContactView>;
  private contacts: Contact[] = [];
  private ready = false;
  private busy = false;

  constructor(private readonly session: KeySession, private readonly actions: ContactUiActions) {
    this.views = { recipient: this.mount("recipient"), sender: this.mount("sender") };
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

  isOwnKey(slot: BindingSlot): boolean {
    return this.session.isOwnKey(this.fingerprint(slot));
  }

  statusLabel(slot: BindingSlot, verified: boolean): string {
    const view = this.views[slot];
    if (this.isOwnKey(slot)) return "Your key";
    const key = view.contact?.key;
    if (key?.status === "changed" && key.fingerprint === this.fingerprint(slot)) return "Key changed";
    return verified ? view.contact ? "Verified contact" : "Verified this session" : "Unverified";
  }

  async importKey(slot: BindingSlot, armoredKey: string): Promise<void> {
    const view = this.views[slot];
    if (view.contact) {
      const updated = await this.store.updateKey(view.contact.id, view.contact.revision, armoredKey);
      await this.applyToBindings(updated, slot);
      await this.reloadList();
      this.actions.status(updated.key.status === "changed"
        ? "Contact key changed. Compare the new fingerprint before using it."
        : "Contact key loaded. Its saved verification applies only to this fingerprint.");
    } else {
      const parsed = await normalizeContactKey(armoredKey);
      this.setKey(slot, parsed.key, parsed.fingerprint);
      view.keyText.value = parsed.armoredKey;
      if (!this.session.isOwnKey(parsed.fingerprint)) {
        // Prefill from the key's self-signed primary user ID; the user can still edit before saving.
        view.name.value ||= parsed.primaryUser.name;
        view.email.value ||= parsed.primaryUser.email;
      }
      this.actions.status(this.session.isOwnKey(parsed.fingerprint)
        ? "This is your own key."
        : `Public key for ${parsed.emails.join(", ") || "no email"} imported. Compare its fingerprint before use.`);
    }
    this.actions.changed();
  }

  async setVerified(slot: BindingSlot, verified: boolean): Promise<void> {
    const view = this.views[slot];
    const trust = slot === "recipient" ? this.session.recipientTrust : this.session.senderTrust;
    const fingerprint = this.fingerprint(slot);
    if (!trust || !fingerprint || this.isOwnKey(slot)) return;
    // A failed persistence operation must not leave a verified in-memory decision.
    this.setTrust(slot, markPublicKeyUnverified(trust));
    this.actions.changed();
    if (view.contact) {
      const updated = await this.store.setVerified(view.contact.id, view.contact.revision, fingerprint, verified);
      await this.applyToBindings(updated);
      await this.reloadList();
      this.actions.status(verified ? "Contact fingerprint verified and saved." : "Contact verification cleared.");
    } else {
      this.setTrust(slot, verified ? markPublicKeyVerified(trust) : markPublicKeyUnverified(trust));
      this.actions.status(verified ? "Fingerprint verified for this session." : "Fingerprint verification cleared.");
    }
    this.actions.changed();
  }

  async checkBeforeUse(slot: BindingSlot): Promise<void> {
    const view = this.views[slot];
    if (!view.contact || this.isOwnKey(slot)) return;
    let current: Contact;
    try {
      current = await this.store.get(view.contact.id);
    } catch (error) {
      this.setKey(slot);
      this.actions.changed();
      throw error;
    }
    const stale = !isVerifiedContactKey(current, this.fingerprint(slot)) || current.email !== view.contact.email;
    await this.applyToBindings(current);
    this.actions.changed();
    if (stale) throw new Error("Contact key or verification changed. Review its current fingerprint before use.");
  }

  private mount(slot: BindingSlot): ContactView {
    document.getElementById(`${slot}-contact-picker`)!.innerHTML = `
      <label for="${slot}-contact">Saved contact</label>
      <select id="${slot}-contact" disabled><option value="">Unsaved key</option></select>
      <p id="${slot}-key-warning" class="key-warning" role="alert" hidden></p>`;
    document.getElementById(`${slot}-contact-editor`)!.innerHTML = `
      <form id="${slot}-contact-form" class="contact-form">
        <div><label for="${slot}-contact-name">Contact name</label>
          <input id="${slot}-contact-name" type="text" maxlength="80" required></div>
        <div><label for="${slot}-contact-email">Contact email</label>
          <input id="${slot}-contact-email" type="email" maxlength="254" required></div>
        <div class="button-row">
          <button id="${slot}-save-contact" class="secondary-button" type="submit" disabled>Save as contact</button>
          <button id="${slot}-delete-contact" class="danger-button" type="button" hidden>Delete contact</button>
        </div>
      </form>
      <details class="contact-history"><summary>Verification history</summary>
        <div id="${slot}-contact-history"></div></details>`;
    const view: ContactView = {
      slot,
      select: document.getElementById(`${slot}-contact`) as HTMLSelectElement,
      name: document.getElementById(`${slot}-contact-name`) as HTMLInputElement,
      email: document.getElementById(`${slot}-contact-email`) as HTMLInputElement,
      save: document.getElementById(`${slot}-save-contact`) as HTMLButtonElement,
      remove: document.getElementById(`${slot}-delete-contact`) as HTMLButtonElement,
      warning: document.getElementById(`${slot}-key-warning`) as HTMLParagraphElement,
      history: document.getElementById(`${slot}-contact-history`) as HTMLDivElement,
      keyText: document.getElementById(`${slot}-public-key`) as HTMLTextAreaElement
    };
    view.select.addEventListener("change", () => {
      const id = view.select.value;
      this.setKey(slot);
      view.contact = undefined;
      this.actions.changed();
      void this.actions.run("Loading contact...", async () => {
        if (id) await this.apply(slot, await this.store.get(id));
        else this.clearView(slot);
        this.actions.changed();
        this.actions.status(id ? "Contact loaded." : "Using an unsaved public key.");
      }).then(() => view.select.focus());
    });
    document.getElementById(`${slot}-contact-form`)!.addEventListener("submit", (event) => {
      event.preventDefault();
      void this.actions.run("Saving contact...", async () => {
        if (view.contact) {
          const updated = await this.store.updateDetails(view.contact.id, view.contact.revision, view.name.value, view.email.value);
          await this.applyToBindings(updated);
        } else {
          if (!this.fingerprint(slot)) throw new Error("Import a public key before saving this contact.");
          if (this.isOwnKey(slot)) throw new Error("This is your own key. It is already saved in your identity vault.");
          await this.apply(slot, await this.store.create(view.name.value, view.email.value, view.keyText.value));
        }
        await this.reloadList();
        this.actions.changed();
        this.actions.status("Contact saved. A new contact or changed email requires fingerprint verification.");
      }).then(() => view.save.focus());
    });
    view.remove.addEventListener("click", async () => {
      const contact = view.contact;
      if (!contact || !await this.actions.confirm("Delete contact?", `Delete ${contact.name} and its saved key, trust, and key-change history?`)) return;
      await this.actions.run("Deleting contact...", async () => {
        await this.store.delete(contact.id, contact.revision);
        for (const other of SLOTS) {
          if (this.views[other].contact?.id === contact.id) this.clearView(other);
        }
        await this.reloadList();
        this.actions.changed();
        this.actions.status("Contact deleted. Active trust for that contact was cleared.");
      });
      view.select.focus();
    });
    return view;
  }

  private async apply(slot: BindingSlot, contact: Contact): Promise<void> {
    const view = this.views[slot];
    const parsed = await normalizeContactKey(contact.key.publicKeyArmored);
    view.contact = contact;
    view.select.value = contact.id;
    view.name.value = contact.name;
    view.email.value = contact.email;
    view.keyText.value = contact.key.publicKeyArmored;
    this.setKey(slot, parsed.key, parsed.fingerprint);
    if (contact.key.status === "verified" && contact.key.fingerprint === parsed.fingerprint) {
      const trust = slot === "recipient" ? this.session.recipientTrust : this.session.senderTrust;
      this.setTrust(slot, markPublicKeyVerified(trust!));
    }
    this.render();
  }

  private async applyToBindings(contact: Contact, forceSlot?: BindingSlot): Promise<void> {
    for (const slot of SLOTS) {
      const view = this.views[slot];
      if (view.contact?.id !== contact.id) continue;
      // Re-apply only where the card still shows the saved key, so an unsaved draft is never
      // replaced by restored trust.
      if (slot === forceSlot || (this.fingerprint(slot) && this.fingerprint(slot) === view.contact.key.fingerprint)) {
        await this.apply(slot, contact);
      } else {
        view.contact = contact;
        view.name.value = contact.name;
        view.email.value = contact.email;
      }
    }
    this.render();
  }

  private clearView(slot: BindingSlot): void {
    const view = this.views[slot];
    view.contact = undefined;
    view.select.value = "";
    view.name.value = "";
    view.email.value = "";
    view.keyText.value = "";
    this.setKey(slot);
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
    for (const slot of SLOTS) {
      const view = this.views[slot];
      const key = view.contact?.key;
      const own = this.isOwnKey(slot);
      const changed = key?.status === "changed" && key.fingerprint === this.fingerprint(slot);
      const displayName = own ? "You" : view.contact?.name ?? DEFAULT_NAMES[slot];
      view.select.disabled = this.busy || !this.ready;
      view.name.disabled = this.busy || !this.ready;
      view.email.disabled = this.busy || !this.ready;
      view.save.disabled = this.busy || !this.ready || own || (!view.contact && !this.fingerprint(slot));
      view.save.textContent = view.contact ? "Save contact details" : "Save as contact";
      view.remove.hidden = !view.contact;
      view.remove.disabled = this.busy;
      view.warning.hidden = !changed;
      view.warning.textContent = changed ? "Key changed. Compare this fingerprint again before use." : "";
      document.getElementById(`${slot}-key-name`)!.textContent = displayName;
      document.getElementById(`${slot}-verification-label`)!.textContent = own
        ? "This is your own key from your identity vault."
        : `I compared this fingerprint with ${displayName} through a separate trusted channel.`;
      view.history.replaceChildren();
      const summary = document.createElement("p");
      summary.textContent = key ? `First seen: ${key.firstSeenAt}. Verified: ${key.verifiedAt ?? "not verified"}.` : "No saved key for this binding.";
      view.history.append(summary);
      for (const change of key?.changes ?? []) {
        const item = document.createElement("p");
        item.textContent = `${change.changedAt}: ${formatFingerprint(change.previousFingerprint)} -> ${formatFingerprint(change.fingerprint)}. Previous verification: ${change.previousVerifiedAt ?? "unverified"}.`;
        view.history.append(item);
      }
    }
  }

  private fingerprint(slot: BindingSlot): string | undefined {
    return slot === "recipient" ? this.session.recipientFingerprint : this.session.senderFingerprint;
  }

  private setKey(slot: BindingSlot, key?: openpgp.PublicKey, fingerprint?: string): void {
    if (slot === "recipient") this.session.setRecipientKey(key, fingerprint);
    else this.session.setSenderKey(key, fingerprint);
  }

  private setTrust(slot: BindingSlot, trust: ReturnType<typeof markPublicKeyVerified>): void {
    if (slot === "recipient") this.session.recipientTrust = trust;
    else this.session.senderTrust = trust;
  }
}
