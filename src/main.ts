import "./style.css";
import {
  createIdentityVault,
  createTemporaryIdentity,
  IDENTITY_VAULT_MAX_PASSPHRASE_LENGTH,
  IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH,
  unlockIdentityVault,
  getDecryptionKeys,
  rotateIdentityVault,
  type IdentityVault,
  type UnlockedIdentity
} from "./pgp/identityVault";
import { describeRecipientProblem, parseAddressList, resolveRecipients } from "./contacts/recipients";
import { describeSigner, ownSigners } from "./contacts/signers";
import { createIdentityBackup, exportPrivateKey, importPrivateKey, restoreIdentityBackup } from "./pgp/identityBackup";
import { formatFingerprint } from "./pgp/keys";
import { decryptMessage, encryptMessage, getKeyIds, getMessageRecipientKeyIds } from "./pgp/message";
import { deleteIdentityVault, loadIdentityVault, saveIdentityVault } from "./storage/identityVaultStorage";
import { isPublicKeyVerified } from "./trust/publicKeyTrust";
import { getVaultView, KeySession, type ActiveKeySource } from "./ui/keySession";
import { ContactController } from "./ui/contactController";

const TEMPORARY_IDENTITY = { name: "Temporary identity", email: "temporary@example.invalid" };

const session = new KeySession();
let vaultExists = false;
let storageReady = false;
let isBusy = false;
/** Key IDs of the extra recipients of the last message encrypted here, for labelling. */
let extraRecipientLabels = new Map<string, string>();

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("App root was not found.");

const passphraseAttributes = `type="password" minlength="${IDENTITY_VAULT_MIN_PASSPHRASE_LENGTH}"
  maxlength="${IDENTITY_VAULT_MAX_PASSPHRASE_LENGTH}" autocomplete="new-password"
  autocapitalize="none" spellcheck="false" required`;

function identityFields(prefix: string): string {
  return `
    <div class="passphrase-field">
      <label for="${prefix}-name">Your name</label>
      <input id="${prefix}-name" type="text" maxlength="80" autocomplete="name" required>
    </div>
    <div class="passphrase-field">
      <label for="${prefix}-email">Your email</label>
      <input id="${prefix}-email" type="email" maxlength="254" autocomplete="email" required>
    </div>`;
}

function keyCard(slot: "recipient" | "sender", role: string, textLabel: string, importLabel: string): string {
  return `
    <article class="key-card">
      <div class="key-heading">
        <h3><span id="${slot}-key-name" class="key-name"></span><span>${role}</span></h3>
        <span id="${slot}-trust-status" class="trust-status">Unverified</span>
      </div>
      <div id="${slot}-contact-picker" class="contact-picker"></div>
      <code id="${slot}-fingerprint" class="fingerprint-value" aria-label="OpenPGP fingerprint">No key loaded</code>
      <label class="trust-checkbox" for="verify-${slot}-key">
        <input id="verify-${slot}-key" type="checkbox" disabled>
        <span id="${slot}-verification-label"></span>
      </label>
      <details id="${slot}-key-details" class="key-details">
        <summary>Public key text</summary>
        <label for="${slot}-public-key">${textLabel}</label>
        <textarea id="${slot}-public-key" class="public-key-input" spellcheck="false" placeholder="Paste an armored OpenPGP public key"></textarea>
        <div class="button-row">
          <button id="copy-${slot}-key" class="secondary-button" type="button" disabled>Copy public key</button>
          <button id="import-${slot}-key" type="button" disabled>${importLabel}</button>
        </div>
        <div id="${slot}-contact-editor"></div>
      </details>
    </article>`;
}

app.innerHTML = `
  <main class="app-shell">
    <header class="masthead">
      <h1>Gmail E2EE</h1>
      <span id="vault-status" class="status-badge" role="status">Checking vault...</span>
    </header>
    <p id="operation-status" class="operation-status" role="status" aria-live="polite" aria-atomic="true">Ready</p>

    <section class="key-vault-section" aria-label="Identity vault">
      <form id="vault-form" class="vault-controls">
        <div id="identity-fields" class="vault-controls">${identityFields("identity")}</div>
        <div id="passphrase-field" class="passphrase-field">
          <label for="vault-passphrase">Vault passphrase</label>
          <input id="vault-passphrase" ${passphraseAttributes}>
        </div>
        <button id="vault-action" type="submit" disabled>Create identity</button>
      </form>
      <div id="identity-summary" class="identity-summary" hidden>
        <p><span id="identity-user-id" class="key-name"></span></p>
        <code id="identity-fingerprint" class="fingerprint-value" aria-label="Your OpenPGP fingerprint"></code>
        <div class="button-row"><button id="copy-identity-key" class="secondary-button" type="button">Copy my public key</button></div>
      </div>
      <details id="advanced-key-options" class="advanced-options">
        <summary>Advanced key options</summary>
        <div class="advanced-actions">
          <button id="generate-keys" class="secondary-button" type="button">Use a temporary identity</button>
          <button id="delete-vault" class="danger-button" type="button" hidden>Delete vault</button>
        </div>
        <form id="rotate-key-form" class="vault-controls" hidden>
          <div class="passphrase-field">
            <label for="rotate-passphrase">Vault passphrase, to rotate your key</label>
            <input id="rotate-passphrase" ${passphraseAttributes.replace("new-password", "current-password")}>
          </div>
          <button id="rotate-key" class="secondary-button" type="submit">Rotate key</button>
        </form>
        <form id="replace-vault-form" class="vault-controls" hidden>
          ${identityFields("replace")}
          <div class="passphrase-field">
            <label for="new-vault-passphrase">New vault passphrase</label>
            <input id="new-vault-passphrase" ${passphraseAttributes}>
          </div>
          <button id="replace-vault" type="submit">Replace vault</button>
        </form>
      </details>
      <details id="backup-options" class="advanced-options">
        <summary>Backup and import</summary>
        <div class="advanced-actions">
          <button id="download-backup" class="secondary-button" type="button" hidden>Download backup</button>
        </div>
        <form id="restore-backup-form" class="vault-controls">
          <div class="passphrase-field">
            <label for="restore-file">Backup file to restore</label>
            <input id="restore-file" type="file" accept=".json,application/json" required>
          </div>
          <div class="passphrase-field">
            <label for="restore-passphrase">Vault passphrase of that backup</label>
            <input id="restore-passphrase" ${passphraseAttributes.replace("new-password", "current-password")}>
          </div>
          <button id="restore-backup" class="secondary-button" type="submit">Restore backup</button>
        </form>
        <form id="export-key-form" class="vault-controls" hidden>
          <div class="passphrase-field">
            <label for="export-passphrase">New passphrase for the exported key</label>
            <input id="export-passphrase" ${passphraseAttributes}>
          </div>
          <button id="export-key" class="secondary-button" type="submit">Export private key</button>
        </form>
        <form id="import-key-form" class="import-key-form">
          <label for="import-key-text">Existing OpenPGP private key to import</label>
          <textarea id="import-key-text" class="public-key-input" spellcheck="false" autocomplete="off" required
            placeholder="-----BEGIN PGP PRIVATE KEY BLOCK-----"></textarea>
          <div class="vault-controls">
            <div class="passphrase-field">
              <label for="import-key-passphrase">Passphrase of that key, if it has one</label>
              <input id="import-key-passphrase" type="password" maxlength="1024" autocomplete="off" autocapitalize="none" spellcheck="false">
            </div>
            <div class="passphrase-field">
              <label for="import-vault-passphrase">New vault passphrase</label>
              <input id="import-vault-passphrase" ${passphraseAttributes}>
            </div>
            <button id="import-key" class="secondary-button" type="submit">Import key</button>
          </div>
        </form>
      </details>
    </section>

    <section class="public-key-section" aria-labelledby="public-key-heading">
      <h2 id="public-key-heading">Key verification</h2>
      <div class="public-key-grid">
        ${keyCard("recipient", "Encrypt to", "Recipient OpenPGP public key", "Import recipient key")}
        ${keyCard("sender", "Expected signer", "Sender OpenPGP public key", "Import sender key")}
      </div>
    </section>

    <section class="message-section" aria-labelledby="message-heading">
      <h2 id="message-heading">Message</h2>
      <div class="workspace-grid">
        <div class="message-column">
          <label for="plaintext">Message to send</label>
          <textarea id="plaintext" spellcheck="true">Meet me at 4 PM.</textarea>
          <label for="extra-recipients" class="spaced-label">Also send to (emails of verified contacts)</label>
          <input id="extra-recipients" type="text" spellcheck="false" autocomplete="off" placeholder="alice@example.com, bob@example.com">
          <button id="encrypt" type="button" disabled>Sign and encrypt</button>
        </div>
        <div class="message-column">
          <label for="decrypted-message">Decrypted message</label>
          <output id="decrypted-message">Nothing decrypted yet</output>
          <button id="decrypt" type="button" disabled>Decrypt and verify</button>
        </div>
      </div>
      <details id="package-details" class="package-details">
        <summary>Encrypted message (OpenPGP)</summary>
        <div class="package-heading">
          <label for="encrypted-package">Armored OpenPGP message</label>
          <button id="tamper-ciphertext" class="secondary-button" type="button" disabled>Tamper ciphertext</button>
        </div>
        <textarea id="encrypted-package" spellcheck="false" placeholder="-----BEGIN PGP MESSAGE----- appears here, or paste one from GnuPG, Thunderbird, Proton, or Mailvelope"></textarea>
        <dl class="field-list" aria-label="Message details">
          <div><dt>Encrypted to</dt><dd id="message-recipients">No message</dd></div>
          <div><dt>Format</dt><dd>Signed, then encrypted (RFC 9580, v4 keys): one session key wrapped per recipient, including you</dd></div>
        </dl>
      </details>
    </section>
  </main>
  <dialog id="vault-confirmation" aria-labelledby="confirmation-title" aria-describedby="confirmation-message">
    <h2 id="confirmation-title"></h2>
    <p id="confirmation-message"></p>
    <form method="dialog" class="confirmation-actions">
      <button class="secondary-button" value="cancel" autofocus>Cancel</button>
      <button id="confirm-vault-action" class="danger-button" value="confirm"></button>
    </form>
  </dialog>
`;

const vaultForm = getElement<HTMLFormElement>("vault-form");
const vaultActionButton = getElement<HTMLButtonElement>("vault-action");
const identityFieldsGroup = getElement<HTMLDivElement>("identity-fields");
const identityNameInput = getElement<HTMLInputElement>("identity-name");
const identityEmailInput = getElement<HTMLInputElement>("identity-email");
const passphraseField = getElement<HTMLDivElement>("passphrase-field");
const vaultPassphraseInput = getElement<HTMLInputElement>("vault-passphrase");
const identitySummary = getElement<HTMLDivElement>("identity-summary");
const identityUserId = getElement<HTMLSpanElement>("identity-user-id");
const identityFingerprint = getElement<HTMLElement>("identity-fingerprint");
const copyIdentityKeyButton = getElement<HTMLButtonElement>("copy-identity-key");
const advancedOptions = getElement<HTMLDetailsElement>("advanced-key-options");
const rotateKeyForm = getElement<HTMLFormElement>("rotate-key-form");
const rotateKeyButton = getElement<HTMLButtonElement>("rotate-key");
const rotatePassphraseInput = getElement<HTMLInputElement>("rotate-passphrase");
const extraRecipientsInput = getElement<HTMLInputElement>("extra-recipients");
const downloadBackupButton = getElement<HTMLButtonElement>("download-backup");
const restoreBackupForm = getElement<HTMLFormElement>("restore-backup-form");
const restoreFileInput = getElement<HTMLInputElement>("restore-file");
const restorePassphraseInput = getElement<HTMLInputElement>("restore-passphrase");
const exportKeyForm = getElement<HTMLFormElement>("export-key-form");
const exportPassphraseInput = getElement<HTMLInputElement>("export-passphrase");
const importKeyForm = getElement<HTMLFormElement>("import-key-form");
const importKeyTextInput = getElement<HTMLTextAreaElement>("import-key-text");
const importKeyPassphraseInput = getElement<HTMLInputElement>("import-key-passphrase");
const importVaultPassphraseInput = getElement<HTMLInputElement>("import-vault-passphrase");
const backupControls = [
  downloadBackupButton, restoreFileInput, restorePassphraseInput, getElement<HTMLButtonElement>("restore-backup"),
  exportPassphraseInput, getElement<HTMLButtonElement>("export-key"),
  importKeyTextInput, importKeyPassphraseInput, importVaultPassphraseInput, getElement<HTMLButtonElement>("import-key")
];
const replaceVaultForm = getElement<HTMLFormElement>("replace-vault-form");
const replaceVaultButton = getElement<HTMLButtonElement>("replace-vault");
const replaceNameInput = getElement<HTMLInputElement>("replace-name");
const replaceEmailInput = getElement<HTMLInputElement>("replace-email");
const newVaultPassphraseInput = getElement<HTMLInputElement>("new-vault-passphrase");
const generateKeysButton = getElement<HTMLButtonElement>("generate-keys");
const deleteVaultButton = getElement<HTMLButtonElement>("delete-vault");
const encryptButton = getElement<HTMLButtonElement>("encrypt");
const decryptButton = getElement<HTMLButtonElement>("decrypt");
const tamperCiphertextButton = getElement<HTMLButtonElement>("tamper-ciphertext");
const plaintextInput = getElement<HTMLTextAreaElement>("plaintext");
const encryptedPackageInput = getElement<HTMLTextAreaElement>("encrypted-package");
const messageRecipients = getElement<HTMLElement>("message-recipients");
const decryptedMessageOutput = getElement<HTMLOutputElement>("decrypted-message");
const operationStatus = getElement<HTMLParagraphElement>("operation-status");
const vaultStatus = getElement<HTMLSpanElement>("vault-status");
const confirmationDialog = getElement<HTMLDialogElement>("vault-confirmation");
const confirmationTitle = getElement<HTMLHeadingElement>("confirmation-title");
const confirmationMessage = getElement<HTMLParagraphElement>("confirmation-message");
const confirmVaultActionButton = getElement<HTMLButtonElement>("confirm-vault-action");

const cards = (["recipient", "sender"] as const).map((slot) => ({
  slot,
  keyInput: getElement<HTMLTextAreaElement>(`${slot}-public-key`),
  copyButton: getElement<HTMLButtonElement>(`copy-${slot}-key`),
  importButton: getElement<HTMLButtonElement>(`import-${slot}-key`),
  verifyCheckbox: getElement<HTMLInputElement>(`verify-${slot}-key`),
  fingerprint: getElement<HTMLElement>(`${slot}-fingerprint`),
  trustStatus: getElement<HTMLSpanElement>(`${slot}-trust-status`)
}));

const contactController = new ContactController(session, {
  run: runOperation,
  changed: () => {
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    renderTrust();
    renderControls();
  },
  status: setStatus,
  confirm: confirmAction
});

vaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy) return;
  const { mode } = getVaultView(vaultExists, session.source);
  if (mode === "unlocked" || mode === "temporary") {
    clearActiveKeys();
    setStatus(mode === "unlocked" ? "Vault locked." : "Temporary identity cleared.");
    focusVaultControl();
    return;
  }
  if (!storageReady) return;
  if (mode === "setup") {
    await createAndSaveVault(identityNameInput, identityEmailInput, vaultPassphraseInput);
    return;
  }
  await runOperation("Unlocking vault...", async () => {
    const vault = await loadIdentityVault();
    if (vault === undefined) {
      vaultExists = false;
      throw new Error("No saved identity was found in this browser.");
    }
    activateIdentity(await unlockIdentityVault(vault, vaultPassphraseInput.value), "vault");
    setStatus("Vault unlocked. Your own key is selected on both cards.");
    focusVaultControl();
  });
});

replaceVaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy || !storageReady) return;
  await createAndSaveVault(replaceNameInput, replaceEmailInput, newVaultPassphraseInput);
});

downloadBackupButton.addEventListener("click", async () => {
  await runOperation("Preparing backup...", async () => {
    const vault = await loadIdentityVault();
    if (vault === undefined) throw new Error("No saved identity was found in this browser.");
    const backup = createIdentityBackup(vault as IdentityVault);
    downloadText(`gmail-e2ee-backup-${(vault as IdentityVault).fingerprint.slice(-8)}.json`, backup, "application/json");
    setStatus("Backup downloaded. It opens only with your vault passphrase, so keep both.");
  });
});

restoreBackupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = restoreFileInput.files?.[0];
  if (isBusy || !storageReady || !file) return;
  if (vaultExists && !await confirmVaultAction("replace")) return;
  await runOperation("Restoring backup...", async () => {
    // The backup must open with its passphrase before it may replace anything.
    const restored = await restoreIdentityBackup(await file.text(), restorePassphraseInput.value);
    await saveIdentityVault(restored.vault);
    vaultExists = true;
    activateIdentity(restored.identity, "vault");
    restoreFileInput.value = "";
    setStatus("Backup restored and unlocked.");
    focusVaultControl();
  });
});

exportKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy || !session.identity) return;
  const identity = session.identity;
  await runOperation("Exporting private key...", async () => {
    const armored = await exportPrivateKey(identity, exportPassphraseInput.value);
    downloadText(`${identity.publicKey.primaryUser.email}-private-key.asc`, armored, "application/pgp-keys");
    setStatus("Private key exported. Other OpenPGP apps can import it with the passphrase you just set.");
  });
});

importKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy || !storageReady) return;
  if (vaultExists && !await confirmVaultAction("replace")) return;
  await runOperation("Importing private key...", async () => {
    const imported = await importPrivateKey(
      importKeyTextInput.value, importKeyPassphraseInput.value, importVaultPassphraseInput.value
    );
    await saveIdentityVault(imported.vault);
    vaultExists = true;
    activateIdentity(imported.identity, "vault");
    setStatus("Key imported, sealed in a new vault, and unlocked.");
    focusVaultControl();
  });
});

generateKeysButton.addEventListener("click", async () => {
  await runOperation("Generating temporary identity...", async () => {
    activateIdentity(await createTemporaryIdentity(TEMPORARY_IDENTITY), "ephemeral");
    advancedOptions.open = false;
    setStatus("Temporary identity ready. It is not saved.");
    focusVaultControl();
  });
});

deleteVaultButton.addEventListener("click", async () => {
  if (isBusy || !vaultExists || !await confirmVaultAction("delete")) return;
  await runOperation("Deleting vault...", async () => {
    await deleteIdentityVault();
    vaultExists = false;
    if (session.source === "vault") clearActiveKeys();
    advancedOptions.open = false;
    setStatus("Saved identity deleted.");
    focusVaultControl();
  });
});

encryptButton.addEventListener("click", async () => {
  if (!session.canEncrypt) return;
  await runOperation("Signing and encrypting...", async () => {
    await contactController.checkBeforeUse("recipient");
    if (!session.canEncrypt || !session.identity || !session.recipientPublicKey) {
      throw new Error("Verify the current recipient key before encryption.");
    }
    // Extra recipients are looked up by address and must all be verified saved contacts.
    // If any is not, nothing is encrypted: leaving someone out silently would be worse.
    const extras = await resolveRecipients(
      contactController.lookup, parseAddressList(extraRecipientsInput.value), session.identity.publicKey
    );
    if (extras.problems.length) {
      throw new Error(`Cannot encrypt. ${extras.problems.map(describeRecipientProblem).join(" ")}`);
    }
    const recipients = [session.recipientPublicKey, ...extras.ready.map((recipient) => recipient.key)];
    extraRecipientLabels = new Map(extras.ready.flatMap((recipient) =>
      getKeyIds(recipient.key).map((id): [string, string] => [id, recipient.email])));
    encryptedPackageInput.value = await encryptMessage(plaintextInput.value, recipients, session.identity.privateKey);
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    const count = await renderMessageRecipients();
    setStatus(count <= 1
      ? "Signed and encrypted to yourself."
      : `Signed and encrypted to ${count - 1} recipient${count === 2 ? "" : "s"} and to yourself.`);
  });
});

rotateKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy || !storageReady || session.source !== "vault") return;
  if (!await confirmAction("Rotate key?",
    "A new key replaces your current one. Your old key is kept so earlier mail stays readable, but contacts must get and verify your new public key.",
    "Rotate key")) return;
  await runOperation("Rotating key...", async () => {
    const vault = await loadIdentityVault();
    if (vault === undefined) throw new Error("No saved identity was found in this browser.");
    const rotated = await rotateIdentityVault(vault, rotatePassphraseInput.value);
    await saveIdentityVault(rotated.vault);
    activateIdentity(rotated.identity, "vault");
    advancedOptions.open = false;
    setStatus("Key rotated. Share your new public key; your old key still opens earlier mail.");
    focusVaultControl();
  });
});

decryptButton.addEventListener("click", async () => {
  if (!session.canDecrypt) return;
  await runOperation("Decrypting and verifying...", async () => {
    try {
      await contactController.checkBeforeUse("sender");
      if (!session.canDecrypt || !session.identity || !session.senderPublicKey) {
        throw new Error("Verify the current sender key before decryption.");
      }
      // Your own retired keys, and a contact's keys verified before they were replaced,
      // still vouch for older mail.
      const savedSigners = contactController.isOwnKey("sender")
        ? ownSigners(session.identity)
        : await contactController.savedSigners("sender");
      const signerKeys = savedSigners?.map((signer) => signer.key) ?? [session.senderPublicKey];
      const result = await decryptMessage(encryptedPackageInput.value, getDecryptionKeys(session.identity), signerKeys);
      const signer = savedSigners?.find((candidate) => candidate.fingerprint === result.signerFingerprint);
      decryptedMessageOutput.textContent = result.text || "(empty message)";
      setStatus(`${signer ? describeSigner(signer) : "Signature verified."} Key ${formatFingerprint(result.signerFingerprint)}.`);
    } catch (error) {
      decryptedMessageOutput.textContent = "Decryption failed";
      throw error;
    }
  });
});

tamperCiphertextButton.addEventListener("click", () => {
  if (isBusy) return;
  const lines = encryptedPackageInput.value.split("\n");
  // Flip one Base64 character in the middle of the armored body.
  const bodyLines = lines.map((line, index) => ({ line, index }))
    .filter(({ line }) => line.length > 20 && !line.startsWith("-----") && !line.includes(":"));
  const target = bodyLines[Math.floor(bodyLines.length / 2)];
  if (!target) {
    setStatus("No armored message to tamper with.");
    return;
  }
  const position = Math.floor(target.line.length / 2);
  const replacement = target.line[position] === "A" ? "B" : "A";
  lines[target.index] = `${target.line.slice(0, position)}${replacement}${target.line.slice(position + 1)}`;
  encryptedPackageInput.value = lines.join("\n");
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  setStatus("Ciphertext changed. Decryption should now fail.");
});

encryptedPackageInput.addEventListener("input", () => {
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  void renderMessageRecipients();
  renderControls();
});

for (const card of cards) {
  card.keyInput.addEventListener("input", () => {
    if (card.slot === "recipient") session.setRecipientKey();
    else session.setSenderKey();
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    renderTrust();
    renderControls();
  });
  card.copyButton.addEventListener("click", () => void copyText(card.keyInput.value, "Public key copied."));
  card.importButton.addEventListener("click", async () => {
    await runOperation(`Importing ${card.slot} key...`, async () => {
      await contactController.importKey(card.slot, card.keyInput.value);
      renderTrust();
    });
    card.importButton.focus();
  });
  card.verifyCheckbox.addEventListener("change", () => {
    const trust = card.slot === "recipient" ? session.recipientTrust : session.senderTrust;
    if (!trust || isBusy) return;
    const verified = card.verifyCheckbox.checked;
    void runOperation("Updating verification...", () => contactController.setVerified(card.slot, verified))
      .then(() => card.verifyCheckbox.focus());
  });
}

copyIdentityKeyButton.addEventListener("click", () => {
  if (session.identity) void copyText(session.identity.publicKey.armoredKey, "Your public key was copied. Share it, then compare fingerprints.");
});

async function createAndSaveVault(name: HTMLInputElement, email: HTMLInputElement, passphrase: HTMLInputElement): Promise<void> {
  if (vaultExists && !await confirmVaultAction("replace")) return;
  await runOperation("Creating identity and encrypted vault...", async () => {
    const created = await createIdentityVault({ name: name.value, email: email.value }, passphrase.value);
    await saveIdentityVault(created.vault);
    vaultExists = true;
    activateIdentity(created.identity, "vault");
    advancedOptions.open = false;
    name.value = "";
    email.value = "";
    setStatus("Identity saved and unlocked. Share your public key and fingerprint with contacts.");
    focusVaultControl();
  });
}

function confirmVaultAction(action: "replace" | "delete"): Promise<boolean> {
  const label = action === "replace" ? "Replace vault" : "Delete vault";
  return confirmAction(`${label}?`, action === "replace"
    ? "Your saved private key will be replaced. Messages encrypted to it can no longer be read."
    : "Your encrypted identity will be deleted from this browser. Messages encrypted to it can no longer be read.", label);
}

function confirmAction(title: string, message: string, label = "Delete contact"): Promise<boolean> {
  if (confirmationDialog.open) return Promise.resolve(false);
  confirmationTitle.textContent = title;
  confirmationMessage.textContent = message;
  confirmVaultActionButton.textContent = label;
  confirmationDialog.returnValue = "cancel";
  return new Promise((resolve) => {
    confirmationDialog.addEventListener("close", () => {
      if (confirmationDialog.returnValue !== "confirm") clearSecretInputs();
      resolve(confirmationDialog.returnValue === "confirm");
    }, { once: true });
    confirmationDialog.showModal();
  });
}

function activateIdentity(identity: UnlockedIdentity, source: ActiveKeySource): void {
  session.activate(identity, source);
  contactController.resetBindings();
  for (const card of cards) card.keyInput.value = identity.publicKey.armoredKey;
  encryptedPackageInput.value = "";
  messageRecipients.textContent = "No message";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  renderTrust();
  renderControls();
}

function clearActiveKeys(): void {
  session.clear();
  contactController.resetBindings();
  plaintextInput.value = "";
  encryptedPackageInput.value = "";
  messageRecipients.textContent = "No message";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  for (const card of cards) card.keyInput.value = "";
  clearSecretInputs();
  document.querySelectorAll<HTMLDetailsElement>("details").forEach((details) => { details.open = false; });
  renderTrust();
  renderControls();
}

/** Shows who a message is encrypted to and returns how many keys that is. */
async function renderMessageRecipients(): Promise<number> {
  const armored = encryptedPackageInput.value.trim();
  if (!armored) {
    messageRecipients.textContent = "No message";
    return 0;
  }
  try {
    const ids = await getMessageRecipientKeyIds(armored);
    const own = session.identity ? getKeyIds(session.identity.publicKey.key) : [];
    const recipient = session.recipientPublicKey ? getKeyIds(session.recipientPublicKey) : [];
    messageRecipients.textContent = ids.map((id) => own.includes(id)
      ? `${id} (you)`
      : recipient.includes(id)
        ? `${id} (recipient)`
        : `${id} (${extraRecipientLabels.get(id) ?? "unknown key"})`).join(", ") || "No public-key recipients";
    return ids.length;
  } catch {
    messageRecipients.textContent = "Not a readable OpenPGP message";
    return 0;
  }
}

function renderControls(): void {
  const view = getVaultView(vaultExists, session.source);
  vaultStatus.textContent = storageReady || session.source ? view.badge : "Storage unavailable";
  vaultStatus.dataset.mode = view.mode;
  vaultActionButton.textContent = view.primaryLabel;
  vaultActionButton.disabled = isBusy || (view.needsPassphrase && !storageReady);
  identityFieldsGroup.hidden = !view.needsIdentityDetails;
  identityNameInput.disabled = isBusy || !view.needsIdentityDetails || !storageReady;
  identityEmailInput.disabled = identityNameInput.disabled;
  passphraseField.hidden = !view.needsPassphrase;
  vaultPassphraseInput.disabled = isBusy || !view.needsPassphrase || !storageReady;
  vaultPassphraseInput.autocomplete = view.mode === "locked" ? "current-password" : "new-password";
  identitySummary.hidden = !session.identity;
  if (session.identity) {
    const user = session.identity.publicKey.primaryUser;
    identityUserId.textContent = `${user.name} <${user.email}>`;
    identityFingerprint.textContent = formatFingerprint(session.identity.publicKey.fingerprint);
  }
  copyIdentityKeyButton.disabled = isBusy || !session.identity;
  generateKeysButton.hidden = !view.canUseTemporaryKeys;
  generateKeysButton.disabled = isBusy;
  deleteVaultButton.hidden = !view.canDeleteVault;
  deleteVaultButton.disabled = isBusy || !storageReady;
  downloadBackupButton.hidden = !vaultExists;
  exportKeyForm.hidden = !session.identity;
  for (const control of backupControls) control.disabled = isBusy || !storageReady;
  rotateKeyForm.hidden = !view.canRotateKey;
  rotateKeyButton.disabled = isBusy || !storageReady;
  rotatePassphraseInput.disabled = isBusy || rotateKeyForm.hidden || !storageReady;
  replaceVaultForm.hidden = !view.canReplaceVault && !view.canCreateInAdvanced;
  replaceVaultButton.textContent = view.canReplaceVault ? "Replace vault" : "Create vault";
  replaceVaultButton.disabled = isBusy || !storageReady;
  for (const input of [replaceNameInput, replaceEmailInput, newVaultPassphraseInput]) {
    input.disabled = isBusy || replaceVaultForm.hidden || !storageReady;
  }
  encryptButton.disabled = isBusy || !session.canEncrypt;
  decryptButton.disabled = isBusy || !session.canDecrypt || !encryptedPackageInput.value.trim();
  tamperCiphertextButton.disabled = isBusy || !encryptedPackageInput.value.trim();
  for (const card of cards) {
    const trust = card.slot === "recipient" ? session.recipientTrust : session.senderTrust;
    card.copyButton.disabled = isBusy || !card.keyInput.value.trim();
    card.importButton.disabled = isBusy || !card.keyInput.value.trim();
    card.verifyCheckbox.disabled = isBusy || !trust || contactController.isOwnKey(card.slot);
    card.keyInput.disabled = isBusy;
  }
  plaintextInput.disabled = isBusy;
  extraRecipientsInput.disabled = isBusy;
  encryptedPackageInput.disabled = isBusy;
  app?.setAttribute("aria-busy", String(isBusy));
  contactController.setBusy(isBusy);
}

function renderTrust(): void {
  for (const card of cards) {
    const recipient = card.slot === "recipient";
    const fingerprint = recipient ? session.recipientFingerprint : session.senderFingerprint;
    const verified = isPublicKeyVerified(recipient ? session.recipientTrust : session.senderTrust, fingerprint);
    card.fingerprint.textContent = fingerprint ? formatFingerprint(fingerprint) : "No key loaded";
    card.trustStatus.textContent = contactController.statusLabel(card.slot, verified);
    card.trustStatus.classList.toggle("is-verified", verified);
    card.verifyCheckbox.checked = verified;
  }
}

async function runOperation(message: string, action: () => Promise<void>): Promise<void> {
  if (isBusy) return;
  isBusy = true;
  renderControls();
  setStatus(message);
  try {
    await action();
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    clearSecretInputs();
    isBusy = false;
    renderControls();
  }
}

/** Clears every passphrase field and any pasted private key. */
function clearSecretInputs(): void {
  document.querySelectorAll<HTMLInputElement>('input[type="password"]').forEach((input) => { input.value = ""; });
  importKeyTextInput.value = "";
}

function downloadText(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function focusVaultControl(): void {
  // Focus after the operation has re-enabled its controls.
  requestAnimationFrame(() => {
    if (!identityNameInput.disabled) identityNameInput.focus();
    else if (!vaultPassphraseInput.disabled) vaultPassphraseInput.focus();
    else vaultActionButton.focus();
  });
}

async function copyText(value: string, success: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    setStatus(success);
  } catch {
    setStatus("Unable to copy. Select and copy the text manually.");
  }
}

function setStatus(message: string): void {
  operationStatus.textContent = message;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error.";
}

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Element "${id}" was not found.`);
  return element as T;
}

async function initializeVault(): Promise<void> {
  try {
    vaultExists = (await loadIdentityVault()) !== undefined;
    storageReady = true;
  } catch (error) {
    setStatus(formatError(error));
  }
  renderControls();
}

renderTrust();
void initializeVault();
void contactController.initialize().catch((error: unknown) => setStatus(formatError(error)));
