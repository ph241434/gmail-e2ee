import "./style.css";
import {
  createDemoKeyVault,
  decryptDemoMessage,
  encryptDemoMessage,
  exportDemoPublicKeys,
  fingerprintDemoPublicKeys,
  formatEncryptedMessage,
  generateDemoKeys,
  parseEncryptedMessage,
  unlockDemoKeyVault,
  type DemoKeys
} from "./demo";
import {
  PRIVATE_KEY_VAULT_MAX_PASSPHRASE_LENGTH,
  PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH
} from "./crypto/privateKeyVault";
import {
  deletePrivateKeyVault,
  loadPrivateKeyVault,
  savePrivateKeyVault
} from "./storage/privateKeyVaultStorage";
import { isPublicKeyVerified } from "./trust/publicKeyTrust";
import { getVaultView, KeySession, type ActiveKeySource } from "./ui/keySession";
import { ContactController } from "./ui/contactController";

const session = new KeySession();
let vaultExists = false;
let storageReady = false;
let isBusy = false;

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("App root was not found.");

const passphraseAttributes = `type="password" minlength="${PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH}"
  maxlength="${PRIVATE_KEY_VAULT_MAX_PASSPHRASE_LENGTH}" autocomplete="new-password"
  autocapitalize="none" spellcheck="false" required`;

app.innerHTML = `
  <main class="app-shell">
    <header class="masthead">
      <h1>Gmail E2EE</h1>
      <span id="vault-status" class="status-badge" role="status">Checking vault...</span>
    </header>
    <p id="operation-status" class="operation-status" role="status" aria-live="polite" aria-atomic="true">Ready</p>

    <section class="key-vault-section" aria-label="Key vault">
      <form id="vault-form" class="vault-controls">
        <div id="passphrase-field" class="passphrase-field">
          <label for="vault-passphrase">Vault passphrase</label>
          <input id="vault-passphrase" ${passphraseAttributes}>
        </div>
        <button id="vault-action" type="submit" disabled>Create vault</button>
      </form>
      <details id="advanced-key-options" class="advanced-options">
        <summary>Advanced key options</summary>
        <div class="advanced-actions">
          <button id="generate-keys" class="secondary-button" type="button">Use temporary keys</button>
          <button id="delete-vault" class="danger-button" type="button" hidden>Delete vault</button>
        </div>
        <form id="replace-vault-form" class="vault-controls" hidden>
          <div class="passphrase-field">
            <label for="new-vault-passphrase">New vault passphrase</label>
            <input id="new-vault-passphrase" ${passphraseAttributes}>
          </div>
          <button id="replace-vault" type="submit">Replace vault</button>
        </form>
      </details>
    </section>

    <section class="public-key-section" aria-labelledby="public-key-heading">
      <h2 id="public-key-heading">Key verification</h2>
      <div class="public-key-grid">
        <article class="key-card">
          <div class="key-heading">
            <h3><span id="alice-key-name" class="key-name">Alice</span><span>Encryption key</span></h3>
            <span id="alice-trust-status" class="trust-status">Unverified</span>
          </div>
          <div id="alice-contact-picker" class="contact-picker"></div>
          <code id="alice-fingerprint" class="fingerprint-value" aria-label="Alice's SHA-256 fingerprint">No key loaded</code>
          <label class="trust-checkbox" for="verify-alice-key">
            <input id="verify-alice-key" type="checkbox" disabled>
            <span id="alice-verification-label">I compared this fingerprint with Alice through a separate trusted channel.</span>
          </label>
          <details id="alice-key-details" class="key-details">
            <summary>Public key text</summary>
            <label for="alice-public-key">Recipient public encryption key</label>
            <textarea id="alice-public-key" class="public-key-input" spellcheck="false" placeholder="Paste a public key in PEM format"></textarea>
            <div class="button-row">
              <button id="copy-alice-key" class="secondary-button" type="button" disabled>Copy public key</button>
              <button id="import-alice-key" type="button" disabled>Import for encryption</button>
            </div>
            <div id="alice-contact-editor"></div>
          </details>
        </article>
        <article class="key-card">
          <div class="key-heading">
            <h3><span id="pavel-key-name" class="key-name">Pavel</span><span>Signature-verification key</span></h3>
            <span id="pavel-trust-status" class="trust-status">Unverified</span>
          </div>
          <div id="pavel-contact-picker" class="contact-picker"></div>
          <code id="pavel-fingerprint" class="fingerprint-value" aria-label="Pavel's SHA-256 fingerprint">No key loaded</code>
          <label class="trust-checkbox" for="verify-pavel-key">
            <input id="verify-pavel-key" type="checkbox" disabled>
            <span id="pavel-verification-label">I compared this fingerprint with Pavel through a separate trusted channel.</span>
          </label>
          <details id="pavel-key-details" class="key-details">
            <summary>Public key text</summary>
            <label for="pavel-public-key">Sender public verification key</label>
            <textarea id="pavel-public-key" class="public-key-input" spellcheck="false" placeholder="Paste a public key in PEM format"></textarea>
            <div class="button-row">
              <button id="copy-pavel-key" class="secondary-button" type="button" disabled>Copy public key</button>
              <button id="import-pavel-key" type="button" disabled>Import for verification</button>
            </div>
            <div id="pavel-contact-editor"></div>
          </details>
        </article>
      </div>
    </section>

    <section class="message-section" aria-labelledby="message-heading">
      <h2 id="message-heading">Message</h2>
      <div class="workspace-grid">
        <div class="message-column">
          <label for="plaintext">Sender message</label>
          <textarea id="plaintext" spellcheck="true">Meet me at 4 PM.</textarea>
          <button id="encrypt" type="button" disabled>Encrypt</button>
        </div>
        <div class="message-column">
          <label for="decrypted-message">Decrypted message</label>
          <output id="decrypted-message">Nothing decrypted yet</output>
          <button id="decrypt" type="button" disabled>Decrypt</button>
        </div>
      </div>
      <details id="package-details" class="package-details">
        <summary>Encrypted package details</summary>
        <div class="package-heading">
          <label for="encrypted-package">Encrypted package</label>
          <button id="tamper-ciphertext" class="secondary-button" type="button" disabled>Tamper ciphertext</button>
        </div>
        <textarea id="encrypted-package" spellcheck="false" placeholder="Encrypted JSON appears here"></textarea>
        <dl class="field-list" aria-label="Encrypted package fields">
          <div><dt>encryptedSessionKey</dt><dd>RSA-OAEP wrapped AES-256 session key</dd></div>
          <div><dt>nonce</dt><dd>96-bit AES-GCM nonce</dd></div>
          <div><dt>ciphertext</dt><dd>AES-GCM ciphertext with authentication tag</dd></div>
          <div><dt>signature</dt><dd>RSA-PSS signature over the deterministic package fields</dd></div>
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
const passphraseField = getElement<HTMLDivElement>("passphrase-field");
const vaultPassphraseInput = getElement<HTMLInputElement>("vault-passphrase");
const advancedOptions = getElement<HTMLDetailsElement>("advanced-key-options");
const replaceVaultForm = getElement<HTMLFormElement>("replace-vault-form");
const replaceVaultButton = getElement<HTMLButtonElement>("replace-vault");
const newVaultPassphraseInput = getElement<HTMLInputElement>("new-vault-passphrase");
const generateKeysButton = getElement<HTMLButtonElement>("generate-keys");
const deleteVaultButton = getElement<HTMLButtonElement>("delete-vault");
const encryptButton = getElement<HTMLButtonElement>("encrypt");
const decryptButton = getElement<HTMLButtonElement>("decrypt");
const tamperCiphertextButton = getElement<HTMLButtonElement>("tamper-ciphertext");
const copyAliceKeyButton = getElement<HTMLButtonElement>("copy-alice-key");
const importAliceKeyButton = getElement<HTMLButtonElement>("import-alice-key");
const copyPavelKeyButton = getElement<HTMLButtonElement>("copy-pavel-key");
const importPavelKeyButton = getElement<HTMLButtonElement>("import-pavel-key");
const verifyAliceKeyCheckbox = getElement<HTMLInputElement>("verify-alice-key");
const verifyPavelKeyCheckbox = getElement<HTMLInputElement>("verify-pavel-key");
const plaintextInput = getElement<HTMLTextAreaElement>("plaintext");
const encryptedPackageInput = getElement<HTMLTextAreaElement>("encrypted-package");
const alicePublicKeyInput = getElement<HTMLTextAreaElement>("alice-public-key");
const pavelPublicKeyInput = getElement<HTMLTextAreaElement>("pavel-public-key");
const aliceFingerprintOutput = getElement<HTMLElement>("alice-fingerprint");
const pavelFingerprintOutput = getElement<HTMLElement>("pavel-fingerprint");
const aliceTrustStatus = getElement<HTMLSpanElement>("alice-trust-status");
const pavelTrustStatus = getElement<HTMLSpanElement>("pavel-trust-status");
const decryptedMessageOutput = getElement<HTMLOutputElement>("decrypted-message");
const operationStatus = getElement<HTMLParagraphElement>("operation-status");
const vaultStatus = getElement<HTMLSpanElement>("vault-status");
const confirmationDialog = getElement<HTMLDialogElement>("vault-confirmation");
const confirmationTitle = getElement<HTMLHeadingElement>("confirmation-title");
const confirmationMessage = getElement<HTMLParagraphElement>("confirmation-message");
const confirmVaultActionButton = getElement<HTMLButtonElement>("confirm-vault-action");
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
    setStatus(mode === "unlocked" ? "Vault locked." : "Temporary keys cleared.");
    focusVaultControl();
    return;
  }
  if (!storageReady) return;
  if (mode === "setup") {
    await createAndSaveVault(vaultPassphraseInput);
    return;
  }
  await runOperation("Unlocking vault...", async () => {
    const vault = await loadPrivateKeyVault();
    if (vault === undefined) {
      vaultExists = false;
      throw new Error("No saved vault was found in this browser.");
    }
    const keys = await unlockDemoKeyVault(vault, vaultPassphraseInput.value);
    await activateDemoKeys(keys, "vault");
    setStatus("Vault unlocked. Compare both fingerprints before use.");
    focusVaultControl();
  });
});

replaceVaultForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (isBusy || !storageReady) return;
  await createAndSaveVault(newVaultPassphraseInput);
});

generateKeysButton.addEventListener("click", async () => {
  await runOperation("Generating temporary keys...", async () => {
    await activateDemoKeys(await generateDemoKeys(), "ephemeral");
    advancedOptions.open = false;
    setStatus("Temporary keys ready. Compare both fingerprints before use.");
    focusVaultControl();
  });
});

deleteVaultButton.addEventListener("click", async () => {
  if (isBusy || !vaultExists || !await confirmVaultAction("delete")) return;
  await runOperation("Deleting vault...", async () => {
    await deletePrivateKeyVault();
    vaultExists = false;
    if (session.source === "vault") clearActiveKeys();
    advancedOptions.open = false;
    setStatus("Saved vault deleted.");
    focusVaultControl();
  });
});

encryptButton.addEventListener("click", async () => {
  if (!session.canEncrypt || !session.keys || !session.recipientPublicKey) return;
  await runOperation("Encrypting message...", async () => {
    await contactController.checkBeforeUse("encryption");
    if (!session.canEncrypt || !session.keys || !session.recipientPublicKey) throw new Error("Verify the current recipient key before encryption.");
    const encrypted = await encryptDemoMessage(plaintextInput.value, session.keys, session.recipientPublicKey);
    encryptedPackageInput.value = formatEncryptedMessage(encrypted);
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    setStatus("Encrypted and signed package ready.");
  });
});

decryptButton.addEventListener("click", async () => {
  if (!session.canDecrypt || !session.keys || !session.senderPublicKey) return;
  await runOperation("Verifying and decrypting...", async () => {
    try {
      await contactController.checkBeforeUse("verification");
      if (!session.canDecrypt || !session.keys || !session.senderPublicKey) throw new Error("Verify the current sender key before decryption.");
      const plaintext = await decryptDemoMessage(parseEncryptedMessage(encryptedPackageInput.value), session.keys, session.senderPublicKey);
      decryptedMessageOutput.textContent = plaintext || "(empty message)";
      setStatus("Signature verified. Message decrypted.");
    } catch (error) {
      decryptedMessageOutput.textContent = "Decryption failed";
      throw error;
    }
  });
});

tamperCiphertextButton.addEventListener("click", () => {
  if (isBusy) return;
  try {
    const encrypted = parseEncryptedMessage(encryptedPackageInput.value);
    encrypted.ciphertext = `${encrypted.ciphertext.startsWith("A") ? "B" : "A"}${encrypted.ciphertext.slice(1)}`;
    encryptedPackageInput.value = formatEncryptedMessage(encrypted);
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    setStatus("Ciphertext changed. Decryption should now fail.");
  } catch (error) {
    setStatus(formatError(error));
  }
});

encryptedPackageInput.addEventListener("input", () => {
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  renderControls();
});
alicePublicKeyInput.addEventListener("input", () => {
  session.setRecipientKey();
  renderTrust();
  renderControls();
});
pavelPublicKeyInput.addEventListener("input", () => {
  session.setSenderKey();
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  renderTrust();
  renderControls();
});

copyAliceKeyButton.addEventListener("click", () => void copyPublicKey(alicePublicKeyInput.value));
copyPavelKeyButton.addEventListener("click", () => void copyPublicKey(pavelPublicKeyInput.value));

importAliceKeyButton.addEventListener("click", async () => {
  await runOperation("Importing recipient key...", async () => {
    await contactController.importKey("encryption", alicePublicKeyInput.value);
    renderTrust();
  });
  importAliceKeyButton.focus();
});
importPavelKeyButton.addEventListener("click", async () => {
  await runOperation("Importing sender key...", async () => {
    await contactController.importKey("verification", pavelPublicKeyInput.value);
    renderTrust();
  });
  importPavelKeyButton.focus();
});

verifyAliceKeyCheckbox.addEventListener("change", () => {
  if (!session.recipientTrust || isBusy) return;
  const verified = verifyAliceKeyCheckbox.checked;
  void runOperation("Updating verification...", () => contactController.setVerified("encryption", verified))
    .then(() => verifyAliceKeyCheckbox.focus());
});
verifyPavelKeyCheckbox.addEventListener("change", () => {
  if (!session.senderTrust || isBusy) return;
  const verified = verifyPavelKeyCheckbox.checked;
  void runOperation("Updating verification...", () => contactController.setVerified("verification", verified))
    .then(() => verifyPavelKeyCheckbox.focus());
});

async function createAndSaveVault(input: HTMLInputElement): Promise<void> {
  if (vaultExists && !await confirmVaultAction("replace")) return;
  await runOperation("Creating encrypted vault...", async () => {
    const created = await createDemoKeyVault(input.value);
    await savePrivateKeyVault(created.vault);
    vaultExists = true;
    await activateDemoKeys(created.demoKeys, "vault");
    advancedOptions.open = false;
    setStatus("Vault saved and unlocked. Compare both fingerprints before use.");
    focusVaultControl();
  });
}

function confirmVaultAction(action: "replace" | "delete"): Promise<boolean> {
  const label = action === "replace" ? "Replace vault" : "Delete vault";
  return confirmAction(`${label}?`, action === "replace"
    ? "The saved private keys will be replaced. They cannot be recovered afterward."
    : "The encrypted private-key vault will be deleted from this browser. This cannot be undone.", label);
}

function confirmAction(title: string, message: string, label = "Delete contact"): Promise<boolean> {
  if (confirmationDialog.open) return Promise.resolve(false);
  confirmationTitle.textContent = title;
  confirmationMessage.textContent = message;
  confirmVaultActionButton.textContent = label;
  confirmationDialog.returnValue = "cancel";
  return new Promise((resolve) => {
    confirmationDialog.addEventListener("close", () => {
      if (confirmationDialog.returnValue !== "confirm") {
        newVaultPassphraseInput.value = "";
      }
      resolve(confirmationDialog.returnValue === "confirm");
    }, { once: true });
    confirmationDialog.showModal();
  });
}

async function activateDemoKeys(keys: DemoKeys, source: ActiveKeySource): Promise<void> {
  const [publicKeys, fingerprints] = await Promise.all([
    exportDemoPublicKeys(keys), fingerprintDemoPublicKeys(keys)
  ]);
  session.activate(keys, source, fingerprints);
  contactController.resetBindings();
  alicePublicKeyInput.value = publicKeys.aliceEncryptionPublicKey;
  pavelPublicKeyInput.value = publicKeys.pavelVerificationPublicKey;
  encryptedPackageInput.value = "";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  renderTrust();
  renderControls();
}

function clearActiveKeys(): void {
  session.clear();
  contactController.resetBindings();
  plaintextInput.value = "";
  encryptedPackageInput.value = "";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  alicePublicKeyInput.value = "";
  pavelPublicKeyInput.value = "";
  vaultPassphraseInput.value = "";
  newVaultPassphraseInput.value = "";
  document.querySelectorAll<HTMLDetailsElement>("details").forEach((details) => { details.open = false; });
  renderTrust();
  renderControls();
}

function renderControls(): void {
  const view = getVaultView(vaultExists, session.source);
  vaultStatus.textContent = storageReady || session.source ? view.badge : "Storage unavailable";
  vaultStatus.dataset.mode = view.mode;
  vaultActionButton.textContent = view.primaryLabel;
  vaultActionButton.disabled = isBusy || (view.needsPassphrase && !storageReady);
  passphraseField.hidden = !view.needsPassphrase;
  vaultPassphraseInput.disabled = isBusy || !view.needsPassphrase || !storageReady;
  vaultPassphraseInput.autocomplete = view.mode === "locked" ? "current-password" : "new-password";
  generateKeysButton.hidden = !view.canUseTemporaryKeys;
  generateKeysButton.disabled = isBusy;
  deleteVaultButton.hidden = !view.canDeleteVault;
  deleteVaultButton.disabled = isBusy || !storageReady;
  replaceVaultForm.hidden = !view.canReplaceVault && !view.canCreateInAdvanced;
  replaceVaultButton.textContent = view.canReplaceVault ? "Replace vault" : "Create vault";
  replaceVaultButton.disabled = isBusy || !storageReady;
  newVaultPassphraseInput.disabled = isBusy || replaceVaultForm.hidden || !storageReady;
  encryptButton.disabled = isBusy || !session.canEncrypt;
  decryptButton.disabled = isBusy || !session.canDecrypt || !encryptedPackageInput.value.trim();
  tamperCiphertextButton.disabled = isBusy || !encryptedPackageInput.value.trim();
  copyAliceKeyButton.disabled = isBusy || !alicePublicKeyInput.value.trim();
  importAliceKeyButton.disabled = isBusy || !alicePublicKeyInput.value.trim();
  copyPavelKeyButton.disabled = isBusy || !pavelPublicKeyInput.value.trim();
  importPavelKeyButton.disabled = isBusy || !pavelPublicKeyInput.value.trim();
  verifyAliceKeyCheckbox.disabled = isBusy || !session.recipientTrust;
  verifyPavelKeyCheckbox.disabled = isBusy || !session.senderTrust;
  [plaintextInput, encryptedPackageInput, alicePublicKeyInput, pavelPublicKeyInput].forEach((input) => {
    input.disabled = isBusy;
  });
  app?.setAttribute("aria-busy", String(isBusy));
  contactController.setBusy(isBusy);
}

function renderTrust(): void {
  const recipientVerified = isPublicKeyVerified(session.recipientTrust, session.recipientFingerprint);
  const senderVerified = isPublicKeyVerified(session.senderTrust, session.senderFingerprint);
  aliceFingerprintOutput.textContent = session.recipientFingerprint || "No key loaded";
  pavelFingerprintOutput.textContent = session.senderFingerprint || "No key loaded";
  aliceTrustStatus.textContent = contactController.statusLabel("encryption", recipientVerified);
  pavelTrustStatus.textContent = contactController.statusLabel("verification", senderVerified);
  aliceTrustStatus.classList.toggle("is-verified", recipientVerified);
  pavelTrustStatus.classList.toggle("is-verified", senderVerified);
  verifyAliceKeyCheckbox.checked = recipientVerified;
  verifyPavelKeyCheckbox.checked = senderVerified;
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
    vaultPassphraseInput.value = "";
    newVaultPassphraseInput.value = "";
    isBusy = false;
    renderControls();
  }
}

function focusVaultControl(): void {
  // Focus after the operation has re-enabled its controls.
  requestAnimationFrame(() => {
    if (!vaultPassphraseInput.disabled) vaultPassphraseInput.focus();
    else vaultActionButton.focus();
  });
}

async function copyPublicKey(value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    setStatus("Public key copied.");
  } catch {
    setStatus("Unable to copy. Select and copy the public key text manually.");
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
    vaultExists = (await loadPrivateKeyVault()) !== undefined;
    storageReady = true;
  } catch (error) {
    setStatus(formatError(error));
  }
  renderControls();
}

void initializeVault();
void contactController.initialize().catch((error: unknown) => setStatus(formatError(error)));
