import "./style.css";
import {
  decryptDemoMessage,
  createDemoKeyVault,
  encryptDemoMessage,
  exportDemoPublicKeys,
  fingerprintDemoPublicKey,
  fingerprintDemoPublicKeys,
  formatEncryptedMessage,
  generateDemoKeys,
  importDemoRecipientPublicKey,
  importDemoSenderPublicKey,
  parseEncryptedMessage,
  unlockDemoKeyVault,
  type DemoKeys
} from "./demo";
import { PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH } from "./crypto/privateKeyVault";
import {
  deletePrivateKeyVault,
  loadPrivateKeyVault,
  savePrivateKeyVault
} from "./storage/privateKeyVaultStorage";
import {
  createUnverifiedPublicKeyTrust,
  isPublicKeyVerified,
  markPublicKeyUnverified,
  markPublicKeyVerified,
  type SessionPublicKeyTrust
} from "./trust/publicKeyTrust";

let demoKeys: DemoKeys | undefined;
let recipientEncryptionPublicKey: CryptoKey | undefined;
let senderVerificationPublicKey: CryptoKey | undefined;
let recipientFingerprint: string | undefined;
let senderFingerprint: string | undefined;
let recipientTrust: SessionPublicKeyTrust | undefined;
let senderTrust: SessionPublicKeyTrust | undefined;
let activeKeySource: "ephemeral" | "vault" | undefined;
let vaultExists = false;
let isBusy = false;

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("App root was not found.");
}

app.innerHTML = `
  <main class="app-shell">
    <section class="masthead">
      <div>
        <p class="eyebrow">Phase 2 local crypto proof of concept</p>
        <h1>Gmail E2EE</h1>
      </div>
      <button id="generate-keys" type="button">Generate Demo Keys</button>
    </section>

    <section class="status-row" aria-live="polite">
      <span id="key-status" class="status-pill">No demo keys yet</span>
      <span id="operation-status" class="status-text">Ready</span>
    </section>

    <section class="key-vault-section" aria-labelledby="key-vault-heading">
      <div class="section-heading">
        <div>
          <p class="eyebrow">PRIVATE KEYS STAY ENCRYPTED AT REST</p>
          <h2 id="key-vault-heading">Local key vault</h2>
        </div>
        <span id="vault-status" class="vault-status">Checking this browser...</span>
      </div>
      <div class="vault-controls">
        <div class="passphrase-field">
          <label for="vault-passphrase">Vault passphrase</label>
          <input
            id="vault-passphrase"
            type="password"
            minlength="${PRIVATE_KEY_VAULT_MIN_PASSPHRASE_LENGTH}"
            maxlength="1024"
            autocomplete="new-password"
            autocapitalize="none"
            spellcheck="false"
          >
        </div>
        <button id="generate-and-save-keys" type="button">Generate &amp; save keys</button>
        <button id="unlock-vault" class="secondary-button" type="button" disabled>Unlock saved keys</button>
        <button id="delete-vault" class="danger-button" type="button" disabled>Delete saved vault</button>
      </div>
    </section>

    <section class="public-key-section" aria-labelledby="public-key-heading">
      <div class="section-heading">
        <div>
          <p class="eyebrow">PUBLIC KEYS MAY BE SHARED</p>
          <h2 id="public-key-heading">Public key exchange</h2>
        </div>
        <p>Importing a key does not verify who owns it.</p>
      </div>

      <div class="public-key-grid">
        <div class="panel">
          <label for="alice-public-key">Alice's public encryption key</label>
          <textarea id="alice-public-key" class="public-key-input" spellcheck="false" placeholder="Generate keys or paste an RSA-OAEP public key in PEM format"></textarea>
          <div class="fingerprint-block">
            <div class="fingerprint-heading">
              <span>SHA-256 fingerprint</span>
              <span id="alice-trust-status" class="trust-status">Unverified</span>
            </div>
            <code id="alice-fingerprint" class="fingerprint-value">Generate or import a key</code>
            <label class="trust-checkbox" for="verify-alice-key">
              <input id="verify-alice-key" type="checkbox" disabled>
              <span>I compared this fingerprint with Alice through a separate trusted channel.</span>
            </label>
          </div>
          <div class="button-row">
            <button id="copy-alice-key" class="secondary-button" type="button" disabled>Copy</button>
            <button id="import-alice-key" type="button" disabled>Import for encryption</button>
          </div>
        </div>

        <div class="panel">
          <label for="pavel-public-key">Pavel's public signature-verification key</label>
          <textarea id="pavel-public-key" class="public-key-input" spellcheck="false" placeholder="Generate keys or paste an RSA-PSS public key in PEM format"></textarea>
          <div class="fingerprint-block">
            <div class="fingerprint-heading">
              <span>SHA-256 fingerprint</span>
              <span id="pavel-trust-status" class="trust-status">Unverified</span>
            </div>
            <code id="pavel-fingerprint" class="fingerprint-value">Generate or import a key</code>
            <label class="trust-checkbox" for="verify-pavel-key">
              <input id="verify-pavel-key" type="checkbox" disabled>
              <span>I compared this fingerprint with Pavel through a separate trusted channel.</span>
            </label>
          </div>
          <div class="button-row">
            <button id="copy-pavel-key" class="secondary-button" type="button" disabled>Copy</button>
            <button id="import-pavel-key" type="button" disabled>Import for verification</button>
          </div>
        </div>
      </div>
    </section>

    <section class="workspace-grid">
      <div class="panel">
        <label for="plaintext">Sender Message</label>
        <textarea id="plaintext" spellcheck="true">Meet me at 4 PM.</textarea>
        <button id="encrypt" type="button" disabled>Encrypt</button>
      </div>

      <div class="panel">
        <div class="panel-heading">
          <label for="encrypted-package">Encrypted Package</label>
          <button id="tamper-ciphertext" type="button" disabled>Tamper Ciphertext</button>
        </div>
        <textarea id="encrypted-package" spellcheck="false" placeholder="Encrypted JSON appears here"></textarea>
        <dl class="field-list" aria-label="Encrypted package fields">
          <div>
            <dt>encryptedSessionKey</dt>
            <dd>RSA-OAEP wrapped AES-256 session key</dd>
          </div>
          <div>
            <dt>nonce</dt>
            <dd>96-bit AES-GCM nonce</dd>
          </div>
          <div>
            <dt>ciphertext</dt>
            <dd>AES-GCM ciphertext with authentication tag</dd>
          </div>
          <div>
            <dt>signature</dt>
            <dd>RSA-PSS signature over the deterministic package fields</dd>
          </div>
        </dl>
      </div>

      <div class="panel">
        <label for="decrypted-message">Decrypted Message</label>
        <output id="decrypted-message">Nothing decrypted yet</output>
        <button id="decrypt" type="button" disabled>Decrypt</button>
      </div>
    </section>
  </main>
`;

const generateKeysButton = getElement<HTMLButtonElement>("generate-keys");
const generateAndSaveKeysButton = getElement<HTMLButtonElement>("generate-and-save-keys");
const unlockVaultButton = getElement<HTMLButtonElement>("unlock-vault");
const deleteVaultButton = getElement<HTMLButtonElement>("delete-vault");
const vaultPassphraseInput = getElement<HTMLInputElement>("vault-passphrase");
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
const keyStatus = getElement<HTMLSpanElement>("key-status");
const operationStatus = getElement<HTMLSpanElement>("operation-status");
const vaultStatus = getElement<HTMLSpanElement>("vault-status");

generateKeysButton.addEventListener("click", async () => {
  setBusy(true, "Generating Pavel and Alice keys...");

  try {
    const keys = await generateDemoKeys();
    await activateDemoKeys(
      keys,
      "Ephemeral keys ready",
      "Keys generated in memory. Compare both fingerprints before using them."
    );
    activeKeySource = "ephemeral";
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

generateAndSaveKeysButton.addEventListener("click", async () => {
  if (
    vaultExists &&
    !window.confirm("Replace the saved vault? The current private keys cannot be recovered afterward.")
  ) {
    return;
  }

  setBusy(true, "Generating and protecting new private keys...");

  try {
    const created = await createDemoKeyVault(vaultPassphraseInput.value);
    await savePrivateKeyVault(created.vault);
    vaultExists = true;
    await activateDemoKeys(
      created.demoKeys,
      "Vault keys unlocked",
      "Encrypted key vault saved in this browser. Compare both fingerprints before use."
    );
    activeKeySource = "vault";
    renderVaultStatus();
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    vaultPassphraseInput.value = "";
    setBusy(false);
  }
});

unlockVaultButton.addEventListener("click", async () => {
  setBusy(true, "Unlocking the saved private-key vault...");

  try {
    const vault = await loadPrivateKeyVault();
    if (vault === undefined) {
      vaultExists = false;
      renderVaultStatus();
      setStatus("No saved private-key vault was found in this browser.");
      return;
    }

    const keys = await unlockDemoKeyVault(vault, vaultPassphraseInput.value);
    await activateDemoKeys(
      keys,
      "Vault keys unlocked",
      "Private keys unlocked for this session. Compare both fingerprints before use."
    );
    activeKeySource = "vault";
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    vaultPassphraseInput.value = "";
    setBusy(false);
  }
});

deleteVaultButton.addEventListener("click", async () => {
  if (!window.confirm("Delete the encrypted private-key vault from this browser?")) {
    return;
  }

  setBusy(true, "Deleting the saved private-key vault...");

  try {
    await deletePrivateKeyVault();
    vaultExists = false;
    if (activeKeySource === "vault") {
      clearActiveKeys();
    }
    renderVaultStatus();
    setStatus("Saved private-key vault deleted from this browser.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    vaultPassphraseInput.value = "";
    setBusy(false);
  }
});

encryptButton.addEventListener("click", async () => {
  if (
    !demoKeys ||
    !recipientEncryptionPublicKey ||
    !isPublicKeyVerified(recipientTrust, recipientFingerprint)
  ) {
    setStatus("Verify Alice's current fingerprint before encrypting.");
    return;
  }

  setBusy(true, "Encrypting message...");

  try {
    const encryptedMessage = await encryptDemoMessage(
      plaintextInput.value,
      demoKeys,
      recipientEncryptionPublicKey
    );
    encryptedPackageInput.value = formatEncryptedMessage(encryptedMessage);
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    decryptButton.disabled = false;
    tamperCiphertextButton.disabled = false;
    setStatus("Encrypted and signed package created.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

decryptButton.addEventListener("click", async () => {
  if (
    !demoKeys ||
    !senderVerificationPublicKey ||
    !isPublicKeyVerified(senderTrust, senderFingerprint)
  ) {
    setStatus("Verify Pavel's current fingerprint before decrypting.");
    return;
  }

  setBusy(true, "Verifying signature and decrypting...");

  try {
    const encryptedMessage = parseEncryptedMessage(encryptedPackageInput.value);
    const plaintext = await decryptDemoMessage(
      encryptedMessage,
      demoKeys,
      senderVerificationPublicKey
    );
    decryptedMessageOutput.textContent = plaintext.length > 0 ? plaintext : "(empty message)";
    setStatus("Signature verified. Message decrypted for Alice.");
  } catch (error) {
    decryptedMessageOutput.textContent = "Decryption failed";
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

tamperCiphertextButton.addEventListener("click", () => {
  try {
    const encryptedMessage = parseEncryptedMessage(encryptedPackageInput.value);
    encryptedMessage.ciphertext = tamperBase64Text(encryptedMessage.ciphertext);
    encryptedPackageInput.value = formatEncryptedMessage(encryptedMessage);
    decryptedMessageOutput.textContent = "Nothing decrypted yet";
    setStatus("Ciphertext changed. Decryption should now fail.");
  } catch (error) {
    setStatus(formatError(error));
  }
});

encryptedPackageInput.addEventListener("input", () => {
  updateControlStates();
});

alicePublicKeyInput.addEventListener("input", () => {
  recipientEncryptionPublicKey = undefined;
  clearRecipientFingerprint();
  updateControlStates();
});

pavelPublicKeyInput.addEventListener("input", () => {
  senderVerificationPublicKey = undefined;
  clearSenderFingerprint();
  updateControlStates();
});

copyAliceKeyButton.addEventListener("click", async () => {
  await copyPublicKey(alicePublicKeyInput.value, "Alice's public encryption key copied.");
});

copyPavelKeyButton.addEventListener("click", async () => {
  await copyPublicKey(pavelPublicKeyInput.value, "Pavel's public verification key copied.");
});

importAliceKeyButton.addEventListener("click", async () => {
  setBusy(true, "Importing Alice's public encryption key...");

  try {
    const importedKey = await importDemoRecipientPublicKey(
      alicePublicKeyInput.value
    );
    const fingerprint = await fingerprintDemoPublicKey(importedKey);
    recipientEncryptionPublicKey = importedKey;
    setRecipientFingerprint(fingerprint);
    setStatus("Alice's key imported. Compare its fingerprint before encryption.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

importPavelKeyButton.addEventListener("click", async () => {
  setBusy(true, "Importing Pavel's public verification key...");

  try {
    const importedKey = await importDemoSenderPublicKey(
      pavelPublicKeyInput.value
    );
    const fingerprint = await fingerprintDemoPublicKey(importedKey);
    senderVerificationPublicKey = importedKey;
    setSenderFingerprint(fingerprint);
    setStatus("Pavel's key imported. Compare its fingerprint before verification.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

verifyAliceKeyCheckbox.addEventListener("change", () => {
  if (!recipientTrust) {
    verifyAliceKeyCheckbox.checked = false;
    return;
  }

  recipientTrust = verifyAliceKeyCheckbox.checked
    ? markPublicKeyVerified(recipientTrust)
    : markPublicKeyUnverified(recipientTrust);
  renderTrustStatus();
  updateControlStates();
  setStatus(
    verifyAliceKeyCheckbox.checked
      ? "Alice's fingerprint marked verified for this session."
      : "Alice's fingerprint verification cleared."
  );
});

verifyPavelKeyCheckbox.addEventListener("change", () => {
  if (!senderTrust) {
    verifyPavelKeyCheckbox.checked = false;
    return;
  }

  senderTrust = verifyPavelKeyCheckbox.checked
    ? markPublicKeyVerified(senderTrust)
    : markPublicKeyUnverified(senderTrust);
  renderTrustStatus();
  updateControlStates();
  setStatus(
    verifyPavelKeyCheckbox.checked
      ? "Pavel's fingerprint marked verified for this session."
      : "Pavel's fingerprint verification cleared."
  );
});

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);

  if (!element) {
    throw new Error(`Element "${id}" was not found.`);
  }

  return element as T;
}

function setBusy(busy: boolean, message?: string): void {
  isBusy = busy;
  generateKeysButton.disabled = busy;
  generateAndSaveKeysButton.disabled = busy;
  unlockVaultButton.disabled = busy || !vaultExists;
  deleteVaultButton.disabled = busy || !vaultExists;
  vaultPassphraseInput.disabled = busy;
  encryptButton.disabled =
    busy ||
    !demoKeys ||
    !recipientEncryptionPublicKey ||
    !isPublicKeyVerified(recipientTrust, recipientFingerprint);
  decryptButton.disabled =
    busy ||
    !demoKeys ||
    !senderVerificationPublicKey ||
    !isPublicKeyVerified(senderTrust, senderFingerprint) ||
    encryptedPackageInput.value.trim().length === 0;
  tamperCiphertextButton.disabled =
    busy || encryptedPackageInput.value.trim().length === 0;
  copyAliceKeyButton.disabled = busy || alicePublicKeyInput.value.trim().length === 0;
  importAliceKeyButton.disabled = busy || alicePublicKeyInput.value.trim().length === 0;
  copyPavelKeyButton.disabled = busy || pavelPublicKeyInput.value.trim().length === 0;
  importPavelKeyButton.disabled = busy || pavelPublicKeyInput.value.trim().length === 0;
  verifyAliceKeyCheckbox.disabled = busy || !recipientTrust;
  verifyPavelKeyCheckbox.disabled = busy || !senderTrust;

  if (message) {
    setStatus(message);
  }
}

async function activateDemoKeys(
  keys: DemoKeys,
  readyLabel: string,
  readyMessage: string
): Promise<void> {
  const [exportedPublicKeys, fingerprints] = await Promise.all([
    exportDemoPublicKeys(keys),
    fingerprintDemoPublicKeys(keys)
  ]);
  demoKeys = keys;
  recipientEncryptionPublicKey = keys.aliceEncryptionKeyPair.publicKey;
  senderVerificationPublicKey = keys.pavelSigningKeyPair.publicKey;
  setRecipientFingerprint(fingerprints.aliceEncryptionFingerprint);
  setSenderFingerprint(fingerprints.pavelVerificationFingerprint);
  alicePublicKeyInput.value = exportedPublicKeys.aliceEncryptionPublicKey;
  pavelPublicKeyInput.value = exportedPublicKeys.pavelVerificationPublicKey;
  keyStatus.textContent = readyLabel;
  keyStatus.classList.add("is-ready");
  encryptedPackageInput.value = "";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  updateControlStates();
  setStatus(readyMessage);
}

function clearActiveKeys(): void {
  demoKeys = undefined;
  activeKeySource = undefined;
  recipientEncryptionPublicKey = undefined;
  senderVerificationPublicKey = undefined;
  alicePublicKeyInput.value = "";
  pavelPublicKeyInput.value = "";
  encryptedPackageInput.value = "";
  decryptedMessageOutput.textContent = "Nothing decrypted yet";
  clearRecipientFingerprint();
  clearSenderFingerprint();
  keyStatus.textContent = "No demo keys yet";
  keyStatus.classList.remove("is-ready");
  updateControlStates();
}

async function refreshVaultStatus(): Promise<void> {
  try {
    vaultExists = (await loadPrivateKeyVault()) !== undefined;
    renderVaultStatus();
  } catch (error) {
    vaultExists = false;
    vaultStatus.textContent = "Storage unavailable";
    setStatus(formatError(error));
  } finally {
    updateControlStates();
  }
}

function renderVaultStatus(): void {
  vaultStatus.textContent = vaultExists ? "Encrypted vault saved" : "No saved vault";
  vaultStatus.classList.toggle("is-saved", vaultExists);
}

function setRecipientFingerprint(fingerprint: string): void {
  recipientFingerprint = fingerprint;
  recipientTrust = createUnverifiedPublicKeyTrust(fingerprint);
  aliceFingerprintOutput.textContent = fingerprint;
  verifyAliceKeyCheckbox.checked = false;
  renderTrustStatus();
}

function setSenderFingerprint(fingerprint: string): void {
  senderFingerprint = fingerprint;
  senderTrust = createUnverifiedPublicKeyTrust(fingerprint);
  pavelFingerprintOutput.textContent = fingerprint;
  verifyPavelKeyCheckbox.checked = false;
  renderTrustStatus();
}

function clearRecipientFingerprint(): void {
  recipientFingerprint = undefined;
  recipientTrust = undefined;
  aliceFingerprintOutput.textContent = "Import this key to calculate its fingerprint";
  verifyAliceKeyCheckbox.checked = false;
  renderTrustStatus();
}

function clearSenderFingerprint(): void {
  senderFingerprint = undefined;
  senderTrust = undefined;
  pavelFingerprintOutput.textContent = "Import this key to calculate its fingerprint";
  verifyPavelKeyCheckbox.checked = false;
  renderTrustStatus();
}

function renderTrustStatus(): void {
  renderOneTrustStatus(
    aliceTrustStatus,
    isPublicKeyVerified(recipientTrust, recipientFingerprint)
  );
  renderOneTrustStatus(
    pavelTrustStatus,
    isPublicKeyVerified(senderTrust, senderFingerprint)
  );
}

function renderOneTrustStatus(element: HTMLElement, isVerified: boolean): void {
  element.textContent = isVerified ? "Verified this session" : "Unverified";
  element.classList.toggle("is-verified", isVerified);
}

function updateControlStates(): void {
  setBusy(isBusy);
}

function setStatus(message: string): void {
  operationStatus.textContent = message;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error.";
}

async function copyPublicKey(value: string, successMessage: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    setStatus(successMessage);
  } catch {
    setStatus("Unable to copy automatically. Select and copy the public key manually.");
  }
}

function tamperBase64Text(value: string): string {
  const replacement = value.startsWith("A") ? "B" : "A";
  return `${replacement}${value.slice(1)}`;
}

void refreshVaultStatus();
