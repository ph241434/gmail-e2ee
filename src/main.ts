import "./style.css";
import {
  decryptDemoMessage,
  encryptDemoMessage,
  exportDemoPublicKeys,
  formatEncryptedMessage,
  generateDemoKeys,
  importDemoRecipientPublicKey,
  importDemoSenderPublicKey,
  parseEncryptedMessage,
  type DemoKeys
} from "./demo";

let demoKeys: DemoKeys | undefined;
let recipientEncryptionPublicKey: CryptoKey | undefined;
let senderVerificationPublicKey: CryptoKey | undefined;

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
          <div class="button-row">
            <button id="copy-alice-key" class="secondary-button" type="button" disabled>Copy</button>
            <button id="import-alice-key" type="button" disabled>Import for encryption</button>
          </div>
        </div>

        <div class="panel">
          <label for="pavel-public-key">Pavel's public signature-verification key</label>
          <textarea id="pavel-public-key" class="public-key-input" spellcheck="false" placeholder="Generate keys or paste an RSA-PSS public key in PEM format"></textarea>
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
const encryptButton = getElement<HTMLButtonElement>("encrypt");
const decryptButton = getElement<HTMLButtonElement>("decrypt");
const tamperCiphertextButton = getElement<HTMLButtonElement>("tamper-ciphertext");
const copyAliceKeyButton = getElement<HTMLButtonElement>("copy-alice-key");
const importAliceKeyButton = getElement<HTMLButtonElement>("import-alice-key");
const copyPavelKeyButton = getElement<HTMLButtonElement>("copy-pavel-key");
const importPavelKeyButton = getElement<HTMLButtonElement>("import-pavel-key");
const plaintextInput = getElement<HTMLTextAreaElement>("plaintext");
const encryptedPackageInput = getElement<HTMLTextAreaElement>("encrypted-package");
const alicePublicKeyInput = getElement<HTMLTextAreaElement>("alice-public-key");
const pavelPublicKeyInput = getElement<HTMLTextAreaElement>("pavel-public-key");
const decryptedMessageOutput = getElement<HTMLOutputElement>("decrypted-message");
const keyStatus = getElement<HTMLSpanElement>("key-status");
const operationStatus = getElement<HTMLSpanElement>("operation-status");

generateKeysButton.addEventListener("click", async () => {
  setBusy(true, "Generating Pavel and Alice keys...");

  try {
    demoKeys = await generateDemoKeys();
    const exportedPublicKeys = await exportDemoPublicKeys(demoKeys);
    recipientEncryptionPublicKey = demoKeys.aliceEncryptionKeyPair.publicKey;
    senderVerificationPublicKey = demoKeys.pavelSigningKeyPair.publicKey;
    alicePublicKeyInput.value = exportedPublicKeys.aliceEncryptionPublicKey;
    pavelPublicKeyInput.value = exportedPublicKeys.pavelVerificationPublicKey;
    keyStatus.textContent = "Demo keys ready";
    keyStatus.classList.add("is-ready");
    updateControlStates();
    setStatus("Keys generated in browser memory. Public keys are ready to share.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

encryptButton.addEventListener("click", async () => {
  if (!demoKeys || !recipientEncryptionPublicKey) {
    setStatus("Generate demo keys and select a recipient public key first.");
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
  if (!demoKeys || !senderVerificationPublicKey) {
    setStatus("Generate demo keys and select a sender verification key first.");
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
  updateControlStates();
});

pavelPublicKeyInput.addEventListener("input", () => {
  senderVerificationPublicKey = undefined;
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
    recipientEncryptionPublicKey = await importDemoRecipientPublicKey(
      alicePublicKeyInput.value
    );
    setStatus("Alice's RSA-OAEP public key imported for encryption.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

importPavelKeyButton.addEventListener("click", async () => {
  setBusy(true, "Importing Pavel's public verification key...");

  try {
    senderVerificationPublicKey = await importDemoSenderPublicKey(
      pavelPublicKeyInput.value
    );
    setStatus("Pavel's RSA-PSS public key imported for verification.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);

  if (!element) {
    throw new Error(`Element "${id}" was not found.`);
  }

  return element as T;
}

function setBusy(isBusy: boolean, message?: string): void {
  generateKeysButton.disabled = isBusy;
  encryptButton.disabled = isBusy || !demoKeys || !recipientEncryptionPublicKey;
  decryptButton.disabled =
    isBusy ||
    !demoKeys ||
    !senderVerificationPublicKey ||
    encryptedPackageInput.value.trim().length === 0;
  tamperCiphertextButton.disabled =
    isBusy || encryptedPackageInput.value.trim().length === 0;
  copyAliceKeyButton.disabled = isBusy || alicePublicKeyInput.value.trim().length === 0;
  importAliceKeyButton.disabled = isBusy || alicePublicKeyInput.value.trim().length === 0;
  copyPavelKeyButton.disabled = isBusy || pavelPublicKeyInput.value.trim().length === 0;
  importPavelKeyButton.disabled = isBusy || pavelPublicKeyInput.value.trim().length === 0;

  if (message) {
    setStatus(message);
  }
}

function updateControlStates(): void {
  setBusy(false);
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
