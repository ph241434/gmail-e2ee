import "./style.css";
import {
  decryptDemoMessage,
  encryptDemoMessage,
  formatEncryptedMessage,
  generateDemoKeys,
  parseEncryptedMessage,
  type DemoKeys
} from "./demo";

let demoKeys: DemoKeys | undefined;

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("App root was not found.");
}

app.innerHTML = `
  <main class="app-shell">
    <section class="masthead">
      <div>
        <p class="eyebrow">Phase 1 local crypto proof of concept</p>
        <h1>Gmail E2EE</h1>
      </div>
      <button id="generate-keys" type="button">Generate Demo Keys</button>
    </section>

    <section class="status-row" aria-live="polite">
      <span id="key-status" class="status-pill">No demo keys yet</span>
      <span id="operation-status" class="status-text">Ready</span>
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
const plaintextInput = getElement<HTMLTextAreaElement>("plaintext");
const encryptedPackageInput = getElement<HTMLTextAreaElement>("encrypted-package");
const decryptedMessageOutput = getElement<HTMLOutputElement>("decrypted-message");
const keyStatus = getElement<HTMLSpanElement>("key-status");
const operationStatus = getElement<HTMLSpanElement>("operation-status");

generateKeysButton.addEventListener("click", async () => {
  setBusy(true, "Generating Pavel and Alice keys...");

  try {
    demoKeys = await generateDemoKeys();
    keyStatus.textContent = "Demo keys ready";
    keyStatus.classList.add("is-ready");
    encryptButton.disabled = false;
    decryptButton.disabled = encryptedPackageInput.value.trim().length === 0;
    setStatus("Keys generated in browser memory.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
    setBusy(false);
  }
});

encryptButton.addEventListener("click", async () => {
  if (!demoKeys) {
    setStatus("Generate demo keys first.");
    return;
  }

  setBusy(true, "Encrypting message...");

  try {
    const encryptedMessage = await encryptDemoMessage(plaintextInput.value, demoKeys);
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
  if (!demoKeys) {
    setStatus("Generate demo keys first.");
    return;
  }

  setBusy(true, "Verifying signature and decrypting...");

  try {
    const encryptedMessage = parseEncryptedMessage(encryptedPackageInput.value);
    const plaintext = await decryptDemoMessage(encryptedMessage, demoKeys);
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
  const hasPackage = encryptedPackageInput.value.trim().length > 0;
  decryptButton.disabled = !demoKeys || !hasPackage;
  tamperCiphertextButton.disabled = !hasPackage;
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
  encryptButton.disabled = isBusy || !demoKeys;
  decryptButton.disabled = isBusy || !demoKeys || encryptedPackageInput.value.trim().length === 0;
  tamperCiphertextButton.disabled = isBusy || encryptedPackageInput.value.trim().length === 0;

  if (message) {
    setStatus(message);
  }
}

function setStatus(message: string): void {
  operationStatus.textContent = message;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : "Unexpected error.";
}

function tamperBase64Text(value: string): string {
  const replacement = value.startsWith("A") ? "B" : "A";
  return `${replacement}${value.slice(1)}`;
}
