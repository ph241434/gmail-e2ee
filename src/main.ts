import "./style.css";
import {
  decryptDemoMessage,
  encryptDemoMessage,
  exportDemoPublicKeys,
  fingerprintDemoPublicKey,
  fingerprintDemoPublicKeys,
  formatEncryptedMessage,
  generateDemoKeys,
  importDemoRecipientPublicKey,
  importDemoSenderPublicKey,
  parseEncryptedMessage,
  type DemoKeys
} from "./demo";
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

generateKeysButton.addEventListener("click", async () => {
  setBusy(true, "Generating Pavel and Alice keys...");

  try {
    demoKeys = await generateDemoKeys();
    const [exportedPublicKeys, fingerprints] = await Promise.all([
      exportDemoPublicKeys(demoKeys),
      fingerprintDemoPublicKeys(demoKeys)
    ]);
    recipientEncryptionPublicKey = demoKeys.aliceEncryptionKeyPair.publicKey;
    senderVerificationPublicKey = demoKeys.pavelSigningKeyPair.publicKey;
    setRecipientFingerprint(fingerprints.aliceEncryptionFingerprint);
    setSenderFingerprint(fingerprints.pavelVerificationFingerprint);
    alicePublicKeyInput.value = exportedPublicKeys.aliceEncryptionPublicKey;
    pavelPublicKeyInput.value = exportedPublicKeys.pavelVerificationPublicKey;
    keyStatus.textContent = "Demo keys ready";
    keyStatus.classList.add("is-ready");
    updateControlStates();
    setStatus("Keys generated. Compare both fingerprints before using them.");
  } catch (error) {
    setStatus(formatError(error));
  } finally {
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

function setBusy(isBusy: boolean, message?: string): void {
  generateKeysButton.disabled = isBusy;
  encryptButton.disabled =
    isBusy ||
    !demoKeys ||
    !recipientEncryptionPublicKey ||
    !isPublicKeyVerified(recipientTrust, recipientFingerprint);
  decryptButton.disabled =
    isBusy ||
    !demoKeys ||
    !senderVerificationPublicKey ||
    !isPublicKeyVerified(senderTrust, senderFingerprint) ||
    encryptedPackageInput.value.trim().length === 0;
  tamperCiphertextButton.disabled =
    isBusy || encryptedPackageInput.value.trim().length === 0;
  copyAliceKeyButton.disabled = isBusy || alicePublicKeyInput.value.trim().length === 0;
  importAliceKeyButton.disabled = isBusy || alicePublicKeyInput.value.trim().length === 0;
  copyPavelKeyButton.disabled = isBusy || pavelPublicKeyInput.value.trim().length === 0;
  importPavelKeyButton.disabled = isBusy || pavelPublicKeyInput.value.trim().length === 0;
  verifyAliceKeyCheckbox.disabled = isBusy || !recipientTrust;
  verifyPavelKeyCheckbox.disabled = isBusy || !senderTrust;

  if (message) {
    setStatus(message);
  }
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
