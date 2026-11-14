import "../src/style.css";
import "./extension.css";
import { releaseIdentity, unlockIdentityVault, type UnlockedIdentity } from "../src/pgp/identityVault";
import { formatFingerprint } from "../src/pgp/keys";
import { loadIdentityVault } from "../src/storage/identityVaultStorage";
import {
  clearUnlockedIdentity,
  loadUnlockedIdentity,
  onUnlockedIdentityChanged,
  saveUnlockedIdentity
} from "./session";

// The popup is drawn by Chrome itself, so it is the safe place to type the vault
// passphrase. It only locks and unlocks; it never shows message text.

const lockStatus = element<HTMLSpanElement>("lock-status");
const message = element<HTMLParagraphElement>("popup-message");
const identitySummary = element<HTMLDivElement>("identity-summary");
const identityUserId = element<HTMLSpanElement>("identity-user-id");
const identityFingerprint = element<HTMLElement>("identity-fingerprint");
const unlockForm = element<HTMLFormElement>("unlock-form");
const passphraseInput = element<HTMLInputElement>("unlock-passphrase");
const unlockButton = element<HTMLButtonElement>("unlock");
const lockButton = element<HTMLButtonElement>("lock");
const keyManagerButton = element<HTMLButtonElement>("open-key-manager");

let busy = false;

unlockForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  busy = true;
  unlockButton.disabled = true;
  message.textContent = "Unlocking...";
  let identity: UnlockedIdentity | undefined;
  try {
    const vault = await loadIdentityVault();
    if (vault === undefined) throw new Error("No saved identity. Open the key manager to create one.");
    identity = await unlockIdentityVault(vault, passphraseInput.value);
    await saveUnlockedIdentity(identity);
    message.textContent = "Unlocked.";
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : "Unable to unlock.";
  } finally {
    // The shared copy lives in session storage; this page does not need its own.
    releaseIdentity(identity);
    passphraseInput.value = "";
    busy = false;
    unlockButton.disabled = false;
    await render();
  }
});

lockButton.addEventListener("click", async () => {
  await clearUnlockedIdentity();
  message.textContent = "Locked.";
  await render();
});

keyManagerButton.addEventListener("click", () => void chrome.runtime.openOptionsPage());

onUnlockedIdentityChanged(() => void render());

async function render(): Promise<void> {
  let identity: UnlockedIdentity | undefined;
  let vaultExists = false;
  try {
    identity = await loadUnlockedIdentity();
    vaultExists = (await loadIdentityVault()) !== undefined;
  } catch (error) {
    message.textContent = error instanceof Error ? error.message : "Storage is unavailable.";
  }
  const mode = identity ? "unlocked" : vaultExists ? "locked" : "setup";
  lockStatus.textContent = { unlocked: "Unlocked", locked: "Locked", setup: "No saved identity" }[mode];
  lockStatus.dataset.mode = mode;
  identitySummary.hidden = !identity;
  if (identity) {
    const user = identity.publicKey.primaryUser;
    identityUserId.textContent = `${user.name} <${user.email}>`;
    identityFingerprint.textContent = formatFingerprint(identity.publicKey.fingerprint);
  }
  unlockForm.hidden = mode !== "locked";
  lockButton.hidden = mode !== "unlocked";
  keyManagerButton.textContent = mode === "setup" ? "Set up in key manager" : "Open key manager";
  if (mode === "locked" && !busy) passphraseInput.focus();
  // Only the fingerprint and name were needed; drop this page's copy of the key.
  releaseIdentity(identity);
}

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Element "${id}" was not found.`);
  return found as T;
}

void render();
