import "../src/style.css";
import "./extension.css";
import { describeSigner, listTrustedSigners } from "../src/contacts/signers";
import { getDecryptionKeys, releaseIdentity, type UnlockedIdentity } from "../src/pgp/identityVault";
import { decryptMessage, MessageDecryptionError } from "../src/pgp/message";
import { ContactStore } from "../src/storage/contactStorage";
import { element, frameId, onPageMessage, openUnlockWindow, postToPage, reportHeight } from "./frame";
import { loadUnlockedIdentity, onUnlockedIdentityChanged } from "./session";

// Reader frame: decrypts one message and shows it. The Gmail page supplies the armored
// text and the sender address it displays; it never receives anything back but a height.

const status = element<HTMLParagraphElement>("viewer-status");
const warning = element<HTMLParagraphElement>("viewer-warning");
const text = element<HTMLPreElement>("viewer-text");
const unlockButton = element<HTMLButtonElement>("viewer-unlock");
const contacts = new ContactStore();

let armored: string | undefined;
let claimedSender: string | undefined;
let renderCount = 0;

function show(state: { status: string; mode: "info" | "ok" | "error"; text?: string; warning?: string; locked?: boolean }): void {
  status.textContent = state.status;
  status.dataset.mode = state.mode;
  warning.hidden = !state.warning;
  warning.textContent = state.warning ?? "";
  text.hidden = state.text === undefined;
  // textContent only: message content is never interpreted as markup.
  text.textContent = state.text ?? "";
  unlockButton.hidden = !state.locked;
}

function explain(error: unknown): string {
  if (!(error instanceof MessageDecryptionError)) return "This message could not be read.";
  switch (error.reason) {
    case "malformed": return "This is not a complete OpenPGP message. Open the full message if Gmail has clipped it.";
    case "not-for-you": return "This message is not encrypted to your key.";
    case "damaged": return "This message was changed or damaged and cannot be trusted.";
    case "unsigned": return "This message is not signed, so its sender cannot be confirmed. It is not shown.";
    case "bad-signature": return "The signature does not match this message. It is not shown.";
    case "unknown-signer":
      return `Signed with a key you have not verified (key ID ${error.signerKeyIds.join(", ") || "unknown"}). ` +
        "Save and verify the sender in the key manager to read it.";
  }
}

async function render(): Promise<void> {
  const current = ++renderCount;
  if (armored === undefined) return;
  // Clear anything on screen first, so plaintext never outlives a lock.
  show({ status: "Decrypting...", mode: "info" });
  let identity: UnlockedIdentity | undefined;
  try {
    identity = await loadUnlockedIdentity();
    if (!identity) {
      show({ status: "Encrypted message. Unlock Gmail E2EE to read it.", mode: "info", locked: true });
      return;
    }
    const signers = await listTrustedSigners(contacts, identity);
    const result = await decryptMessage(armored, getDecryptionKeys(identity), signers.map((signer) => signer.key));
    if (current !== renderCount) return;
    const signer = signers.find((candidate) => candidate.fingerprint === result.signerFingerprint)!;
    // The page's idea of the sender is only a hint; say so when it disagrees with the signature.
    const mismatch = claimedSender && claimedSender !== signer.email
      ? `Gmail shows this message as from ${claimedSender}, but it was signed by ${signer.email}.`
      : undefined;
    show({ status: `Decrypted. ${describeSigner(signer)}`, mode: "ok", text: result.text || "(empty message)", warning: mismatch });
  } catch (error) {
    if (current === renderCount) show({ status: explain(error), mode: "error" });
  } finally {
    releaseIdentity(identity);
  }
}

unlockButton.addEventListener("click", openUnlockWindow);
onUnlockedIdentityChanged(() => void render());
onPageMessage((message) => {
  if (message.type !== "gmail-e2ee:show") return;
  armored = message.armored;
  claimedSender = message.claimedSender?.trim().toLowerCase();
  void render();
});

reportHeight();
postToPage({ type: "gmail-e2ee:ready", frameId });
