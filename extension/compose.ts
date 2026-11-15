import "../src/style.css";
import "./extension.css";
import { describeRecipientProblem, parseAddressList, resolveRecipients } from "../src/contacts/recipients";
import { releaseIdentity, type UnlockedIdentity } from "../src/pgp/identityVault";
import { encryptMessage } from "../src/pgp/message";
import { ContactStore } from "../src/storage/contactStorage";
import { element, frameId, onPageMessage, openUnlockWindow, postToPage, reportHeight } from "./frame";
import { loadUnlockedIdentity, onUnlockedIdentityChanged } from "./session";

// Compose frame: the message is typed here, on the extension's origin, and only the
// encrypted result is handed to the Gmail page.

const status = element<HTMLParagraphElement>("compose-status");
const unlockButton = element<HTMLButtonElement>("compose-unlock");
const form = element<HTMLFormElement>("compose-form");
const recipientsInput = element<HTMLInputElement>("compose-recipients");
const textInput = element<HTMLTextAreaElement>("compose-text");
const problems = element<HTMLUListElement>("compose-problems");
const encryptButton = element<HTMLButtonElement>("compose-encrypt");
const cancelButton = element<HTMLButtonElement>("compose-cancel");
const contacts = new ContactStore();

let busy = false;

function showProblems(lines: string[]): void {
  problems.replaceChildren(...lines.map((line) => {
    const item = document.createElement("li");
    item.textContent = line;
    return item;
  }));
  problems.hidden = lines.length === 0;
}

/** Shows the editor when unlocked and an unlock prompt when locked. Typed text is kept across both. */
async function renderLockState(): Promise<void> {
  let identity: UnlockedIdentity | undefined;
  try {
    identity = await loadUnlockedIdentity();
  } catch {
    identity = undefined;
  }
  const unlocked = identity !== undefined;
  if (identity) status.textContent = `Signing as ${identity.publicKey.primaryUser.email}.`;
  else status.textContent = "Unlock Gmail E2EE to write an encrypted message.";
  releaseIdentity(identity);
  form.hidden = !unlocked;
  unlockButton.hidden = unlocked;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (busy) return;
  busy = true;
  encryptButton.disabled = true;
  showProblems([]);
  let identity: UnlockedIdentity | undefined;
  try {
    identity = await loadUnlockedIdentity();
    if (!identity) {
      await renderLockState();
      return;
    }
    const emails = parseAddressList(recipientsInput.value);
    if (emails.length === 0) throw new Error("Add at least one recipient.");
    const resolution = await resolveRecipients(contacts, emails, identity.publicKey);
    // Every recipient must be a verified contact. Leaving one out silently, or sending
    // to an unverified key, would both be worse than stopping.
    if (resolution.problems.length) {
      showProblems(resolution.problems.map(describeRecipientProblem));
      return;
    }
    const armored = await encryptMessage(
      textInput.value, resolution.ready.map((recipient) => recipient.key), identity.privateKey
    );
    textInput.value = "";
    postToPage({ type: "gmail-e2ee:encrypted", frameId, armored });
  } catch (error) {
    showProblems([error instanceof Error ? error.message : "Unable to encrypt."]);
  } finally {
    releaseIdentity(identity);
    busy = false;
    encryptButton.disabled = false;
  }
});

// Browsers do not let a frame from another origin open a confirm dialog, so discarding
// typed text takes a second click instead.
let discardArmed = false;
cancelButton.addEventListener("click", () => {
  if (textInput.value.trim() && !discardArmed) {
    discardArmed = true;
    cancelButton.textContent = "Discard message";
    return;
  }
  textInput.value = "";
  postToPage({ type: "gmail-e2ee:cancel", frameId });
});
textInput.addEventListener("input", () => {
  discardArmed = false;
  cancelButton.textContent = "Cancel";
});

unlockButton.addEventListener("click", openUnlockWindow);
onUnlockedIdentityChanged(() => void renderLockState());
onPageMessage((message) => {
  if (message.type !== "gmail-e2ee:compose") return;
  // Addresses read from the Gmail page are a starting point the user can correct.
  if (!recipientsInput.value) recipientsInput.value = message.recipients.join(", ");
});

void renderLockState();
reportHeight();
postToPage({ type: "gmail-e2ee:ready", frameId });
