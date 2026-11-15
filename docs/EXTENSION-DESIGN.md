# Chrome Extension Design

How the OpenPGP core becomes a Chrome extension that encrypts and decrypts inside the Gmail website, and where the trust boundaries are.

## Goals and non-goals

Goals:

- Write a message, encrypt it to verified contacts, and send it through the normal Gmail website.
- Read encrypted messages in Gmail, with the signer checked against verified contacts.
- Keep private keys and plaintext out of the Gmail page.

Non-goals for this version:

- No Gmail API, OAuth, or Google Cloud project. The extension only touches the Gmail page the user already has open.
- No PGP/MIME. Bodies are sent as inline armored text. Subject lines are not encrypted, and attachments are not handled.
- No key server or automatic key discovery.

## The Gmail page is untrusted

Everything on `mail.google.com` is treated as hostile input. That page is controlled by the mail provider the tool is meant to protect message content from, and it autosaves whatever is typed into its compose box to Google's servers as a draft. Three rules follow:

1. Plaintext is never typed into, or rendered in, the Gmail page. It lives only in pages served from the extension's own origin.
2. Private keys never leave the extension's origin.
3. Anything read from the Gmail page (recipient addresses, the claimed sender, the armored text) is a hint or an input to check, never a decision.

## Contexts

| Context | Origin | Sees keys | Sees plaintext | Job |
| --- | --- | --- | --- | --- |
| Key manager (`options.html`) | extension | yes | yes | Create, unlock, back up and rotate the identity; manage and verify contacts |
| Popup (`popup.html`) | extension | yes | no | Show lock state; unlock and lock |
| Reader frame (`viewer.html`) | extension, framed by Gmail | yes | yes | Decrypt one message and show it |
| Compose frame (`compose.html`) | extension, framed by Gmail | yes | yes | Take the message text, encrypt it, hand back armored text |
| Background worker (`background.js`) | extension | no | no | Auto-lock timer; restricts session storage to extension pages |
| Content script (`content.js`) | runs in the Gmail page | no | no | Find armored blocks and compose boxes; place the frames; insert armored text |

The two frames are cross-origin to Gmail, so the page cannot read their contents or keystrokes. The content script shares the page's DOM, which is why it is given neither keys nor plaintext.

## Storage

- **Identity vault and contacts**: IndexedDB under the extension origin, unchanged from the web app. Extension pages share it; the Gmail page and content script cannot reach it.
- **Unlocked identity**: `chrome.storage.session`. Chrome keeps this area in memory only, clears it when the browser closes, and with the `TRUSTED_CONTEXTS` access level (set explicitly by the background worker) hides it from content scripts. Manifest V3 background workers are stopped after a short idle time, so the unlocked key cannot simply live in a worker variable.
- **Auto-lock**: when an identity is unlocked the background worker sets an alarm; when it fires, the session entry is removed and every open frame and page drops its key and clears any plaintext on screen.

Unlocking with the vault passphrase happens only in the popup or the key manager, which Chrome draws itself. The frames inside Gmail never ask for the passphrase: a page can position a frame misleadingly, so the frames only offer a button that opens the popup window.

## Reading a message

1. The content script scans the page for text between `-----BEGIN PGP MESSAGE-----` and `-----END PGP MESSAGE-----`, skipping anything inside an editable compose box.
2. It hides that text and inserts a `viewer.html` frame in its place, then posts the armored text and the sender address Gmail displays.
3. The frame accepts messages only from its parent window at `https://mail.google.com`.
4. The frame decrypts with the identity's current and retired keys and requires a signature from a trusted signer: the user, a verified contact, or a contact key that was verified before it was replaced.
5. It shows the text with `textContent` only, plus who signed it. If the signer's address differs from the address Gmail displayed, it says so.
6. The frame reports only its height back to the page.

Unsigned messages, messages from unverified keys, tampered messages, and messages not addressed to the user show an explanation and no plaintext.

## Writing a message

1. The content script adds an **Encrypt** button to each Gmail compose box.
2. Clicking it opens a `compose.html` frame over the compose box and posts the addresses it found in the To and CC fields.
3. The user checks or edits the recipients and types the message in the frame.
4. The frame resolves every address to a verified contact key. If any address cannot be resolved, it encrypts nothing and lists the problems.
5. It signs, encrypts to all recipients and to the user, and posts the armored text back.
6. The content script replaces the compose body with the armored text. The user sends with Gmail's own Send button.

## Messages between the page and the frames

All messages are plain objects with a `type` starting `gmail-e2ee:` and a random `frameId` chosen by the content script.

| Direction | Type | Carries |
| --- | --- | --- |
| frame to page | `ready` | nothing; asks for input |
| page to reader | `show` | armored text, displayed sender address |
| page to compose | `compose` | addresses from To and CC |
| reader or compose to page | `resize` | frame height |
| compose to page | `encrypted` | armored text |
| compose to page | `cancel` | nothing |

Frames check `event.origin` and `event.source`, and post back with an explicit target origin. Plaintext never crosses this channel.

## Manifest

- Manifest V3, minimum permissions: `storage`, `alarms`. No host permissions beyond the content script match for `https://mail.google.com/*`.
- `viewer.html` and `compose.html` are web-accessible only to `https://mail.google.com`.
- Extension pages use `script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors https://mail.google.com`, so no inline or remote script can run and no other site can frame the pages.

## Testing

`npm run test:e2e` builds a test variant of the extension (`dist-extension-e2e/`) and loads it into Chromium with Playwright. The variant differs from the real build in one way: it also accepts `http://localhost:4173`, where `e2e/fake-gmail.html` stands in for Gmail. That page copies the markup the content script relies on and records every window message and every change to its compose box, so tests can assert that plaintext never reaches the page. The real build contains no trace of the test origin.

The stand-in page is not Gmail. Everything in `extension/content/gmailDom.ts` encodes an assumption about Gmail's markup and needs a manual check against the real site.

## Known limits

- **Gmail's page structure is not a stable interface.** Finding compose boxes and recipient fields relies on attributes Gmail has used for years, but Google can change them. Reading relies only on the armored text itself. When a lookup fails, the compose frame still works with recipients typed by hand, and the armored text can be copied.
- **Redressing.** The page controls where frames sit and can cover or imitate them. It cannot read them. The frames never accept the passphrase for this reason.
- **Metadata.** Sender, recipients, subject, timing and size remain visible to Gmail. Recipient key IDs are visible in every encrypted message.
- **BCC.** Only To and CC are read. A BCC recipient is not encrypted to unless added by hand, and would then be visible to the others by key ID.
- **Clipped messages.** Gmail truncates very long messages in the thread view; a truncated armored block is not detected until the full message is opened.
- **Replies do not quote** the decrypted text, because the compose frame never receives it.
- **A compromised browser or a malicious extension with broader permissions** can defeat all of this.
