// Content script for the Gmail page. It finds armored messages and compose boxes, places
// the extension's frames, and inserts finished armored text. It runs inside the page it
// does not trust, so it is given no keys and never sees plaintext.

import { newFrameId, parseFrameMessage, type PageToFrameMessage } from "../protocol";
import {
  findArmoredBlocks,
  findComposeBoxes,
  findSenderEmail,
  insertArmoredText,
  MARKER_ATTRIBUTE,
  readRecipients,
  type ArmoredBlock
} from "./gmailDom";

const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL("")).origin;
const MIN_FRAME_HEIGHT = 60;
const MAX_FRAME_HEIGHT = 4_000;
const ACCENT = "#176b87";

interface MountedFrame {
  iframe: HTMLIFrameElement;
  /** What to send once the frame says it is ready. */
  input: PageToFrameMessage;
  /** Compose frames only: the Gmail editor being replaced, and how to close the frame. */
  compose?: { box: HTMLElement; close: () => void };
}

const frames = new Map<string, MountedFrame>();

function createFrame(page: "viewer.html" | "compose.html", frameId: string, title: string): HTMLIFrameElement {
  const iframe = document.createElement("iframe");
  iframe.src = `${chrome.runtime.getURL(page)}#${frameId}`;
  iframe.title = title;
  iframe.setAttribute(MARKER_ATTRIBUTE, "frame");
  iframe.style.cssText = `display:block;width:100%;height:${MIN_FRAME_HEIGHT}px;border:0;color-scheme:light;`;
  return iframe;
}

function createWrapper(kind: string): HTMLDivElement {
  const wrapper = document.createElement("div");
  wrapper.setAttribute(MARKER_ATTRIBUTE, kind);
  wrapper.style.cssText = `margin:8px 0;border:1px solid #c9d5de;border-left:4px solid ${ACCENT};border-radius:6px;background:#fff;overflow:hidden;`;
  return wrapper;
}

function createButton(label: string): HTMLButtonElement {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.style.cssText = `margin:0;padding:4px 10px;border:1px solid ${ACCENT};border-radius:4px;background:#fff;color:${ACCENT};font:500 12px/1.4 system-ui,sans-serif;cursor:pointer;`;
  return button;
}

/** Replaces an armored block with a reader frame. */
function mountViewer(block: ArmoredBlock): void {
  block.element.setAttribute(MARKER_ATTRIBUTE, "source");
  const frameId = newFrameId();
  const wrapper = createWrapper("viewer");
  const iframe = createFrame("viewer.html", frameId, "Decrypted message (Gmail E2EE)");
  wrapper.append(iframe);
  if (block.standalone) {
    // The element holds only ciphertext, so it can be folded away behind a toggle.
    const toggle = createButton("Show encrypted text");
    toggle.style.margin = "6px 8px";
    block.element.style.display = "none";
    toggle.addEventListener("click", () => {
      const hidden = block.element.style.display === "none";
      block.element.style.display = hidden ? "" : "none";
      toggle.textContent = hidden ? "Hide encrypted text" : "Show encrypted text";
    });
    wrapper.append(toggle);
  }
  block.element.insertAdjacentElement("afterend", wrapper);
  frames.set(frameId, {
    iframe,
    input: { type: "gmail-e2ee:show", frameId, armored: block.armored, claimedSender: findSenderEmail(block.element) }
  });
}

/** Adds the Encrypt button above a Gmail compose box. */
function mountComposeToolbar(box: HTMLElement): void {
  box.setAttribute(MARKER_ATTRIBUTE, "compose-box");
  const toolbar = document.createElement("div");
  toolbar.setAttribute(MARKER_ATTRIBUTE, "toolbar");
  toolbar.style.cssText = "margin:6px 0;";
  const button = createButton("Encrypt with Gmail E2EE");
  button.addEventListener("click", () => openComposeFrame(box, toolbar));
  toolbar.append(button);
  box.insertAdjacentElement("beforebegin", toolbar);
}

/**
 * Opens the compose frame in place of Gmail's editor. The editor is hidden while the
 * frame is open, so the message is typed into the frame and never into the Gmail page,
 * which would save it to Google as a draft.
 */
function openComposeFrame(box: HTMLElement, toolbar: HTMLElement): void {
  if ([...frames.values()].some((frame) => frame.compose?.box === box)) return;
  const frameId = newFrameId();
  const wrapper = createWrapper("compose");
  const iframe = createFrame("compose.html", frameId, "Write an encrypted message (Gmail E2EE)");
  wrapper.append(iframe);
  const previousDisplay = box.style.display;
  box.style.display = "none";
  toolbar.style.display = "none";
  toolbar.insertAdjacentElement("afterend", wrapper);
  const close = () => {
    frames.delete(frameId);
    wrapper.remove();
    box.style.display = previousDisplay;
    toolbar.style.display = "";
  };
  frames.set(frameId, {
    iframe,
    input: { type: "gmail-e2ee:compose", frameId, recipients: readRecipients(box) },
    compose: { box, close }
  });
}

window.addEventListener("message", (event) => {
  // Only this extension's own frames are listened to.
  if (event.origin !== EXTENSION_ORIGIN) return;
  const message = parseFrameMessage(event.data);
  const frame = message && frames.get(message.frameId);
  if (!message || !frame || event.source !== frame.iframe.contentWindow) return;
  switch (message.type) {
    case "gmail-e2ee:ready":
      frame.iframe.contentWindow?.postMessage(frame.input, EXTENSION_ORIGIN);
      break;
    case "gmail-e2ee:resize":
      frame.iframe.style.height = `${Math.min(MAX_FRAME_HEIGHT, Math.max(MIN_FRAME_HEIGHT, Math.ceil(message.height)))}px`;
      break;
    case "gmail-e2ee:cancel":
      frame.compose?.close();
      break;
    case "gmail-e2ee:encrypted":
      if (!frame.compose) break;
      frame.compose.close();
      if (!insertArmoredText(frame.compose.box, message.armored)) {
        // The page refused the text. Leave it for the user to copy rather than lose it.
        void navigator.clipboard.writeText(message.armored).catch(() => undefined);
        window.alert("Gmail E2EE could not place the encrypted text in the message. It was copied to the clipboard; paste it into the message body.");
      }
      break;
  }
});

function scan(): void {
  for (const [frameId, frame] of frames) {
    if (!frame.iframe.isConnected) frames.delete(frameId);
  }
  for (const block of findArmoredBlocks(document.body)) mountViewer(block);
  for (const box of findComposeBoxes(document)) {
    if (!box.hasAttribute(MARKER_ATTRIBUTE)) mountComposeToolbar(box);
  }
}

// Gmail builds its pages as the user moves around, so the page is rescanned after changes.
let scanTimer: number | undefined;
new MutationObserver(() => {
  if (scanTimer !== undefined) return;
  scanTimer = window.setTimeout(() => {
    scanTimer = undefined;
    scan();
  }, 400);
}).observe(document.documentElement, { childList: true, subtree: true, characterData: true });

scan();
