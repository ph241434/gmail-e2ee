// Shared plumbing for the reader and compose frames, which run on the extension's origin
// but are shown inside the Gmail page.

import { PAGE_ORIGINS } from "./constants";
import { parsePageMessage, type FrameToPageMessage, type PageToFrameMessage } from "./protocol";

/** The content script puts the frame's id in the URL fragment when it creates the frame. */
export const frameId = location.hash.slice(1);

/**
 * Sends a message to the page that embeds this frame. The target origin is always
 * explicit, so nothing is delivered if some other site managed to frame this page.
 */
export function postToPage(message: FrameToPageMessage): void {
  for (const origin of PAGE_ORIGINS) window.parent.postMessage(message, origin);
}

/** Listens for input from the embedding page, ignoring every other sender. */
export function onPageMessage(handler: (message: PageToFrameMessage) => void): void {
  window.addEventListener("message", (event) => {
    if (event.source !== window.parent || !PAGE_ORIGINS.includes(event.origin)) return;
    const message = parsePageMessage(event.data, frameId);
    if (message) handler(message);
  });
}

/** Keeps the page informed of this frame's height, the only thing it learns about the content. */
export function reportHeight(): void {
  const report = () => postToPage({
    type: "gmail-e2ee:resize", frameId, height: document.documentElement.scrollHeight
  });
  new ResizeObserver(report).observe(document.body);
  report();
}

/** Opens the extension's own unlock window. The passphrase is never typed inside the Gmail page. */
export function openUnlockWindow(): void {
  window.open(chrome.runtime.getURL("popup.html"), "gmail-e2ee-unlock", "popup,width=400,height=440");
}

export function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Element "${id}" was not found.`);
  return found as T;
}
