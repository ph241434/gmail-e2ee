/** Key under which the unlocked identity is held in chrome.storage.session. */
export const SESSION_KEY = "unlockedIdentity";

/** The identity locks itself this long after it was unlocked. */
export const AUTO_LOCK_MINUTES = 60;
export const AUTO_LOCK_ALARM = "gmail-e2ee-auto-lock";

export const GMAIL_ORIGIN = "https://mail.google.com";

// Replaced at build time. It is an empty string in the real extension; the browser-test
// build sets it to the local page that stands in for Gmail.
declare const __E2E_PAGE_ORIGIN__: string;

/** The only pages allowed to frame, and exchange messages with, the reader and compose frames. */
export const PAGE_ORIGINS: readonly string[] = __E2E_PAGE_ORIGIN__
  ? [GMAIL_ORIGIN, __E2E_PAGE_ORIGIN__]
  : [GMAIL_ORIGIN];
