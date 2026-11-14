/** Key under which the unlocked identity is held in chrome.storage.session. */
export const SESSION_KEY = "unlockedIdentity";

/** The identity locks itself this long after it was unlocked. */
export const AUTO_LOCK_MINUTES = 60;
export const AUTO_LOCK_ALARM = "gmail-e2ee-auto-lock";

/** The only page allowed to frame the reader and compose pages. */
export const GMAIL_ORIGIN = "https://mail.google.com";
