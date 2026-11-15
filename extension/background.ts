import { AUTO_LOCK_ALARM, AUTO_LOCK_MINUTES, SESSION_KEY } from "./constants";

// The background worker never handles keys or plaintext. It keeps session storage closed
// to content scripts and locks the identity after a fixed time.

// This is Chrome's default, stated explicitly so a future change cannot expose the
// unlocked key to scripts running in the Gmail page.
void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });

chrome.runtime.onInstalled.addListener(({ reason }) => {
  if (reason === "install") void chrome.runtime.openOptionsPage();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "session" || !(SESSION_KEY in changes)) return;
  if (changes[SESSION_KEY].newValue === undefined) void chrome.alarms.clear(AUTO_LOCK_ALARM);
  else void chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) void chrome.storage.session.remove(SESSION_KEY);
});
