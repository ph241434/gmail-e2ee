// Messages between the Gmail page (content script) and the extension's frames.
// Plaintext and keys never appear in any of them. Everything arriving from the page
// side is untrusted input; everything sent to the page is safe for the page to see.

export const MESSAGE_PREFIX = "gmail-e2ee:";

/** Upper bounds on what a frame accepts from the page. */
export const MAX_ARMORED_LENGTH = 5_000_000;
export const MAX_HINT_LENGTH = 320;
export const MAX_RECIPIENT_HINTS = 60;

/** Frame to page: the frame has loaded and wants its input. */
export interface ReadyMessage { type: "gmail-e2ee:ready"; frameId: string }
/** Page to reader frame: one armored message and the sender address the page displays. */
export interface ShowMessage { type: "gmail-e2ee:show"; frameId: string; armored: string; claimedSender?: string }
/** Page to compose frame: addresses found in the To and CC fields. */
export interface ComposeMessage { type: "gmail-e2ee:compose"; frameId: string; recipients: string[] }
/** Frame to page: the frame's content height in pixels. */
export interface ResizeMessage { type: "gmail-e2ee:resize"; frameId: string; height: number }
/** Compose frame to page: the finished armored message. */
export interface EncryptedMessage { type: "gmail-e2ee:encrypted"; frameId: string; armored: string }
/** Compose frame to page: the user closed the editor without encrypting. */
export interface CancelMessage { type: "gmail-e2ee:cancel"; frameId: string }

export type FrameToPageMessage = ReadyMessage | ResizeMessage | EncryptedMessage | CancelMessage;
export type PageToFrameMessage = ShowMessage | ComposeMessage;

export function newFrameId(): string {
  return crypto.randomUUID();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Validates a message arriving in a frame from the page. Returns undefined for anything unexpected. */
export function parsePageMessage(data: unknown, frameId: string): PageToFrameMessage | undefined {
  if (!isRecord(data) || data.frameId !== frameId) return undefined;
  if (data.type === "gmail-e2ee:show") {
    if (typeof data.armored !== "string" || data.armored.length > MAX_ARMORED_LENGTH) return undefined;
    const claimedSender = typeof data.claimedSender === "string" && data.claimedSender.length <= MAX_HINT_LENGTH
      ? data.claimedSender : undefined;
    return { type: data.type, frameId, armored: data.armored, claimedSender };
  }
  if (data.type === "gmail-e2ee:compose") {
    const recipients = Array.isArray(data.recipients)
      ? data.recipients.filter((value): value is string => typeof value === "string" && value.length <= MAX_HINT_LENGTH)
        .slice(0, MAX_RECIPIENT_HINTS)
      : [];
    return { type: data.type, frameId, recipients };
  }
  return undefined;
}

/** Validates a message arriving in the page from a frame. Returns undefined for anything unexpected. */
export function parseFrameMessage(data: unknown): FrameToPageMessage | undefined {
  if (!isRecord(data) || typeof data.frameId !== "string" || typeof data.type !== "string") return undefined;
  const { frameId } = data;
  switch (data.type) {
    case "gmail-e2ee:ready":
    case "gmail-e2ee:cancel":
      return { type: data.type, frameId };
    case "gmail-e2ee:resize":
      return typeof data.height === "number" && Number.isFinite(data.height)
        ? { type: data.type, frameId, height: data.height } : undefined;
    case "gmail-e2ee:encrypted":
      return typeof data.armored === "string" && data.armored.length <= MAX_ARMORED_LENGTH
        ? { type: data.type, frameId, armored: data.armored } : undefined;
    default:
      return undefined;
  }
}
