import { describe, expect, test } from "vitest";
import { ARMOR_BEGIN, ARMOR_END, normalizeArmor } from "../extension/content/gmailDom";
import {
  MAX_ARMORED_LENGTH,
  MAX_RECIPIENT_HINTS,
  parseFrameMessage,
  parsePageMessage
} from "../extension/protocol";

const BODY = ["wV4DMdfL7jXx9wISAQdA8VGJaaiCfIAxXrlsR6zCUfrrGDA/r+S7DGLjyB7G", "WiQwyVebu1kkXqZSD5MZY09CZ1T/TkgCebDXVIQkvhbhY8niOQdXOo00FybC", "=x08g"];
const CLEAN = [ARMOR_BEGIN, "", ...BODY, ARMOR_END].join("\n");

describe("armored text copied out of a web page", () => {
  test("a clean block is returned unchanged", () => {
    expect(normalizeArmor(CLEAN)).toBe(CLEAN);
  });

  test("surrounding text, indentation, blank lines and CRLF are removed", () => {
    const messy = `Hi Bob,\r\n\r\n  ${ARMOR_BEGIN}\r\n\r\n\r\n   ${BODY[0]}\r\n\r\n${BODY[1]}  \r\n${BODY[2]}\r\n${ARMOR_END}\r\n\r\nSent from my phone`;
    expect(normalizeArmor(messy)).toBe(CLEAN);
  });

  test("reply quote marks are removed, however deep", () => {
    const quoted = CLEAN.split("\n").map((line) => `> > ${line}`).join("\n");
    expect(normalizeArmor(quoted)).toBe(CLEAN);
  });

  test("armor headers are kept ahead of the blank line", () => {
    const withHeader = [ARMOR_BEGIN, "Comment: sent with care", "", ...BODY, ARMOR_END].join("\n");
    expect(normalizeArmor(withHeader.replace("\n\n", "\n"))).toBe(withHeader);
  });

  test("a body whose line breaks became spaces is rebuilt", () => {
    expect(normalizeArmor(`${ARMOR_BEGIN} ${BODY.join(" ")} ${ARMOR_END}`)).toBe(CLEAN);
  });

  test.each([
    ["no end marker (a clipped message)", `${ARMOR_BEGIN}\n\n${BODY[0]}`],
    ["no begin marker", `${BODY[0]}\n${ARMOR_END}`],
    ["a clipped message running into the next one", `${ARMOR_BEGIN}\n\n${BODY[0]}\n${CLEAN}`],
    ["an empty body", `${ARMOR_BEGIN}\n\n${ARMOR_END}`],
    ["text that is not Base64 inside the block", `${ARMOR_BEGIN}\n\nthis is <b>not</b> armor\n${ARMOR_END}`]
  ])("returns nothing for %s", (_label, text) => {
    expect(normalizeArmor(text)).toBeUndefined();
  });
});

describe("messages from the page to a frame", () => {
  test("accepts a well-formed show message for this frame", () => {
    expect(parsePageMessage({ type: "gmail-e2ee:show", frameId: "f1", armored: CLEAN, claimedSender: "a@example.test" }, "f1"))
      .toEqual({ type: "gmail-e2ee:show", frameId: "f1", armored: CLEAN, claimedSender: "a@example.test" });
  });

  test("ignores messages for another frame, unknown types, and non-objects", () => {
    expect(parsePageMessage({ type: "gmail-e2ee:show", frameId: "other", armored: CLEAN }, "f1")).toBeUndefined();
    expect(parsePageMessage({ type: "gmail-e2ee:decrypt-and-return", frameId: "f1" }, "f1")).toBeUndefined();
    expect(parsePageMessage("gmail-e2ee:show", "f1")).toBeUndefined();
    expect(parsePageMessage(null, "f1")).toBeUndefined();
  });

  test("rejects oversized or mistyped armored text and drops a bad sender hint", () => {
    expect(parsePageMessage({ type: "gmail-e2ee:show", frameId: "f1", armored: "x".repeat(MAX_ARMORED_LENGTH + 1) }, "f1")).toBeUndefined();
    expect(parsePageMessage({ type: "gmail-e2ee:show", frameId: "f1", armored: 42 }, "f1")).toBeUndefined();
    expect(parsePageMessage({ type: "gmail-e2ee:show", frameId: "f1", armored: CLEAN, claimedSender: { toString: () => "x" } }, "f1"))
      .toEqual({ type: "gmail-e2ee:show", frameId: "f1", armored: CLEAN, claimedSender: undefined });
  });

  test("keeps only string recipient hints, and only a bounded number", () => {
    const many = Array.from({ length: MAX_RECIPIENT_HINTS + 20 }, (_, index) => `user${index}@example.test`);
    const parsed = parsePageMessage({ type: "gmail-e2ee:compose", frameId: "f1", recipients: [7, null, ...many] }, "f1");
    expect(parsed).toMatchObject({ type: "gmail-e2ee:compose" });
    expect((parsed as { recipients: string[] }).recipients).toEqual(many.slice(0, MAX_RECIPIENT_HINTS));
    expect(parsePageMessage({ type: "gmail-e2ee:compose", frameId: "f1", recipients: "a@example.test" }, "f1"))
      .toEqual({ type: "gmail-e2ee:compose", frameId: "f1", recipients: [] });
  });
});

describe("messages from a frame to the page", () => {
  test("accepts the four known messages", () => {
    expect(parseFrameMessage({ type: "gmail-e2ee:ready", frameId: "f1" })).toEqual({ type: "gmail-e2ee:ready", frameId: "f1" });
    expect(parseFrameMessage({ type: "gmail-e2ee:cancel", frameId: "f1", extra: 1 })).toEqual({ type: "gmail-e2ee:cancel", frameId: "f1" });
    expect(parseFrameMessage({ type: "gmail-e2ee:resize", frameId: "f1", height: 120 })).toEqual({ type: "gmail-e2ee:resize", frameId: "f1", height: 120 });
    expect(parseFrameMessage({ type: "gmail-e2ee:encrypted", frameId: "f1", armored: CLEAN })).toEqual({ type: "gmail-e2ee:encrypted", frameId: "f1", armored: CLEAN });
  });

  test("rejects malformed ones", () => {
    expect(parseFrameMessage({ type: "gmail-e2ee:resize", frameId: "f1", height: "tall" })).toBeUndefined();
    expect(parseFrameMessage({ type: "gmail-e2ee:resize", frameId: "f1", height: Number.NaN })).toBeUndefined();
    expect(parseFrameMessage({ type: "gmail-e2ee:encrypted", frameId: "f1" })).toBeUndefined();
    expect(parseFrameMessage({ type: "gmail-e2ee:ready" })).toBeUndefined();
    expect(parseFrameMessage({ type: "something-else", frameId: "f1" })).toBeUndefined();
  });
});
