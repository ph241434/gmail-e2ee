// Everything that depends on how the Gmail page is built lives here, so it can be tested
// against sample markup and fixed in one place when Gmail changes. Nothing in this file
// handles keys or plaintext.

export const ARMOR_BEGIN = "-----BEGIN PGP MESSAGE-----";
export const ARMOR_END = "-----END PGP MESSAGE-----";

/** Marks elements this extension has already handled or inserted. */
export const MARKER_ATTRIBUTE = "data-gmail-e2ee";

const BLOCK_ELEMENTS = new Set(["DIV", "P", "PRE", "LI", "TR", "BLOCKQUOTE", "TABLE", "SECTION"]);
const MAX_ANCESTOR_STEPS = 6;
const EMAIL_PATTERN = /[^\s<>,;:"'()[\]]+@[^\s<>,;:"'()[\]]+\.[^\s<>,;:"'()[\]]+/g;

export interface ArmoredBlock {
  /** The smallest element containing the whole armored message. */
  element: HTMLElement;
  armored: string;
  /** True when the element holds nothing but the armored message, so it can be hidden. */
  standalone: boolean;
}

/** Text of an element with line breaks where the page shows them. */
export function extractText(node: Node): string {
  if (node.nodeType === Node.TEXT_NODE) return (node as Text).data;
  if (node.nodeType !== Node.ELEMENT_NODE) return "";
  const element = node as Element;
  if (element.tagName === "BR") return "\n";
  if (element.tagName === "SCRIPT" || element.tagName === "STYLE") return "";
  let text = "";
  for (const child of element.childNodes) text += extractText(child);
  return BLOCK_ELEMENTS.has(element.tagName) ? `\n${text}\n` : text;
}

/**
 * Rebuilds a clean armored block from text copied out of a page: removes reply quote
 * marks, stray indentation and blank lines the page added. Returns undefined when the
 * text does not hold exactly one complete block.
 */
export function normalizeArmor(text: string): string | undefined {
  const begin = text.indexOf(ARMOR_BEGIN);
  const end = text.indexOf(ARMOR_END, begin + ARMOR_BEGIN.length);
  if (begin < 0 || end < 0) return undefined;
  const inner = text.slice(begin + ARMOR_BEGIN.length, end);
  // A second BEGIN before the END means two messages ran together, for example a clipped one.
  if (inner.includes("-----BEGIN PGP")) return undefined;
  const lines = inner.split(/\r?\n/).map((line) => line.replace(/^(?:\s*>)+/, "").trim()).filter((line) => line !== "");
  const headers: string[] = [];
  while (lines.length && /^[A-Za-z-]+: /.test(lines[0])) headers.push(lines.shift()!);
  // If the page collapsed line breaks into spaces, the Base64 body is still intact once split.
  const body = lines.flatMap((line) => line.split(/\s+/));
  if (body.length === 0 || body.some((line) => !/^[A-Za-z0-9+/=]+$/.test(line))) return undefined;
  return [ARMOR_BEGIN, ...headers, "", ...body, ARMOR_END].join("\n");
}

/**
 * Finds armored messages shown on the page. Text inside editable areas is skipped, so a
 * message the user is about to send is never replaced.
 */
export function findArmoredBlocks(root: ParentNode & Node): ArmoredBlock[] {
  const blocks: ArmoredBlock[] = [];
  const document = root.ownerDocument ?? (root as Document);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const offset = (node as Text).data.indexOf(ARMOR_BEGIN);
    if (offset < 0) continue;
    let element = node.parentElement;
    if (!element || element.closest(`[contenteditable="true"], textarea, script, style, [${MARKER_ATTRIBUTE}]`)) continue;
    // Climb to the smallest ancestor that holds an end marker after this begin marker.
    const textFrom = (ancestor: Element, toEnd: boolean): string => {
      const range = document.createRange();
      if (toEnd) {
        range.setStart(node!, offset);
        range.setEndAfter(ancestor.lastChild ?? ancestor);
      } else {
        range.setStartBefore(ancestor.firstChild ?? ancestor);
        range.setEnd(node!, offset);
      }
      return range.toString();
    };
    for (let steps = 0; element && steps < MAX_ANCESTOR_STEPS && !textFrom(element, true).includes(ARMOR_END); steps += 1) {
      element = element.parentElement;
    }
    if (!element || element === document.body || element === document.documentElement) continue;
    // The ancestor may hold other messages too (a thread, a quoted reply), so pick out the
    // block that starts at this node. A block cut short by Gmail runs into the next begin
    // marker and is rejected by normalizeArmor.
    const blocksBefore = textFrom(element, false).split(ARMOR_BEGIN).length - 1;
    const text = extractText(element);
    let begin = -1;
    for (let count = 0; count <= blocksBefore; count += 1) begin = text.indexOf(ARMOR_BEGIN, begin + 1);
    if (begin < 0) continue;
    const armored = normalizeArmor(text.slice(begin));
    if (!armored) continue;
    const end = text.indexOf(ARMOR_END, begin) + ARMOR_END.length;
    const standalone = (text.slice(0, begin) + text.slice(end)).trim() === "";
    blocks.push({ element: element as HTMLElement, armored, standalone });
  }
  return blocks;
}

/**
 * The sender address Gmail shows for the message containing `element`. This is only a
 * hint for the reader frame, which decides for itself who signed the message.
 */
export function findSenderEmail(element: Element): string | undefined {
  for (let node: Element | null = element, steps = 0; node && steps < 20; node = node.parentElement, steps += 1) {
    // Gmail puts the sender in span.gD[email]; recipients use other classes but the same attribute.
    const sender = node.querySelector(".gD[email]") ?? node.querySelector("[email]");
    const email = sender?.getAttribute("email")?.trim().toLowerCase();
    if (email && email.includes("@")) return email;
  }
  return undefined;
}

/** Gmail's message editors: the pop-up compose window and inline replies. */
export function findComposeBoxes(root: ParentNode): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>('div[contenteditable="true"][role="textbox"]')].filter((box) =>
    box.getAttribute("g_editable") === "true" ||
    box.getAttribute("aria-multiline") === "true" ||
    /message body/i.test(box.getAttribute("aria-label") ?? ""));
}

/** The form or dialog that holds a compose box together with its recipient and subject fields. */
function findComposeContainer(box: Element): Element {
  let fallback: Element | null = null;
  for (let node = box.parentElement, steps = 0; node && steps < 25; node = node.parentElement, steps += 1) {
    if (node.querySelector('[name="subjectbox"], [name="to"]')) return node;
    if (!fallback && (node.tagName === "FORM" || node.getAttribute("role") === "dialog")) fallback = node;
  }
  return fallback ?? box.parentElement ?? box;
}

/**
 * Addresses in the To and CC fields of the compose window around `box`. Gmail has shown
 * recipients both as form fields and as chips carrying the address in an attribute, so
 * both are read. The result only pre-fills the compose frame, where the user checks it.
 */
export function readRecipients(box: Element): string[] {
  const container = findComposeContainer(box);
  const found: string[] = [];
  const add = (value: string | null | undefined) => {
    for (const match of (value ?? "").match(EMAIL_PATTERN) ?? []) {
      const email = match.toLowerCase();
      if (!found.includes(email)) found.push(email);
    }
  };
  for (const field of container.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>(
    'input[name="to"], input[name="cc"], textarea[name="to"], textarea[name="cc"]')) add(field.value);
  for (const chip of container.querySelectorAll("[data-hovercard-id], [email]")) {
    if (box.contains(chip)) continue;
    add(chip.getAttribute("data-hovercard-id"));
    add(chip.getAttribute("email"));
  }
  return found;
}

/**
 * Replaces the compose body with armored text. Tries the browser's own text insertion
 * first, because Gmail reacts to it like typing; falls back to setting the content
 * directly. Returns false if the text did not end up in the box.
 */
export function insertArmoredText(box: HTMLElement, armored: string): boolean {
  const document = box.ownerDocument;
  box.focus();
  let inserted = false;
  try {
    const selection = document.getSelection();
    const range = document.createRange();
    range.selectNodeContents(box);
    selection?.removeAllRanges();
    selection?.addRange(range);
    inserted = document.execCommand("insertText", false, armored);
  } catch {
    inserted = false;
  }
  if (!inserted || normalizeArmor(extractText(box)) !== normalizeArmor(armored)) {
    box.replaceChildren();
    for (const line of armored.split("\n")) box.append(document.createTextNode(line), document.createElement("br"));
    box.dispatchEvent(new Event("input", { bubbles: true }));
  }
  return normalizeArmor(extractText(box)) === normalizeArmor(armored);
}
