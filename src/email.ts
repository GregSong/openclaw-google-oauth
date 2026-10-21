export interface Rfc2822Args {
  to: string;
  subject: string;
  body: string;
  cc?: string;
  bcc?: string;
  replyTo?: string;
}

// RFC 5322 §2.1.1: a header field is a single line. A raw CR, LF or NUL inside
// an interpolated value ends the current header and starts a new one, so an
// untrusted `subject`/`to` containing "\r\nBcc: attacker@example.com" silently
// adds recipients. Every header value is validated before it is concatenated.
const HEADER_BREAK = /[\r\n\0]/;

// Sanity bound only. RFC 5322 §2.1.1 limits a *folded* line to 998 octets, but
// this encoder does not implement folding, so a long-but-legitimate address
// list (a 30-person CC) must not be rejected. This just stops pathological
// input from producing an absurd header.
const MAX_HEADER_LENGTH = 8192;

// Conservative address check: dot-atom-ish local part, dotted domain, no
// whitespace/angle brackets/quotes/separators. Display names are handled
// separately by stripping the "Name <addr>" wrapper first.
const ADDRESS = /^[^\s@<>",;:]*[^\s@<>",;:]+@[^\s@<>",;:]+\.[^\s@<>",;:]+$/;

function assertSingleLine(name: string, value: string): string {
  if (HEADER_BREAK.test(value)) {
    throw new Error(
      `${name} must not contain CR, LF or NUL characters (possible header injection)`
    );
  }
  if (value.length > MAX_HEADER_LENGTH) {
    throw new Error(`${name} exceeds ${MAX_HEADER_LENGTH} characters`);
  }
  return value;
}

/** Split on commas that are outside quotes and outside angle brackets. */
function splitAddressList(value: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  let inAngle = false;

  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === "\\" && inQuotes && i + 1 < value.length) {
      current += ch + value[i + 1];
      i += 1;
      continue;
    }
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && ch === "<") inAngle = true;
    else if (!inQuotes && ch === ">") inAngle = false;
    else if (!inQuotes && !inAngle && ch === ",") {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts.map((part) => part.trim());
}

function assertAddressList(name: string, value: string): string {
  assertSingleLine(name, value);
  const entries = splitAddressList(value);
  if (entries.length === 0) {
    throw new Error(`${name} is empty`);
  }
  for (const entry of entries) {
    if (entry === "") {
      throw new Error(`${name} contains an empty address`);
    }
    const wrapped = /^.*<([^<>]+)>\s*$/.exec(entry);
    const address = (wrapped ? wrapped[1] : entry).trim();
    if (!ADDRESS.test(address)) {
      throw new Error(`${name} contains an invalid email address: ${entry}`);
    }
  }
  return value;
}

export function encodeRfc2822(args: Rfc2822Args): string {
  const headers = [
    `To: ${assertAddressList("to", args.to)}`,
    args.cc ? `Cc: ${assertAddressList("cc", args.cc)}` : undefined,
    args.bcc ? `Bcc: ${assertAddressList("bcc", args.bcc)}` : undefined,
    args.replyTo ? `Reply-To: ${assertAddressList("replyTo", args.replyTo)}` : undefined,
    `Subject: ${assertSingleLine("subject", args.subject)}`,
    "MIME-Version: 1.0",
    'Content-Type: text/plain; charset="UTF-8"',
    "Content-Transfer-Encoding: 7bit",
  ].filter(Boolean) as string[];
  const message = `${headers.join("\r\n")}\r\n\r\n${args.body}`;
  return Buffer.from(message)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function decodeRfc2822(encoded: string): string {
  const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(base64, "base64").toString("utf8");
}
