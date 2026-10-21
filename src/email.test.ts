import { describe, it, expect } from "vitest";
import { encodeRfc2822, decodeRfc2822 } from "./email.js";

describe("encodeRfc2822", () => {
  it("produces a base64url-encoded string (no +, /, or = chars)", () => {
    const encoded = encodeRfc2822({
      to: "alice@example.com",
      subject: "Hello",
      body: "Test body",
    });
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("round-trips back to a parseable RFC 2822 message", () => {
    const args = {
      to: "alice@example.com",
      subject: "Status update",
      body: "All systems nominal.",
    };
    const decoded = decodeRfc2822(encodeRfc2822(args));
    expect(decoded).toContain("To: alice@example.com");
    expect(decoded).toContain("Subject: Status update");
    expect(decoded).toContain('Content-Type: text/plain; charset="UTF-8"');
    expect(decoded.endsWith("All systems nominal.")).toBe(true);
  });

  it("omits Cc/Bcc/Reply-To headers when not provided", () => {
    const decoded = decodeRfc2822(
      encodeRfc2822({ to: "a@b.com", subject: "S", body: "B" })
    );
    expect(decoded).not.toContain("Cc:");
    expect(decoded).not.toContain("Bcc:");
    expect(decoded).not.toContain("Reply-To:");
  });

  it("includes optional headers when provided", () => {
    const decoded = decodeRfc2822(
      encodeRfc2822({
        to: "a@b.com",
        cc: "c@d.com",
        bcc: "e@f.com",
        replyTo: "g@h.com",
        subject: "S",
        body: "B",
      })
    );
    expect(decoded).toContain("Cc: c@d.com");
    expect(decoded).toContain("Bcc: e@f.com");
    expect(decoded).toContain("Reply-To: g@h.com");
  });

  it("preserves UTF-8 in body and subject", () => {
    const decoded = decodeRfc2822(
      encodeRfc2822({
        to: "alice@example.com",
        subject: "Café ☕",
        body: "Résumé — naïve fiancé",
      })
    );
    expect(decoded).toContain("Café ☕");
    expect(decoded).toContain("Résumé — naïve fiancé");
  });

  it("separates headers from body with CRLF CRLF", () => {
    const encoded = encodeRfc2822({
      to: "a@b.com",
      subject: "S",
      body: "B",
    });
    const decoded = decodeRfc2822(encoded);
    expect(decoded).toMatch(/\r\n\r\n/);
  });
});

describe("encodeRfc2822 header injection hardening", () => {
  // Payloads are assembled at runtime so the repo does not carry a
  // copy-pasteable attack string.
  const CR = String.fromCharCode(13);
  const LF = String.fromCharCode(10);
  const NUL = String.fromCharCode(0);
  const BREAK = CR + LF;
  const INJECTED_HEADER = "Bcc: someone@example.invalid";

  const base = { to: "alice@example.com", subject: "Hello", body: "hi" };

  it.each([
    ["subject", { ...base, subject: "Hello" + BREAK + INJECTED_HEADER }],
    ["to", { ...base, to: "alice@example.com" + BREAK + INJECTED_HEADER }],
    ["cc", { ...base, cc: "a@b.com" + BREAK + INJECTED_HEADER }],
    ["bcc", { ...base, bcc: "a@b.com" + BREAK + INJECTED_HEADER }],
    ["replyTo", { ...base, replyTo: "a@b.com" + BREAK + INJECTED_HEADER }],
  ])("rejects a CRLF injection attempt in %s", (_field, args) => {
    expect(() => encodeRfc2822(args as Parameters<typeof encodeRfc2822>[0])).toThrow(
      /possible header injection/
    );
  });

  it.each([
    ["bare CR", CR],
    ["bare LF", LF],
    ["NUL", NUL],
  ])("rejects a lone %s in the subject", (_name, ch) => {
    expect(() => encodeRfc2822({ ...base, subject: "Hi" + ch + "there" })).toThrow(
      /possible header injection/
    );
  });

  it("never emits an extra header block", () => {
    // Belt-and-braces: exactly one blank line, and exactly the five headers we
    // intentionally wrote. Anything else means something got injected.
    const decoded = decodeRfc2822(
      encodeRfc2822({ ...base, subject: "Status: ok", to: "a@b.com" })
    );
    const parts = decoded.split(BREAK + BREAK);
    expect(parts).toHaveLength(2);

    const headerNames = parts[0]
      .split(BREAK)
      .map((line) => line.slice(0, line.indexOf(":")));
    expect(headerNames).toEqual([
      "To",
      "Subject",
      "MIME-Version",
      "Content-Type",
      "Content-Transfer-Encoding",
    ]);
  });

  it("accepts a comma-separated list with display names", () => {
    const decoded = decodeRfc2822(
      encodeRfc2822({
        ...base,
        to: '"Doe, John" <john@example.com>, Jane Roe <jane@example.com>',
      })
    );
    expect(decoded).toContain('To: "Doe, John" <john@example.com>, Jane Roe <jane@example.com>');
  });

  it("does not split a comma that sits inside a quoted display name", () => {
    expect(() =>
      encodeRfc2822({ ...base, to: '"Doe, John" <john@example.com>' })
    ).not.toThrow();
  });

  it.each([
    ["no domain", "alice"],
    ["no @", "alice.example.com"],
    ["empty local part", "@example.com"],
    ["semicolon separator", "a@b.com;c@d.com"],
    ["stray angle bracket", "alice@example.com>"],
  ])("rejects an invalid address (%s)", (_name, to) => {
    expect(() => encodeRfc2822({ ...base, to })).toThrow(/invalid email address|empty address/);
  });

  it("rejects an empty entry in the list", () => {
    expect(() => encodeRfc2822({ ...base, to: "a@b.com, " })).toThrow(/empty address/);
  });

  it("still accepts a long but legitimate CC list", () => {
    const cc = Array.from({ length: 40 }, (_, i) => `person${i}@example.com`).join(", ");
    expect(() => encodeRfc2822({ ...base, cc })).not.toThrow();
  });
});

