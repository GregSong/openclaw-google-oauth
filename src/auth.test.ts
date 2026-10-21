import { beforeEach, describe, it, expect } from "vitest";
import { homedir } from "node:os";
import {
  expandHome,
  SCOPES,
  createAuthState,
  peekAuthState,
  consumeAuthState,
  clearAuthStates,
  parseAuthInput,
  assertAccountAllowed,
  metaPathFor,
} from "./auth.js";

describe("expandHome", () => {
  it("returns homedir for '~'", () => {
    expect(expandHome("~")).toBe(homedir());
  });

  it("expands '~/' prefix", () => {
    expect(expandHome("~/foo/bar")).toBe(`${homedir()}/foo/bar`);
  });

  it("does not expand mid-path tildes", () => {
    expect(expandHome("/etc/~/foo")).toBe("/etc/~/foo");
  });

  it("passes absolute paths through unchanged", () => {
    expect(expandHome("/var/log/app.log")).toBe("/var/log/app.log");
  });

  it("passes relative paths through unchanged", () => {
    expect(expandHome("./relative/path")).toBe("./relative/path");
  });
});

describe("SCOPES", () => {
  it("includes scopes for all six Workspace APIs", () => {
    const families = [
      "gmail",
      "calendar",
      "drive",
      "documents",
      "spreadsheets",
      "presentations",
    ];
    for (const family of families) {
      expect(
        SCOPES.some((s) => s.includes(family)),
        `no scope for ${family}`
      ).toBe(true);
    }
  });

  it("uses Google's HTTPS scope URLs", () => {
    for (const scope of SCOPES) {
      expect(scope).toMatch(/^https:\/\/www\.googleapis\.com\/auth\//);
    }
  });

  it("requests gmail.modify (read+label) instead of gmail.readonly", () => {
    expect(SCOPES).toContain("https://www.googleapis.com/auth/gmail.modify");
    expect(SCOPES).not.toContain("https://www.googleapis.com/auth/gmail.readonly");
  });

  it("requests full drive scope (so shared folders/files are visible)", () => {
    expect(SCOPES).toContain("https://www.googleapis.com/auth/drive");
    // drive.file is intentionally NOT requested — it only lets the app see
    // files it created itself, not files merely shared with the account.
    // That broke the "sharer controls access via Drive ACLs" mental model.
    expect(SCOPES).not.toContain("https://www.googleapis.com/auth/drive.file");
  });
});

describe("OAuth state", () => {
  beforeEach(() => clearAuthStates());

  it("mints distinct, URL-safe values", () => {
    const a = createAuthState();
    const b = createAuthState();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]{40,}$/);
  });

  it("accepts a fresh state", () => {
    const state = createAuthState();
    expect(peekAuthState(state)).toBe(true);
  });

  it("peeking does not consume the state", () => {
    const state = createAuthState();
    expect(peekAuthState(state)).toBe(true);
    expect(peekAuthState(state)).toBe(true);
    expect(consumeAuthState(state)).toBe(true);
  });

  it("is single-use", () => {
    const state = createAuthState();
    expect(consumeAuthState(state)).toBe(true);
    expect(consumeAuthState(state)).toBe(false);
    expect(peekAuthState(state)).toBe(false);
  });

  it("rejects a state it never minted", () => {
    expect(peekAuthState("made-up-no-such-state")).toBe(false);
    expect(consumeAuthState("made-up-no-such-state")).toBe(false);
  });

  it("expires after the TTL", () => {
    const at = 1_000_000;
    const state = createAuthState(at);
    // TTL is 10 minutes — one millisecond past it must be rejected.
    expect(peekAuthState(state, at + 10 * 60 * 1000 + 1)).toBe(false);
  });

  it("forgets everything on clear", () => {
    const state = createAuthState();
    clearAuthStates();
    expect(peekAuthState(state)).toBe(false);
  });
});

describe("parseAuthInput", () => {
  it("treats a bare code as a code", () => {
    expect(parseAuthInput("4/0Ax4XfWh")).toEqual({ code: "4/0Ax4XfWh" });
  });

  it("extracts code and state from the full redirect URL", () => {
    const parsed = parseAuthInput(
      "http://localhost:3000/?code=4%2F0Ax4XfWh&state=abc123&scope=drive"
    );
    expect(parsed.code).toBe("4/0Ax4XfWh");
    expect(parsed.state).toBe("abc123");
  });

  it("reports a missing state rather than inventing one", () => {
    const parsed = parseAuthInput("http://localhost:3000/?code=abc");
    expect(parsed.code).toBe("abc");
    expect(parsed.state).toBeUndefined();
  });

  it("trims surrounding whitespace", () => {
    expect(parseAuthInput("  abc  ")).toEqual({ code: "abc" });
  });

  it("does not mistake prose for a URL", () => {
    expect(parseAuthInput("the code is abc")).toEqual({ code: "the code is abc" });
  });
});

describe("assertAccountAllowed", () => {
  it("allows the first authorization when nothing is recorded", () => {
    expect(() => assertAccountAllowed({ actual: "me@example.com" })).not.toThrow();
  });

  it("allows a matching recorded account, case-insensitively", () => {
    expect(() =>
      assertAccountAllowed({
        recorded: "Me@Example.com",
        actual: "me@example.com",
      })
    ).not.toThrow();
  });

  it("blocks a silent account swap", () => {
    expect(() =>
      assertAccountAllowed({
        recorded: "me@example.com",
        actual: "attacker@evil.invalid",
      })
    ).toThrow(/differs from the account this plugin previously authorized/);
  });

  it("allows an intentional swap when allowChange is set", () => {
    expect(() =>
      assertAccountAllowed({
        recorded: "me@example.com",
        actual: "other@example.com",
        allowChange: true,
      })
    ).not.toThrow();
  });

  it("pins to expectedAccount when configured", () => {
    expect(() =>
      assertAccountAllowed({
        actual: "me@example.com",
        expected: "me@example.com",
      })
    ).not.toThrow();
    expect(() =>
      assertAccountAllowed({
        actual: "attacker@evil.invalid",
        expected: "me@example.com",
      })
    ).toThrow(/expectedAccount/);
  });

  it("does not let allowChange override the explicit expectedAccount pin", () => {
    expect(() =>
      assertAccountAllowed({
        actual: "attacker@evil.invalid",
        expected: "me@example.com",
        allowChange: true,
      })
    ).toThrow(/expectedAccount/);
  });
});

describe("metaPathFor", () => {
  it("puts metadata beside the token file", () => {
    expect(metaPathFor("/tmp/gmail-token.json")).toBe(
      "/tmp/gmail-token.json.meta.json"
    );
  });
});
