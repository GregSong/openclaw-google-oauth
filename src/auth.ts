import { google } from "googleapis";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import type { OAuth2Client } from "google-auth-library";

export interface AuthConfig {
  credentialsPath: string;
  tokenPath: string;
  /** Refuse to finish OAuth unless the authorized account matches this email. */
  expectedAccount?: string;
  /** Allow the account to differ from the one previously authorized. */
  allowAccountChange?: boolean;
}

export const SCOPES = [
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar.events",
  // Drive is deliberately split in two instead of requesting the account-wide
  // `auth/drive` scope:
  //
  //   drive.readonly — see and download everything, so the agent can still
  //                    browse the account's own and shared files. Read-only
  //                    means a wrong or injected fileId can at worst reveal
  //                    something, never destroy it.
  //   drive.file     — create/edit/delete *only* files this app itself
  //                    created. Google enforces this, so destructive
  //                    operations (trash, permissions.create) on a
  //                    pre-existing file fail with 403 no matter what the
  //                    model decides to do.
  //
  // The union is "read anything, mutate only what we made". Note the split is
  // by *who created the file*, not by owner: a document the user built by hand
  // is therefore read-only to this plugin.
  //
  // Content-level edits of existing Google Docs/Sheets/Slides are still
  // allowed through the documents/spreadsheets/presentations scopes below —
  // those are account-wide by design and cannot be narrowed per file.
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/drive.file",
  "https://www.googleapis.com/auth/documents",
  "https://www.googleapis.com/auth/spreadsheets",
  "https://www.googleapis.com/auth/presentations",
];

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return resolve(homedir(), p.slice(2));
  return p;
}

interface InstalledCredentials {
  installed?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
  web?: {
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
  };
}

async function readCredentials(credentialsPath: string) {
  const raw = await readFile(expandHome(credentialsPath), "utf8");
  const parsed = JSON.parse(raw) as InstalledCredentials;
  const creds = parsed.installed ?? parsed.web;
  if (!creds) {
    throw new Error(
      `Credentials file at ${credentialsPath} is missing "installed" or "web" block`
    );
  }
  return creds;
}

export async function createOAuthClient(
  config: AuthConfig
): Promise<OAuth2Client> {
  const creds = await readCredentials(config.credentialsPath);
  const client = new google.auth.OAuth2(
    creds.client_id,
    creds.client_secret,
    creds.redirect_uris[0]
  );

  try {
    const tokenRaw = await readFile(expandHome(config.tokenPath), "utf8");
    client.setCredentials(JSON.parse(tokenRaw));
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      throw err;
    }
  }

  return client;
}

// ── OAuth state ─────────────────────────────────────────────────────────────
//
// Without a `state` parameter an authorization code is accepted from anywhere:
// whoever can get the agent to call google_auth_complete wins, including an
// injected instruction that carries the attacker's own code. Accepting it
// overwrites the token file, after which every "user" request is served
// against the attacker's Google account. (OAuth 2.0 §10.12.)

const STATE_TTL_MS = 10 * 60 * 1000;
const pendingStates = new Map<string, number>();

/** Mint a single-use state value and remember it until it expires. */
export function createAuthState(now: number = Date.now()): string {
  for (const [state, expiresAt] of pendingStates) {
    if (expiresAt <= now) pendingStates.delete(state);
  }
  const state = randomBytes(32).toString("base64url");
  pendingStates.set(state, now + STATE_TTL_MS);
  return state;
}

/** Is this a live state we minted? Does not consume it. */
export function peekAuthState(state: string, now: number = Date.now()): boolean {
  const expiresAt = pendingStates.get(state);
  return expiresAt !== undefined && expiresAt > now;
}

/** Consume a state. True only for a live, previously minted state. */
export function consumeAuthState(state: string, now: number = Date.now()): boolean {
  const expiresAt = pendingStates.get(state);
  if (expiresAt === undefined) return false;
  pendingStates.delete(state);
  return expiresAt > now;
}

/** Test seam: forget every pending state. */
export function clearAuthStates(): void {
  pendingStates.clear();
}

export interface AuthInput {
  code: string;
  state?: string;
}

/**
 * Accept either a bare authorization code or the full URL Google redirected
 * to. The redirect URL is what a human actually has in the address bar, and
 * it carries both `code` and `state`.
 */
export function parseAuthInput(input: string): AuthInput {
  const trimmed = input.trim();
  if (!/^https?:\/\//i.test(trimmed)) return { code: trimmed };
  try {
    const url = new URL(trimmed);
    return {
      code: url.searchParams.get("code") ?? "",
      state: url.searchParams.get("state") ?? undefined,
    };
  } catch {
    return { code: trimmed };
  }
}

// ── Account binding ─────────────────────────────────────────────────────────
//
// `state` proves the code came from *our* authorization start. It does not
// prove a human pasted it — an agent told to "re-authorize" can legitimately
// run start→complete with an account of its choosing. So after the exchange we
// resolve which account was actually authorized and refuse to overwrite a
// token that belongs to somebody else.

export interface AccountGuard {
  recorded?: string;
  actual: string;
  expected?: string;
  allowChange?: boolean;
}

export function assertAccountAllowed(guard: AccountGuard): void {
  const actual = guard.actual.trim().toLowerCase();

  if (guard.expected && guard.expected.trim().toLowerCase() !== actual) {
    throw new Error(
      `Authorized account (${guard.actual}) does not match the configured ` +
        `expectedAccount (${guard.expected}). Refusing to store the token. ` +
        `Update expectedAccount in the plugin config if you meant to switch.`
    );
  }

  if (!guard.recorded || guard.allowChange) return;

  if (guard.recorded.trim().toLowerCase() !== actual) {
    throw new Error(
      `Authorized account (${guard.actual}) differs from the account this ` +
        `plugin previously authorized (${guard.recorded}). Refusing to ` +
        `overwrite the token. Set allowAccountChange=true in the plugin ` +
        `config only if you intend to switch accounts.`
    );
  }
}

/**
 * Which Google account does this client act as? Drive `about.get` returns
 * `user.emailAddress` and needs only the Drive scope we already request, so
 * this adds no new consent step and forces no re-authorization.
 */
async function resolveAuthorizedAccount(client: OAuth2Client): Promise<string> {
  const drive = google.drive({ version: "v3", auth: client });
  const res = await drive.about.get({ fields: "user" });
  const email = res.data.user?.emailAddress;
  if (!email) {
    throw new Error(
      "Could not determine which Google account was authorized " +
        "(drive.about returned no user.emailAddress)."
    );
  }
  return email;
}

export function metaPathFor(tokenPath: string): string {
  return `${tokenPath}.meta.json`;
}

async function readRecordedAccount(
  tokenPath: string
): Promise<string | undefined> {
  try {
    const raw = await readFile(metaPathFor(tokenPath), "utf8");
    const parsed = JSON.parse(raw) as { account?: string };
    return parsed.account;
  } catch (err: unknown) {
    // No metadata yet (first authorization) is fine; a corrupt file is not —
    // treating it as absent would silently disable the account guard.
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new Error(
      `Token metadata at ${metaPathFor(tokenPath)} is unreadable. ` +
        `Delete it and re-run the OAuth flow. (${(err as Error).message})`
    );
  }
}

export interface ExchangeResult {
  tokenPath: string;
  scopes: string[];
  account: string;
}

export async function buildAuthUrl(
  config: AuthConfig
): Promise<{ authUrl: string; state: string }> {
  const client = await createOAuthClient(config);
  const state = createAuthState();
  const authUrl = client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state,
  });
  return { authUrl, state };
}

export async function exchangeCode(
  config: AuthConfig,
  input: string,
  explicitState?: string
): Promise<ExchangeResult> {
  const parsed = parseAuthInput(input);
  const state = explicitState ?? parsed.state;

  if (!state) {
    throw new Error(
      "Missing OAuth state. Call google_auth_start again and paste the FULL " +
        "redirected URL (it carries both code and state) instead of only the code."
    );
  }
  if (!consumeAuthState(state)) {
    throw new Error(
      "OAuth state is unknown, expired (10 minute limit), or already used. " +
        "Call google_auth_start again and retry with the new redirect URL."
    );
  }
  if (!parsed.code) {
    throw new Error(
      "No authorization code found in the supplied value. Paste the full " +
        "redirected URL, or the bare code together with its state."
    );
  }

  const client = await createOAuthClient(config);
  const { tokens } = await client.getToken(parsed.code);
  if (!tokens.refresh_token) {
    throw new Error(
      "No refresh_token returned. Revoke prior consent at " +
        "https://myaccount.google.com/permissions then retry with prompt=consent."
    );
  }
  client.setCredentials(tokens);

  const tokenPath = expandHome(config.tokenPath);
  const account = await resolveAuthorizedAccount(client);
  assertAccountAllowed({
    recorded: await readRecordedAccount(tokenPath),
    actual: account,
    expected: config.expectedAccount,
    allowChange: config.allowAccountChange,
  });

  const scopes = (tokens.scope ?? "").split(" ").filter(Boolean);
  await mkdir(dirname(tokenPath), { recursive: true, mode: 0o700 });
  await writeFile(tokenPath, JSON.stringify(tokens, null, 2), { mode: 0o600 });
  // `mode` above only applies when the file is *created*. If a token file
  // already exists from an earlier version (or was copied in) with looser
  // permissions, the write above would leave it world-readable. Tighten it
  // explicitly on every write.
  await chmod(tokenPath, 0o600);

  const metaPath = metaPathFor(tokenPath);
  await writeFile(
    metaPath,
    JSON.stringify({ account, authorizedAt: new Date().toISOString(), scopes }, null, 2),
    { mode: 0o600 }
  );
  await chmod(metaPath, 0o600);

  return { tokenPath, scopes, account };
}

export async function withTimeout<T>(
  promise: Promise<T>,
  label: string,
  ms = 30000
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)),
      ms
    );
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
