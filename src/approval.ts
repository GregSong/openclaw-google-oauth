// Host-enforced approval for the irreversible tools.
//
// The three SKILL.md "operation tiers" are doctrine: they live in the prompt
// and a prompt-injected instruction can ignore them. A before_tool_call hook
// returning `requireApproval` is different — the OpenClaw host suspends the
// call and asks the human, and nothing the model writes can answer that
// prompt. That is the only layer in this plugin that a prompt injection
// cannot satisfy on its own.
//
// Scope: send / share are irreversible (a share also emails the recipient),
// so they are critical and can only be approved once. Trash and delete are
// recoverable for ~30 days, so a session-wide "allow-always" is offered for
// those. Everything else — reads, creates, content appends — is left alone;
// gating them would train the operator to click through the dialog.

export type ApprovalSeverity = "info" | "warning" | "critical";
export type ApprovalDecision = "allow-once" | "allow-always" | "deny";

export interface ApprovalRequirement {
  title: string;
  description: string;
  severity: ApprovalSeverity;
  timeoutMs: number;
  timeoutBehavior: "allow" | "deny";
  allowedDecisions: ApprovalDecision[];
}

/** How long the human has to answer before the call is denied. */
const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

/** Keep dialog text readable; never dump a whole email body into the prompt. */
const PREVIEW_CHARS = 160;

function preview(value: unknown): string {
  if (value === undefined || value === null) return "";
  const text = String(value).replace(/\s+/g, " ").trim();
  if (text.length <= PREVIEW_CHARS) return text;
  return `${text.slice(0, PREVIEW_CHARS)}…`;
}

function field(params: Record<string, unknown>, key: string): string {
  return preview(params[key]);
}

const IRREVERSIBLE: ApprovalDecision[] = ["allow-once", "deny"];
const RECOVERABLE: ApprovalDecision[] = ["allow-once", "allow-always", "deny"];

function requirement(
  title: string,
  description: string,
  severity: ApprovalSeverity,
  allowedDecisions: ApprovalDecision[]
): ApprovalRequirement {
  return {
    title,
    description,
    severity,
    timeoutMs: APPROVAL_TIMEOUT_MS,
    // Fail closed: a missed dialog must not silently become a "yes".
    timeoutBehavior: "deny",
    allowedDecisions,
  };
}

/**
 * Approval requirement for a tool call, or undefined when the tool is not one
 * we gate. Undefined is the common case — unknown tools (including other
 * plugins') must never be held up by this policy.
 */
export function buildApprovalRequest(
  toolName: string,
  params: Record<string, unknown> = {}
): ApprovalRequirement | undefined {
  switch (toolName) {
    case "gmail_message_send":
      return requirement(
        "Send this email?",
        [
          `To: ${field(params, "to") || "(none)"}`,
          params.cc ? `Cc: ${field(params, "cc")}` : undefined,
          params.bcc ? `Bcc: ${field(params, "bcc")}` : undefined,
          `Subject: ${field(params, "subject") || "(none)"}`,
          `Body: ${field(params, "body") || "(empty)"}`,
        ]
          .filter(Boolean)
          .join("\n"),
        "critical",
        IRREVERSIBLE
      );

    case "drive_permission_create":
      return requirement(
        "Share this Drive file?",
        [
          `File: ${field(params, "fileId") || "(none)"}`,
          `With: ${field(params, "emailAddress") || "(none)"}`,
          `Role: ${field(params, "role") || "reader"}`,
          "Sharing cannot be taken back from someone who already copied the file.",
        ].join("\n"),
        "critical",
        IRREVERSIBLE
      );

    case "gmail_message_trash":
      return requirement(
        "Move this Gmail message to Trash?",
        `Message id: ${field(params, "id") || "(none)"}\nRecoverable from Trash for 30 days.`,
        "warning",
        RECOVERABLE
      );

    case "drive_file_trash":
      return requirement(
        "Move this Drive file to Trash?",
        `File: ${field(params, "fileId") || "(none)"}\nRecoverable from Trash for 30 days.`,
        "warning",
        RECOVERABLE
      );

    case "calendar_event_delete":
      return requirement(
        "Delete this calendar event?",
        `Calendar: ${field(params, "calendarId") || "primary"}\nEvent: ${field(params, "eventId") || "(none)"}\nRecoverable from Calendar Trash for ~30 days.`,
        "warning",
        RECOVERABLE
      );

    case "gmail_message_modify": {
      // Label changes are cheap to undo, except this one: adding TRASH is a
      // delete by another name.
      const add = params.addLabelIds;
      const trashes = Array.isArray(add) && add.includes("TRASH");
      if (!trashes) return undefined;
      return requirement(
        "Move this Gmail message to Trash?",
        `Message id: ${field(params, "id") || "(none)"}\nThis call adds the TRASH label.\nRecoverable from Trash for 30 days.`,
        "warning",
        RECOVERABLE
      );
    }

    default:
      return undefined;
  }
}
