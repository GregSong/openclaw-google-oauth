import { describe, it, expect } from "vitest";
import { buildApprovalRequest } from "./approval.js";

const GATED = [
  "gmail_message_send",
  "drive_permission_create",
  "gmail_message_trash",
  "drive_file_trash",
  "calendar_event_delete",
];

describe("buildApprovalRequest — which tools are gated", () => {
  it.each(GATED)("gates %s", (toolName) => {
    expect(buildApprovalRequest(toolName, {})).toBeDefined();
  });

  it.each([
    "gmail_messages_list",
    "gmail_message_get",
    "calendar_events_list",
    "calendar_event_create",
    "drive_files_list",
    "drive_file_get",
    "docs_create",
    "docs_append_text",
    "sheets_values_append",
    "slides_get",
    "google_auth_start",
    "some_other_plugins_tool",
  ])("leaves %s alone", (toolName) => {
    expect(buildApprovalRequest(toolName, {})).toBeUndefined();
  });

  it("gates gmail_message_modify only when it adds the TRASH label", () => {
    expect(
      buildApprovalRequest("gmail_message_modify", { id: "m1", addLabelIds: ["STARRED"] })
    ).toBeUndefined();
    expect(
      buildApprovalRequest("gmail_message_modify", { id: "m1", removeLabelIds: ["UNREAD"] })
    ).toBeUndefined();
    expect(
      buildApprovalRequest("gmail_message_modify", { id: "m1", addLabelIds: ["TRASH"] })
    ).toBeDefined();
  });
});

describe("buildApprovalRequest — how the dialog behaves", () => {
  it("fails closed on timeout for every gated tool", () => {
    for (const toolName of GATED) {
      expect(buildApprovalRequest(toolName, {})?.timeoutBehavior).toBe("deny");
    }
  });

  it("sets a finite timeout", () => {
    const req = buildApprovalRequest("gmail_message_send", {});
    expect(req?.timeoutMs).toBeGreaterThan(0);
    expect(req?.timeoutMs).toBeLessThanOrEqual(15 * 60 * 1000);
  });

  it("does not offer a permanent approval for send or share", () => {
    for (const toolName of ["gmail_message_send", "drive_permission_create"]) {
      expect(buildApprovalRequest(toolName, {})?.allowedDecisions).toEqual([
        "allow-once",
        "deny",
      ]);
    }
  });

  it("marks send and share as critical, trash/delete as warning", () => {
    expect(buildApprovalRequest("gmail_message_send", {})?.severity).toBe("critical");
    expect(buildApprovalRequest("drive_permission_create", {})?.severity).toBe("critical");
    expect(buildApprovalRequest("drive_file_trash", {})?.severity).toBe("warning");
    expect(buildApprovalRequest("calendar_event_delete", {})?.severity).toBe("warning");
  });
});

describe("buildApprovalRequest — what the human actually sees", () => {
  it("shows the recipient and subject of the email being sent", () => {
    const req = buildApprovalRequest("gmail_message_send", {
      to: "alice@example.com",
      subject: "Quarterly numbers",
      body: "Here is the file you asked for.",
    });
    expect(req?.description).toContain("alice@example.com");
    expect(req?.description).toContain("Quarterly numbers");
  });

  it("shows who a file is being shared with, and at what role", () => {
    const req = buildApprovalRequest("drive_permission_create", {
      fileId: "f_123",
      emailAddress: "stranger@example.invalid",
      role: "writer",
    });
    expect(req?.description).toContain("stranger@example.invalid");
    expect(req?.description).toContain("writer");
    expect(req?.description).toContain("f_123");
  });

  it("truncates a long body instead of dumping it into the dialog", () => {
    const req = buildApprovalRequest("gmail_message_send", {
      to: "a@b.com",
      subject: "s",
      body: "x".repeat(5000),
    });
    expect(req!.description.length).toBeLessThan(1200);
    expect(req!.description).toContain("…");
  });

  it("collapses newlines in the previewed fields", () => {
    const req = buildApprovalRequest("gmail_message_send", {
      to: "a@b.com",
      subject: "line one\nline two",
      body: "b",
    });
    expect(req!.description).not.toMatch(/line one\nline two/);
  });

  it("still produces a usable dialog when params are missing", () => {
    const req = buildApprovalRequest("gmail_message_send", {});
    expect(req?.title).toBeTruthy();
    expect(req?.description).toContain("(none)");
  });
});
