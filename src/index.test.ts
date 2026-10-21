import { describe, it, expect } from "vitest";
import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";
import plugin from "./index.js";

const expectedTools = [
  "google_auth_start",
  "google_auth_complete",
  "gmail_messages_list",
  "gmail_message_get",
  "gmail_message_send",
  "gmail_message_modify",
  "gmail_message_trash",
  "calendar_events_list",
  "calendar_event_create",
  "calendar_event_get",
  "calendar_event_delete",
  "drive_files_list",
  "drive_file_get",
  "drive_permission_create",
  "drive_file_trash",
  "docs_create",
  "docs_get",
  "docs_append_text",
  "sheets_create",
  "sheets_get",
  "sheets_values_get",
  "sheets_values_append",
  "slides_create",
  "slides_get",
];

describe("tangleclaw-google-oauth plugin metadata", () => {
  const metadata = getToolPluginMetadata(plugin);

  it("exposes metadata via the OpenClaw SDK helper", () => {
    expect(metadata).toBeDefined();
  });

  it("declares the expected id, name, and description", () => {
    expect(metadata!.id).toBe("tangleclaw-google-oauth");
    expect(metadata!.name).toBe("TangleClaw Google OAuth");
    expect(metadata!.description).toMatch(/Google Workspace/);
    expect(metadata!.description).toMatch(/direct OAuth/i);
  });

  it("exposes every expected tool exactly once", () => {
    const names = metadata!.tools.map((t) => t.name);
    for (const expected of expectedTools) {
      expect(names).toContain(expected);
    }
    expect(new Set(names).size).toBe(names.length);
  });

  it("does not expose unexpected tools", () => {
    const names = metadata!.tools.map((t) => t.name).sort();
    expect(names).toEqual([...expectedTools].sort());
  });

  it("gives every tool a non-empty description", () => {
    for (const t of metadata!.tools) {
      expect(t.description, `tool ${t.name} missing description`).toBeTruthy();
    }
  });

  it("declares activation on startup", () => {
    expect(metadata!.activation.onStartup).toBe(true);
  });

  it("declares a configSchema with credentialsPath and tokenPath", () => {
    const props = (metadata!.configSchema as { properties?: Record<string, unknown> }).properties;
    expect(props).toHaveProperty("credentialsPath");
    expect(props).toHaveProperty("tokenPath");
  });

  it("declares the approval policy, defaulting to confirm", () => {
    const props = (metadata!.configSchema as {
      properties?: Record<string, { default?: unknown }>;
    }).properties;
    expect(props).toHaveProperty("approvalPolicy");
    expect(props!.approvalPolicy.default).toBe("confirm");
  });
});

describe("approval hook wiring", () => {
  type HookEvent = { toolName: string; params: Record<string, unknown> };
  type HookHandler = (event: HookEvent) => unknown;
  type Api = Parameters<typeof plugin.register>[0];

  function fakeApi(pluginConfig: Record<string, unknown> = {}) {
    const hooks: Array<{ name: string; handler: HookHandler }> = [];
    const tools: unknown[] = [];
    const api = {
      pluginConfig,
      registerTool: (tool: unknown) => {
        tools.push(tool);
      },
      on: (name: string, handler: HookHandler) => {
        hooks.push({ name, handler });
      },
    };
    return { api: api as unknown as Api, hooks, tools };
  }

  it("registers every tool and a before_tool_call hook", () => {
    const { api, hooks, tools } = fakeApi();
    plugin.register(api);

    expect(tools).toHaveLength(expectedTools.length);
    expect(hooks.map((h) => h.name)).toContain("before_tool_call");
  });

  it("requires approval for a send and passes reads straight through", () => {
    const { api, hooks } = fakeApi();
    plugin.register(api);
    const hook = hooks.find((h) => h.name === "before_tool_call")!.handler;

    expect(
      hook({ toolName: "gmail_message_send", params: { to: "a@b.com", subject: "s", body: "b" } })
    ).toMatchObject({ requireApproval: { severity: "critical" } });

    expect(hook({ toolName: "gmail_messages_list", params: {} })).toBeUndefined();
  });

  it("does not interrupt calls that belong to other plugins", () => {
    const { api, hooks } = fakeApi();
    plugin.register(api);
    const hook = hooks.find((h) => h.name === "before_tool_call")!.handler;

    expect(hook({ toolName: "web_search", params: {} })).toBeUndefined();
    expect(hook({ toolName: "read", params: { path: "/etc/passwd" } })).toBeUndefined();
  });

  it("can be switched off through config", () => {
    const { api, hooks } = fakeApi({ approvalPolicy: "off" });
    plugin.register(api);

    expect(hooks.filter((h) => h.name === "before_tool_call")).toHaveLength(0);
  });
});
