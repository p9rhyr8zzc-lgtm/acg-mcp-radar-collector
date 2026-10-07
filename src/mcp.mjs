import { assertSchema, cleanName, fail, safeURL } from "./security.mjs";
import { remoteRequest, responseJSON } from "./transport.mjs";
import { CAPS } from "./types.mjs";
function canonical(value) {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, v]) => JSON.stringify(k) + ":" + canonical(v)).join(",") + "}";
  return JSON.stringify(value);
}
async function hash(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(value)));
  return Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, "0")).join("");
}
const structural = /* @__PURE__ */ new Set([
  "type",
  "properties",
  "required",
  "enum",
  "const",
  "additionalProperties",
  "items",
  "prefixItems",
  "minimum",
  "maximum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  "multipleOf",
  "minLength",
  "maxLength",
  "pattern",
  "format",
  "minItems",
  "maxItems",
  "uniqueItems",
  "minProperties",
  "maxProperties",
  "patternProperties",
  "propertyNames",
  "$ref",
  "$dynamicRef",
  "$defs",
  "definitions",
  "allOf",
  "anyOf",
  "oneOf",
  "not",
  "if",
  "then",
  "else",
  "dependentRequired",
  "dependentSchemas"
]);
function structuralSchema(schema) {
  assertSchema(schema);
  const visit = (value, names = false) => {
    if (Array.isArray(value)) return value.map((v) => visit(v));
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(Object.entries(value).filter(([k]) => names || structural.has(k)).map(([k, v]) => [k, ["enum", "const", "required", "dependentRequired"].includes(k) && !names ? structuredClone(v) : visit(v, !names && ["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"].includes(k))]));
  };
  const result = visit(schema);
  assertSchema(result);
  if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|(?:sk-|ghp_|github_pat_|Bearer\s)[A-Za-z0-9_-]+|-----BEGIN/i.test(JSON.stringify(result))) fail("sensitive_schema_rejected");
  return result;
}
async function discover(server, transport, now) {
  if (!server.endpoint) fail("no_public_endpoint");
  const endpoint = safeURL(server.endpoint).href;
  let session;
  let negotiated = "2025-06-18";
  const headers = () => ({
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": negotiated,
    ...session ? { "Mcp-Session-Id": session } : {}
  });
  const rpc = async (id, method, params) => {
    const response = await remoteRequest(transport, endpoint, { method: "POST", headers: headers(), body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
    if (method === "initialize") {
      const value = response.headers.get("mcp-session-id");
      if (value) {
        if (value.length > 256 || /[^\x21-\x7e]/.test(value)) fail("invalid_session");
        session = value;
      }
    }
    const data = responseJSON(response);
    if (data?.jsonrpc !== "2.0" || data.id !== id || data.error || !data.result || typeof data.result !== "object" || Array.isArray(data.result)) fail("invalid_rpc_result");
    return data.result;
  };
  const init = await rpc(1, "initialize", { protocolVersion: negotiated, capabilities: {}, clientInfo: { name: "acg-radar-readonly", version: "1.0.0" } });
  if (!["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"].includes(String(init.protocolVersion))) fail("unsupported_mcp_version");
  negotiated = String(init.protocolVersion);
  if (!init.capabilities || typeof init.capabilities !== "object" || !("tools" in init.capabilities)) fail("no_tools_capability");
  const notified = await remoteRequest(transport, endpoint, { method: "POST", headers: headers(), body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
  if ([401, 403].includes(notified.status)) fail("authentication_required");
  if (![200, 202, 204].includes(notified.status)) fail("initialization_failed");
  const snapshots = [];
  const names = /* @__PURE__ */ new Set();
  const cursors = /* @__PURE__ */ new Set();
  let cursor;
  for (let page = 0; page < CAPS.toolPages; page++) {
    const result = await rpc(page + 2, "tools/list", cursor ? { cursor } : {});
    if (!Array.isArray(result.tools)) fail("invalid_tools");
    if (result.tools.length + snapshots.length > CAPS.tools) fail("tool_limit");
    for (const item of result.tools) {
      const name = cleanName(item?.name);
      if (names.has(name)) fail("duplicate_tool");
      names.add(name);
      const schema = structuralSchema(item.inputSchema);
      assertSchema(schema);
      snapshots.push({
        server: server.name,
        tool: name,
        version: server.version,
        endpoint,
        schema,
        hash: await hash(schema),
        fetchedAt: now,
        registryUpdatedAt: server.updatedAt,
        verified: true
      });
    }
    if (result.nextCursor === void 0 || result.nextCursor === null || result.nextCursor === "") return snapshots;
    if (typeof result.nextCursor !== "string" || result.nextCursor.length > 512 || cursors.has(result.nextCursor)) fail("tool_pagination_anomaly");
    cursors.add(result.nextCursor);
    cursor = result.nextCursor;
  }
  return fail("tool_pagination_limit");
}
export {
  canonical,
  discover,
  hash,
  structuralSchema
};
