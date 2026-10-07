import { CAPS } from "./types.mjs";
import { fail, jsonText, safeURL } from "./security.mjs";
async function remoteRequest(transport, raw, init) {
  let u = safeURL(raw);
  if (!transport?.dnsPinned) fail("secure_remote_transport_unavailable");
  for (let i = 0; i <= CAPS.redirects; i++) {
    const response = await transport.request(u.href, init);
    if (response.status < 300 || response.status > 399) return response;
    const location = response.headers.get("location");
    if (!location) fail("invalid_redirect");
    const next = safeURL(new URL(location, u).href);
    if (next.origin !== u.origin) fail("cross_origin_redirect");
    u = next;
  }
  return fail("redirect_limit");
}
function responseJSON(response) {
  if (response.status !== 200) fail(response.status === 401 || response.status === 403 ? "authentication_required" : "upstream_http_failure");
  const content = response.headers.get("content-type") ?? "";
  if (content.includes("application/json")) return jsonText(response.text);
  if (content.includes("text/event-stream")) {
    const events = response.text.replaceAll("\r\n", "\n").split("\n\n");
    for (const event of events) {
      const data = event.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
      if (!data) continue;
      const value = jsonText(data);
      if (value && typeof value === "object" && "id" in value) return value;
    }
  }
  return fail("unsupported_mcp_response");
}
export {
  remoteRequest,
  responseJSON
};
