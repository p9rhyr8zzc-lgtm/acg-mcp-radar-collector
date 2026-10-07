import { request } from "node:https";
import { Resolver } from "node:dns/promises";
import { isIP } from "node:net";
import { checkServerIdentity } from "node:tls";
import { CAPS, REGISTRY } from "./types.mjs";
import { fail, publicIP, safeURL } from "./security.mjs";
function publicAddresses(addresses) {
  if (!addresses.length || addresses.some((a) => !publicIP(a.address) || isIP(a.address) !== a.family)) fail("ssrf_dns_blocked");
  return [...addresses.filter((a) => a.family === 4), ...addresses.filter((a) => a.family === 6)];
}
function choosePublicAddress(addresses, index = 0) {
  const safe = publicAddresses(addresses);
  return safe[index % safe.length];
}
async function resolveAll(host) {
  if (isIP(host)) return [{ address: host, family: isIP(host) }];
  const resolver = new Resolver({ timeout: 1500, tries: 1 });
  const timer = setTimeout(() => resolver.cancel(), 2e3);
  try {
    const answers = await Promise.all([resolver.resolve4(host), resolver.resolve6(host)].map(async (query, i) => {
      try {
        return (await query).map((address) => ({ address, family: i === 0 ? 4 : 6 }));
      } catch (e) {
        if (e.code === "ENODATA") return [];
        throw new Error("dns_resolution_failed");
      }
    }));
    return answers.flat();
  } finally {
    clearTimeout(timer);
  }
}
function pinnedOptions(u, chosen, init) {
  const host = u.hostname.replace(/^\[|\]$/g, "");
  return {
    hostname: chosen.address,
    port: 443,
    family: chosen.family,
    path: u.pathname + u.search,
    method: init.method,
    agent: false,
    servername: isIP(host) ? void 0 : host,
    rejectUnauthorized: true,
    checkServerIdentity: (_ignored, cert) => checkServerIdentity(host, cert),
    maxHeaderSize: 16384,
    headers: { ...init.headers, Host: u.host, "accept-encoding": "identity", connection: "close" }
  };
}
class NodePinnedTransport {
  constructor(resolver = resolveAll, connector = request, mode = "mcp", ingestURL = void 0, diagnostic = () => {}, timers = {}) {
    this.resolver = resolver;
    this.connector = connector;
    this.mode = mode;
    this.ingestURL = ingestURL;
    this.diagnostic = diagnostic;
    this.timers = { connectMs: 2000, tlsMs: 2000, responseMs: CAPS.timeoutMs, ...timers };
    this.addressCursor = new Map();
  }
  dnsPinned = true;
  async request(raw, init) {
    let u;
    if (this.mode === "fixed") {
      u = new URL(raw);
      const withoutQuery = new URL(u);
      withoutQuery.search = "";
      safeURL(withoutQuery.href);
      if (raw.length > 4096) fail("unsafe_url");
      if ((u.origin + u.pathname === REGISTRY ||
          (u.origin === new URL(REGISTRY).origin && /^\/v0\.1\/servers\/[A-Za-z0-9_.+%-]+\/versions\/latest$/.test(u.pathname) && !u.search)) && init.method === "GET") {
        for (const [key, value] of u.searchParams) if (!["updated_since", "cursor", "limit", "version", "search"].includes(key) || value.length > 1024) fail("untrusted_origin");
        if (Object.keys(init.headers ?? {}).some((k) => k.toLowerCase() !== "accept")) fail("unsafe_request_header");
      } else if (this.ingestURL && u.href === this.ingestURL && init.method === "POST" && !u.search) {
        for (const key of Object.keys(init.headers ?? {})) if (!["content-type", "x-radar-timestamp", "x-radar-nonce", "x-radar-body-hash", "x-radar-signature"].includes(key.toLowerCase())) fail("unsafe_request_header");
      } else fail("untrusted_origin");
    } else {
      u = safeURL(raw);
      if (init.method !== "POST" || !init.body) fail("readonly_mcp_only");
      const rpc = JSON.parse(init.body);
      if (!["initialize", "notifications/initialized", "tools/list"].includes(rpc.method ?? "")) fail("readonly_mcp_only");
      for (const key of Object.keys(init.headers ?? {})) if (!["content-type", "accept", "mcp-protocol-version", "mcp-session-id"].includes(key.toLowerCase())) fail("unsafe_request_header");
    }
    const hostname = u.hostname.replace(/^\[|\]$/g, "");
    const addresses = publicAddresses(await this.resolver(hostname));
    const cursor = this.addressCursor.get(hostname) ?? 0;
    const index = cursor % addresses.length;
    const chosen = addresses[index];
    this.addressCursor.set(hostname, cursor + 1);
    const category = this.ingestURL && u.href === this.ingestURL ? "radar_ingest" : u.origin === new URL(REGISTRY).origin ? "registry" : "mcp";
    this.diagnostic({ event: "address_selected", category, family: chosen.family, index, count: addresses.length });
    return await new Promise((resolve, reject) => {
      let settled = false;
      let connectTimer;
      let tlsTimer;
      const overall = setTimeout(() => req.destroy(new Error("response_timeout")), this.timers.responseMs);
      const finish = (error, result) => {
        if (settled) return;
        settled = true;
        clearTimeout(overall);
        clearTimeout(connectTimer);
        clearTimeout(tlsTimer);
        if (error) reject(error);
        else resolve(result);
      };
      const req = this.connector(pinnedOptions(u, chosen, init), (res) => {
        if (res.headers["content-encoding"] && res.headers["content-encoding"] !== "identity") {
          req.destroy(new Error("compressed_response_rejected"));
          return;
        }
        let bytes = 0;
        const chunks = [];
        const headers = new Headers();
        for (const key of ["content-type", "location", "mcp-session-id"]) {
          const val = res.headers[key];
          if (typeof val === "string") headers.set(key, val);
        }
        res.on("data", (chunk) => {
          bytes += chunk.length;
          if (bytes > CAPS.responseBytes) {
            req.destroy(new Error("response_too_large"));
            return;
          }
          chunks.push(chunk);
          if (headers.get("content-type")?.includes("text/event-stream")) {
            const text = Buffer.concat(chunks).toString("utf8").replaceAll("\r\n", "\n");
            for (const event of text.split("\n\n").slice(0, -1)) {
              const payload = event.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trimStart()).join("\n");
              try {
                if (JSON.parse(payload).id === JSON.parse(init.body).id) {
                  finish(void 0, { status: res.statusCode ?? 0, headers, text: event + "\n\n" });
                  res.destroy();
                  return;
                }
              } catch {
              }
            }
          }
        });
        res.on("error", (error) => finish(error));
        res.on("end", () => {
          if (bytes > CAPS.responseBytes) {
            finish(new Error("response_too_large"));
            return;
          }
          try {
            finish(void 0, { status: res.statusCode ?? 0, headers, text: new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)) });
          } catch {
            finish(new Error("malformed_utf8"));
          }
        });
      });
      req.on("socket", (socket) => {
        connectTimer = setTimeout(() => req.destroy(new Error("connect_timeout")), this.timers.connectMs);
        socket.once("connect", () => {
          clearTimeout(connectTimer);
          tlsTimer = setTimeout(() => req.destroy(new Error("tls_timeout")), this.timers.tlsMs);
        });
        socket.once("secureConnect", () => clearTimeout(tlsTimer));
      });
      req.on("error", (error) => finish(error));
      req.end(init.body);
    });
  }
}
const fixedTransport = new NodePinnedTransport(resolveAll, request, "fixed");
async function fixedPinnedRequest(url, init) {
  const response = await fixedTransport.request(url, init);
  if (response.status >= 300 && response.status <= 399) fail("fixed_origin_redirect_rejected");
  return response;
}
function createFixedPinnedRequest(diagnostic) {
  const transport = new NodePinnedTransport(resolveAll, request, "fixed", undefined, diagnostic);
  return async (url, init) => {
    const response = await transport.request(url, init);
    if (response.status >= 300 && response.status <= 399) fail("fixed_origin_redirect_rejected");
    return response;
  };
}
export {
  NodePinnedTransport,
  createFixedPinnedRequest,
  choosePublicAddress,
  fixedPinnedRequest,
  pinnedOptions,
  resolveAll
};
