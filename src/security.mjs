import { isIP } from "node:net";
import { assertSafeJson } from "./json-guard.mjs";
import { CAPS } from "./types.mjs";
function fail(code) {
  throw new Error(code);
}
function publicIP(address) {
  const ip = address.replace(/^\[|\]$/g, "").toLowerCase();
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 192 && b === 0 || a === 192 && b === 88 && c === 99 || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100) || a === 203 && b === 0 && c === 113);
  }
  if (isIP(ip) === 6) {
    const first = parseInt(ip.split(":")[0], 16);
    const second = parseInt(ip.split(":")[1] || "0", 16);
    return first >= 8192 && first <= 16383 && first !== 8194 && first !== 16383 && !(first === 8193 && (second < 512 || second === 3512));
  }
  return false;
}
function safeURL(raw) {
  if (raw.length > 2048 || /[\u0000-\u0020\\]/.test(raw)) fail("unsafe_url");
  let u;
  try {
    u = new URL(raw);
  } catch {
    return fail("unsafe_url");
  }
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host.length > 253 || u.pathname.length > 1024 || u.protocol !== "https:" || u.username || u.password || u.hash || u.search || u.port && u.port !== "443" || /@|(?:token|secret|api[_-]?key|password)[=:/]|(?:sk-|ghp_|github_pat_)[a-zA-Z0-9_-]+/i.test(decodeURIComponent(u.pathname))) fail("unsafe_url");
  if (isIP(host)) {
    if (!publicIP(host)) fail("ssrf_blocked");
  } else if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) || /(?:^|\.)(?:localhost|local|internal|lan|home|test|invalid|example|onion)$/.test(host) || /(?:^|\.)metadata(?:\.|$)/.test(host) || host.endsWith(".arpa")) fail("ssrf_blocked");
  return u;
}
function safeRepository(raw) {
  if (typeof raw !== "string") return;
  try {
    const u = safeURL(raw);
    return u.hostname === "github.com" && /^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(u.pathname) ? u.origin + u.pathname.replace(/\/$/, "").replace(/\.git$/, "") : void 0;
  } catch {
    return;
  }
}
function assertSchema(value) {
  assertSafeJson(value, { maxNodes: CAPS.schemaNodes, schema: true });
  if (!value || typeof value !== "object" || Array.isArray(value) || value.type !== "object") fail("invalid_input_schema");
  if (new TextEncoder().encode(JSON.stringify(value)).length > CAPS.schemaBytes) fail("schema_too_large");
}
function cleanName(value, max = 120) {
  if (typeof value !== "string" || !value.length || value.length > max || !/^[a-zA-Z0-9_./:@+-]+$/.test(value) || /@/.test(value)) fail("invalid_identifier");
  return value;
}
function jsonText(text) {
  if (new TextEncoder().encode(text).length > CAPS.responseBytes) fail("response_too_large");
  const value = JSON.parse(text);
  assertSafeJson(value, { maxNodes: CAPS.jsonNodes });
  return value;
}
export {
  assertSchema,
  cleanName,
  fail,
  jsonText,
  publicIP,
  safeRepository,
  safeURL
};
