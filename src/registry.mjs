import { CAPS, REGISTRY } from './types.mjs';
import { cleanName, fail, jsonText, safeURL } from './security.mjs';
import { fixedPinnedRequest } from './node-transport.mjs';

export const SEEDS = Object.freeze(['com.cloudflare.mcp/mcp', 'io.github.upstash/context7', 'com.microsoft/microsoft-learn-mcp', 'dev.svelte/mcp']);
export function initialSync(now = new Date().toISOString()) {
  return { since: new Date(Date.parse(now) - 30 * 86400000).toISOString(), cursor: null, windowStartedAt: null, lastSuccess: null, seenCursors: [] };
}
export function classify(item) {
  const s = item?.server;
  if (!s || typeof s !== 'object') fail('malformed_server');
  const name = cleanName(s.name, 200), version = cleanName(s.version, 80);
  const meta = item._meta?.['io.modelcontextprotocol.registry/official'];
  if (!name.includes('/') || typeof meta?.updatedAt !== 'string' || !Number.isFinite(Date.parse(meta.updatedAt)) || !['active', 'deprecated', 'deleted'].includes(meta.status)) fail('invalid_registry_metadata');
  let endpoint = null;
  if (Array.isArray(s.remotes)) for (const r of s.remotes) {
    if (r?.type !== 'streamable-http' || typeof r.url !== 'string' || (r.headers !== undefined && (!Array.isArray(r.headers) || r.headers.length))) continue;
    try { endpoint = safeURL(r.url).href; break; } catch { /* Unsafe metadata is never retained. */ }
  }
  return { name, version, updatedAt: meta.updatedAt, status: meta.status, category: endpoint ? 'A' : 'D', endpoint,
    registryUrl: `${REGISTRY}/${encodeURIComponent(name)}/versions/${encodeURIComponent(version)}` };
}
export async function readPage(params, fetcher = fixedPinnedRequest) {
  const u = new URL(REGISTRY); u.search = new URLSearchParams(params).toString();
  const result = await fetcher(u.href, { method: 'GET', headers: { accept: 'application/json' } });
  if (result.status !== 200) fail('registry_unavailable');
  const data = jsonText(result.text);
  if (!Array.isArray(data?.servers) || data.servers.length > CAPS.serversPerRun || data.metadata?.count !== data.servers.length) fail('registry_pagination_anomaly');
  return data;
}
export async function lookup(name, fetcher = fixedPinnedRequest) {
  if (!SEEDS.includes(name)) fail('unapproved_seed');
  // Official detail endpoint avoids broad search scans; "latest" is defined by the Registry API.
  const response = await fetcher(`${REGISTRY}/${encodeURIComponent(name)}/versions/latest`, { method: 'GET', headers: { accept: 'application/json' } });
  if (response.status !== 200) fail('registry_unavailable');
  const raw = jsonText(response.text);
  if (raw?.server?.name !== name) fail('registry_seed_missing');
  const server = classify(raw);
  return server;
}
export async function pollPage(previous, now, fetcher = fixedPinnedRequest) {
  if (!previous || typeof previous.since !== 'string' || !Number.isFinite(Date.parse(previous.since)) ||
      (previous.cursor !== null && (typeof previous.cursor !== 'string' || previous.cursor.length > 1024)) ||
      !Array.isArray(previous.seenCursors) || previous.seenCursors.length >= 1000 || previous.seenCursors.some(v => typeof v !== 'string' || v.length > 1024)) fail('invalid_sync_state');
  const sync = structuredClone(previous);
  sync.windowStartedAt ??= now;
  const data = await readPage({ updated_since: sync.since, version: 'latest', limit: '10', ...(sync.cursor ? { cursor: sync.cursor } : {}) }, fetcher);
  const next = data.metadata.nextCursor;
  if (next !== undefined && next !== null && next !== '' && (typeof next !== 'string' || next.length > 1024 || next === sync.cursor || sync.seenCursors.includes(next) || !data.servers.length)) fail('registry_pagination_anomaly');
  const servers = [];
  for (const raw of data.servers) { try { servers.push(classify(raw)); } catch { /* No untrusted raw data escapes. */ } }
  sync.cursor = typeof next === 'string' && next ? next : null;
  if (sync.cursor) sync.seenCursors.push(sync.cursor);
  else { sync.since = new Date(Date.parse(sync.windowStartedAt) - 1).toISOString(); sync.windowStartedAt = null; sync.lastSuccess = now; sync.seenCursors = []; }
  return { servers, sync, processed: data.servers.length };
}
