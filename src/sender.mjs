import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { request } from 'node:https';
import { NodePinnedTransport, resolveAll } from './node-transport.mjs';
import { fail, jsonText, safeURL } from './security.mjs';
import { structuralSchema, hash, canonical } from './mcp.mjs';
import { initialSync } from './registry.mjs';

export const INGEST_PATH = '/internal/collector-ingest', INGEST_BYTES = 12288;
const digest = body => createHash('sha256').update(body).digest('hex');
const message = (time, nonce, bodyHash) => ['radar-ingest-v2', 'POST', INGEST_PATH, time, nonce, bodyHash].join('\n');
export function signedHeaders(body, secret, time = String(Date.now()), nonce = randomUUID()) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) fail('ingest_secret_unavailable');
  if (Buffer.byteLength(body) > INGEST_BYTES) fail('ingest_too_large');
  const bodyHash = digest(body);
  return { 'content-type': 'application/json', 'x-radar-timestamp': time, 'x-radar-nonce': nonce, 'x-radar-body-hash': bodyHash,
    'x-radar-signature': createHmac('sha256', secret).update(message(time, nonce, bodyHash)).digest('hex') };
}
export function ingestConfig(url, secret) {
  if (!url) { if (secret) fail('orphan_ingest_secret'); return { mode: 'mock' }; }
  const u = safeURL(url);
  if (u.pathname !== INGEST_PATH || !secret || Buffer.byteLength(secret) < 32) fail('invalid_ingest_configuration');
  return { mode: 'configured', url: u.href, secret };
}
// In-memory test receiver only. No persistent storage and no application diff engine.
export class MockReceiver {
  #secret; #nonces = new Set(); #snapshots = new Map();
  constructor(secret) { this.#secret = secret; this.sync = initialSync(); this.tracked = {}; }
  get snapshotCount() { return this.#snapshots.size; }
  async receive(body, headers, now = Date.now()) {
    if (Buffer.byteLength(body) > INGEST_BYTES) fail('ingest_too_large');
    const time = headers['x-radar-timestamp'], nonce = headers['x-radar-nonce'], signature = headers['x-radar-signature'];
    if (!/^\d{13}$/.test(time ?? '') || now - Number(time) > 300000 || Number(time) - now > 30000 || !/^[a-f0-9-]{36}$/.test(nonce ?? '') || !/^[a-f0-9]{64}$/.test(signature ?? '')) fail('unauthorized');
    const expected = signedHeaders(body, this.#secret, time, nonce);
    if (headers['x-radar-body-hash'] !== expected['x-radar-body-hash'] || !timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected['x-radar-signature'], 'hex'))) fail('unauthorized');
    if (this.#nonces.has(nonce)) fail('replay_rejected');
    if (this.#nonces.size >= 512) fail('nonce_capacity');
    const p = jsonText(body); let result = { ok: true };
    if (p.kind === 'state') result = { sync: this.sync, tracked: this.tracked };
    else if (p.kind === 'registry') {
      if (Object.keys(this.tracked).length >= 500 && !this.tracked[p.server.name]) fail('tracked_server_capacity');
      this.tracked[p.server.name] = { server: p.server, lastAttempt: null };
    } else if (p.kind === 'sync') {
      if (canonical(p.previous) !== canonical(this.sync)) fail('sync_conflict'); this.sync = p.sync;
    } else if (p.kind === 'snapshot') {
      const s = p.snapshot, server = this.tracked[s.serverId]?.server;
      if (!server || server.version !== s.registryVersion || new URL(server.endpoint).origin !== s.canonicalOrigin || s.sourceType !== 'official_registry_mcp') fail('invalid_snapshot_source');
      const clean = structuralSchema(s.inputSchema);
      if (canonical(clean) !== canonical(s.inputSchema) || await hash(clean) !== s.schemaHash) fail('invalid_snapshot_hash');
      this.#snapshots.set(s.serverId + ':' + s.toolName + ':' + s.schemaHash, s);
    } else if (p.kind !== 'attempt') fail('invalid_ingest_kind');
    this.#nonces.add(nonce); return structuredClone(result);
  }
}
export function createSender(config, mockSecret) {
  const secret = config.mode === 'mock' ? mockSecret : config.secret;
  const mock = config.mode === 'mock' ? new MockReceiver(secret) : undefined;
  const transport = config.mode === 'configured' ? new NodePinnedTransport(resolveAll, request, 'fixed', config.url) : undefined;
  let uploads = 0;
  return { mock, get uploads() { return uploads; }, async send(payload) {
    if (++uploads > 80) fail('upload_limit');
    const body = JSON.stringify(payload), headers = signedHeaders(body, secret);
    if (mock) return mock.receive(body, headers);
    const response = await transport.request(config.url, { method: 'POST', body, headers });
    if (response.status !== 200) fail('ingestion_rejected');
    return jsonText(response.text);
  } };
}
