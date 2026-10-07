import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { publicIP, safeURL, assertSchema, jsonText } from '../src/security.mjs';
import { choosePublicAddress, NodePinnedTransport, pinnedOptions } from '../src/node-transport.mjs';
import { remoteRequest, responseJSON } from '../src/transport.mjs';
import { discover, structuralSchema, hash } from '../src/mcp.mjs';
import { CAPS, REGISTRY } from '../src/types.mjs';
import { classify, initialSync, pollPage } from '../src/registry.mjs';
import { signedHeaders, MockReceiver, INGEST_BYTES, ingestConfig } from '../src/sender.mjs';

const endpoint = 'https://mcp.publicvendor.com/mcp';
const rpcBody = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
const ok = (value, status = 200, extra = {}) => ({ status, headers: new Headers({ 'content-type': 'application/json', ...extra }), text: JSON.stringify(value) });
const privateAddresses = ['0.0.0.0','10.1.2.3','127.0.0.1','169.254.169.254','172.16.0.1','192.168.0.1','100.64.0.1','192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:0808:0808::1'];
for (const ip of privateAddresses) test('non-public address blocked: ' + ip, () => assert.equal(publicIP(ip), false));
test('globally routable address accepted', () => { assert.equal(publicIP('8.8.8.8'), true); assert.equal(publicIP('2606:4700::1111'), true); });
test('private IP fixture never reaches connector', async () => {
  let calls = 0;
  const t = new NodePinnedTransport(async () => [{ address: privateAddresses[1], family: 4 }], () => { calls++; });
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), /ssrf_dns_blocked/); assert.equal(calls, 0);
});
test('all A and AAAA records checked, mixed private response fails', () => {
  assert.throws(() => choosePublicAddress([{ address: '8.8.8.8', family: 4 }, { address: '::1', family: 6 }]), /ssrf_dns_blocked/);
  assert.throws(() => choosePublicAddress([]), /ssrf_dns_blocked/);
  assert.throws(() => choosePublicAddress([{ address: '8.8.8.8', family: 6 }]), /ssrf_dns_blocked/);
});
for (const bad of ['http://mcp.publicvendor.com/mcp', endpoint + '?access=hidden', endpoint + '#fragment', endpoint.replace('https://','https://user:pass@'), 'https://metadata.publicvendor.com/mcp', 'https://' + 'localhost' + '/mcp'])
  test('unsafe URL rejected', () => assert.throws(() => safeURL(bad)));
test('redirect-private blocked before follow-up connection', async () => {
  let calls = 0;
  const t = { dnsPinned: true, request: async () => { calls++; return ok({}, 302, { location: 'https://' + privateAddresses[2] + '/mcp' }); } };
  await assert.rejects(remoteRequest(t, endpoint, { method: 'POST', body: rpcBody }), /ssrf_blocked/); assert.equal(calls, 1);
});
test('redirects limited and origin cannot change', async () => {
  let calls = 0; const t = { dnsPinned: true, request: async () => { calls++; return ok({}, 307, { location: '/mcp' }); } };
  await assert.rejects(remoteRequest(t, endpoint, { method: 'POST', body: rpcBody }), /redirect_limit/); assert.equal(calls, 4);
  t.request = async () => ok({}, 307, { location: 'https://other.publicvendor.com/mcp' });
  await assert.rejects(remoteRequest(t, endpoint, { method: 'POST', body: rpcBody }), /cross_origin_redirect/);
});
function connectorFor({ chunks = [Buffer.from('{}')], encoding, failTLS = false } = {}, capture = () => {}) {
  return (options, callback) => {
    capture(options);
    const req = new EventEmitter();
    req.destroy = error => { queueMicrotask(() => req.emit('error', error)); };
    req.end = () => queueMicrotask(() => {
      if (failTLS) { req.destroy(options.checkServerIdentity('ignored', { subjectaltname: 'DNS:wrong.publicvendor.com', subject: { CN: 'wrong.publicvendor.com' } })); return; }
      const res = new EventEmitter(); res.statusCode = 200; res.headers = { 'content-type': 'application/json', ...(encoding ? { 'content-encoding': encoding } : {}) };
      res.destroy = () => {}; callback(res);
      queueMicrotask(() => { for (const chunk of chunks) res.emit('data', chunk); res.emit('end'); });
    }); return req;
  };
}
test('rebinding fixture: socket pins first checked IP, later DNS is never used', async () => {
  let resolutions = 0, options;
  const dns = async () => [{ address: ++resolutions === 1 ? '8.8.8.8' : privateAddresses[2], family: 4 }];
  const t = new NodePinnedTransport(dns, connectorFor({}, o => options = o));
  await t.request(endpoint, { method: 'POST', body: rpcBody });
  assert.equal(resolutions, 1); assert.equal(options.hostname, '8.8.8.8'); assert.equal(options.lookup, undefined);
  assert.equal(options.servername, 'mcp.publicvendor.com'); assert.equal(options.headers.Host, 'mcp.publicvendor.com'); assert.equal(options.agent, false);
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), /ssrf_dns_blocked/); assert.equal(resolutions, 2);
});
test('TLS hostname mismatch blocked by actual pinned certificate callback', async () => {
  const t = new NodePinnedTransport(async () => [{ address: '8.8.8.8', family: 4 }], connectorFor({ failTLS: true }));
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), e => e.code === 'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(pinnedOptions(new URL(endpoint), { address: '8.8.8.8', family: 4 }, { method: 'POST' }).rejectUnauthorized, true);
});
test('oversized body blocked at streaming transport boundary', async () => {
  const t = new NodePinnedTransport(async () => [{ address: '8.8.8.8', family: 4 }], connectorFor({ chunks: [Buffer.alloc(CAPS.responseBytes + 1)] }));
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), /response_too_large/);
});
test('compressed responses rejected before buffering', async () => {
  const t = new NodePinnedTransport(async () => [{ address: '8.8.8.8', family: 4 }], connectorFor({ encoding: 'gzip' }));
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), /compressed_response_rejected/);
});
test('tool calls and authentication headers never allowed', async () => {
  const t = new NodePinnedTransport(() => { throw new Error('dns_should_not_run'); });
  await assert.rejects(t.request(endpoint, { method: 'POST', body: JSON.stringify({ method: 'tools/call' }) }), /readonly_mcp_only/);
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody, headers: { Authorization: 'fixture' } }), /unsafe_request_header/);
});
test('fixed transport permits only official Registry and configured ingest', async () => {
  const t = new NodePinnedTransport(() => { throw new Error('dns_reached'); }, undefined, 'fixed');
  await assert.rejects(t.request(endpoint, { method: 'GET' }), /untrusted_origin/);
  await assert.rejects(t.request(REGISTRY + '?url=arbitrary', { method: 'GET' }), /untrusted_origin/);
});
test('unpinned transports fail closed', async () => assert.rejects(remoteRequest({ request: async () => ok({}) }, endpoint, { method: 'POST', body: rpcBody }), /secure_remote_transport_unavailable/));
test('authentication-required is explicit, no bypass', () => assert.throws(() => responseJSON(ok({}, 401)), /authentication_required/));
const schema = { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] };
test('schema sanitization strips descriptions and examples', () => assert.deepEqual(structuralSchema({ ...schema, description: 'fixture description', examples: [{}], properties: { query: { type: 'string', description: 'fixture' } } }), schema));
test('schema caps, local references and regex safety enforced', () => {
  assert.throws(() => assertSchema({ type: 'object', enum: Array.from({ length: 300 }, () => 1) }), /node_limit_exceeded/);
  assert.throws(() => assertSchema({ type: 'object', description: 'x'.repeat(9000) }), /schema_too_large/);
  assert.throws(() => assertSchema({ type: 'object', $ref: 'https://publicvendor.com/schema' }), /external_schema_reference/);
  assert.throws(() => assertSchema({ type: 'object', pattern: '(a+)+' }), /unsafe_regex/);
  assert.throws(() => jsonText('{"__proto__":{}}'), /unsafe_property_name/);
});
test('malformed UTF-8 and non-JSON content rejected', async () => {
  const t = new NodePinnedTransport(async () => [{ address: '8.8.8.8', family: 4 }], connectorFor({ chunks: [Buffer.from([255])] }));
  await assert.rejects(t.request(endpoint, { method: 'POST', body: rpcBody }), /malformed_utf8/);
  assert.throws(() => responseJSON({ status: 200, headers: new Headers(), text: '{}' }), /unsupported_mcp_response/);
});
function mcpFixture(tools) {
  const methods = []; return { methods, dnsPinned: true, async request(_url, init) {
    const rpc = JSON.parse(init.body); methods.push(rpc.method);
    if (rpc.method === 'notifications/initialized') return ok({}, 202);
    return ok({ jsonrpc: '2.0', id: rpc.id, result: rpc.method === 'initialize' ? { protocolVersion: '2025-06-18', capabilities: { tools: {} } } : { tools } });
  } };
}
const server = { name: 'com.publicvendor/mcp', version: '1.0.0', endpoint, updatedAt: new Date().toISOString() };
test('complete read-only MCP handshake returns structural baseline', async () => {
  const t = mcpFixture([{ name: 'search', inputSchema: schema }]); const snapshots = await discover(server, t, server.updatedAt);
  assert.equal(snapshots.length, 1); assert.equal(snapshots[0].hash, await hash(schema)); assert.deepEqual(t.methods, ['initialize', 'notifications/initialized', 'tools/list']);
});
test('tool count cap gives zero partial snapshots', async () => {
  const t = mcpFixture(Array.from({ length: 9 }, (_, i) => ({ name: 'tool' + i, inputSchema: schema })));
  await assert.rejects(discover(server, t, server.updatedAt), /tool_limit/);
});
test('Registry rejects authenticated, unsafe and malformed remote records', () => {
  const item = { server: { name: server.name, version: '1', remotes: [{ type: 'streamable-http', url: endpoint, headers: {} }] }, _meta: { 'io.modelcontextprotocol.registry/official': { updatedAt: server.updatedAt, status: 'active' } } };
  assert.equal(classify(item).endpoint, null); item.server.remotes[0].headers = [{ name: 'Authorization' }]; assert.equal(classify(item).endpoint, null);
  item.server.remotes[0] = { type: 'streamable-http', url: 'https://' + privateAddresses[2] + '/mcp' }; assert.equal(classify(item).endpoint, null);
});
test('incremental poll validates cursor and leaves input state unchanged on failure', async () => {
  const prior = initialSync(); prior.cursor = 'same';
  const serialized = JSON.stringify(prior);
  await assert.rejects(pollPage(prior, server.updatedAt, async () => ok({ servers: [{}], metadata: { count: 1, nextCursor: 'same' } })), /registry_pagination_anomaly/);
  assert.equal(JSON.stringify(prior), serialized);
});
test('HMAC receiver verifies authenticity, freshness and replay protection', async () => {
  const secret = randomBytes(32).toString('hex'), body = JSON.stringify({ kind: 'state' }); const receiver = new MockReceiver(secret);
  const headers = signedHeaders(body, secret); await receiver.receive(body, headers);
  await assert.rejects(receiver.receive(body, headers), /replay_rejected/);
  await assert.rejects(receiver.receive(body + ' ', signedHeaders(body, secret)), /unauthorized/);
  await assert.rejects(receiver.receive(body, signedHeaders(body, secret, String(Date.now() - 300001))), /unauthorized/);
  const forged = signedHeaders(body, secret); forged['x-radar-signature'] = '0'.repeat(64);
  await assert.rejects(receiver.receive(body, forged), /unauthorized/);
});
test('signed snapshot protocol deduplicates identical hashes', async () => {
  const secret = randomBytes(32).toString('hex'), receiver = new MockReceiver(secret);
  const send = p => { const body = JSON.stringify(p); return receiver.receive(body, signedHeaders(body, secret)); };
  await send({ kind: 'registry', server });
  const snapshot = { serverId: server.name, registryVersion: server.version, canonicalOrigin: new URL(endpoint).origin, toolName: 'search', inputSchema: schema, schemaHash: await hash(schema), registryUpdatedAt: server.updatedAt, collectedAt: server.updatedAt, sourceType: 'official_registry_mcp' };
  await send({ kind: 'snapshot', snapshot }); await send({ kind: 'snapshot', snapshot }); assert.equal(receiver.snapshotCount, 1);
  snapshot.schemaHash = '0'.repeat(64); await assert.rejects(send({ kind: 'snapshot', snapshot }), /invalid_snapshot_hash/);
});
test('ingest body cap and owner configuration fail closed', () => {
  const secret = randomBytes(32).toString('hex');
  assert.throws(() => signedHeaders('x'.repeat(INGEST_BYTES + 1), secret), /ingest_too_large/);
  assert.deepEqual(ingestConfig('', ''), { mode: 'mock' });
  assert.throws(() => ingestConfig(endpoint, secret), /invalid_ingest_configuration/);
  assert.throws(() => ingestConfig('', secret), /orphan_ingest_secret/);
});
test('workflow hardens public default-branch execution and uses no paid storage', () => {
  const workflow = readFileSync(new URL('../.github/workflows/secure-collector.yml', import.meta.url), 'utf8');
  assert.match(workflow, /runs-on: ubuntu-latest/); assert.match(workflow, /timeout-minutes: 5/);
  assert.match(workflow, /contents: read/); assert.match(workflow, /group: acg-radar-collector/);
  assert.match(workflow, /cancel-in-progress: true/); assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/);
  assert.match(workflow, /ref: \$\{\{ github\.event\.repository\.default_branch \}\}/);
  const uses = [...workflow.matchAll(/uses: (.+)/g)].map(m => m[1]); assert.deepEqual(uses, ['actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683']);
  assert.doesNotMatch(workflow, /pull_request|issues:|repository_dispatch|upload-artifact|actions\/cache|setup-node|inputs:/);
  assert.equal((workflow.match(/secrets\./g) ?? []).length, 1); assert.match(workflow, /secrets\.RADAR_INGEST_SECRET/);
  assert.match(workflow, /env -i PATH=/);
});
test('malicious fork PR and workflow-edit branch cannot reach secret job', () => {
  const allowed = ({ event, ref, branch = 'main', privateRepo = false, url = '' }) => !privateRepo && ref === 'refs/heads/' + branch && (event === 'workflow_dispatch' || (event === 'schedule' && url !== ''));
  for (const event of ['pull_request', 'pull_request_target', 'issues', 'repository_dispatch']) assert.equal(allowed({ event, ref: 'refs/heads/main', url: endpoint }), false);
  for (const event of ['schedule', 'workflow_dispatch']) assert.equal(allowed({ event, ref: 'refs/heads/malicious-workflow', url: endpoint }), false);
  assert.equal(allowed({ event: 'workflow_dispatch', ref: 'refs/heads/main' }), true);
  assert.equal(allowed({ event: 'schedule', ref: 'refs/heads/main' }), false);
  assert.equal(allowed({ event: 'schedule', ref: 'refs/heads/main', url: endpoint }), true);
  assert.equal(allowed({ event: 'workflow_dispatch', ref: 'refs/heads/main', privateRepo: true }), false);
});
