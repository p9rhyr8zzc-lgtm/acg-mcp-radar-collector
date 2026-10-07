import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { SEEDS, lookup, pollPage } from './registry.mjs';
import { discover } from './mcp.mjs';
import { NodePinnedTransport } from './node-transport.mjs';
import { createSender, ingestConfig } from './sender.mjs';
import { LIVE_CAPS } from './types.mjs';

const safeError = e => /^[a-z_]+$/.test(e?.message ?? '') ? e.message : 'network_or_validation_failure';
export async function collect(config) {
  const started = Date.now();
  const deadline = setTimeout(() => { console.error('collector_run_timeout'); process.exit(1); }, 210000);
  const sender = createSender(config, config.mode === 'mock' ? randomBytes(32).toString('hex') : undefined);
  const results = []; let registryProcessed = 0, schemas = 0, attempts = 0, metadataSkipped = 0, findings = 0;
  const budget = () => { if (Date.now() - started > 180000) throw new Error('run_budget_exceeded'); };
  async function retryRead(fn) { try { return await fn(); } catch (e) { budget(); return fn(); } }
  try {
    const prior = await sender.send({ kind: 'state' });
    // Manual mock gate verifies live Registry detail reads. Configured operation polls incrementally.
    const page = config.mode === 'mock' ? { processed: 0, servers: [], sync: prior.sync } : await retryRead(() => pollPage(prior.sync, new Date().toISOString()));
    registryProcessed = Math.min(page.processed, LIVE_CAPS.registryUpdates);
    for (const server of page.servers.slice(0, LIVE_CAPS.registryUpdates).filter(s => s.category === 'A' || prior.tracked[s.name]?.server.category === 'A')) await sender.send({ kind: 'registry', server });
    await sender.send({ kind: 'sync', previous: prior.sync, sync: page.sync });
    // Only identifiers are seeded. Every endpoint is freshly obtained from the official Registry.
    const candidates = [];
    if (config.mode === 'mock' || !Object.keys(prior.tracked).length) {
      for (const name of SEEDS) {
        if (candidates.length >= LIVE_CAPS.acceptedServers) break;
        budget(); const server = await retryRead(() => lookup(name)); await sender.send({ kind: 'registry', server });
        if (config.mode === 'mock') registryProcessed++;
        if (server.status === 'active' && server.category === 'A') candidates.push(server);
        else metadataSkipped++;
      }
    } else {
      const current = new Map(Object.values(prior.tracked).map(t => [t.server.name, t.server]));
      for (const server of page.servers) current.set(server.name, server);
      const last = name => prior.tracked[name]?.lastAttempt ?? '';
      candidates.push(...[...current.values()].filter(s => s.status === 'active' && s.category === 'A').sort((a, b) => last(a.name).localeCompare(last(b.name))).slice(0, LIVE_CAPS.acceptedServers));
    }
    for (const server of candidates.slice(0, LIVE_CAPS.acceptedServers)) {
      if (findings >= LIVE_CAPS.findings || schemas >= LIVE_CAPS.snapshots) break;
      budget(); let found, error;
      for (let retry = 0; retry < 2 && attempts < LIVE_CAPS.remoteAttempts; retry++) {
        attempts++;
        try { found = await discover(server, new NodePinnedTransport(), new Date().toISOString()); break; }
        catch (e) { error = safeError(e); if (!['dns_resolution_failed', 'network_or_validation_failure', 'request_timeout', 'connect_timeout', 'tls_timeout', 'upstream_http_failure'].includes(error)) break; budget(); }
      }
      if (found?.length) {
        if (schemas + found.length > LIVE_CAPS.snapshots) { results.push({ server: server.name, result: 'DEFERRED_SNAPSHOT_CAP', schemas: 0 }); break; }
        let outcome = 'NO_CHANGE', uploaded = 0;
        for (const s of found) { const received = await sender.send({ kind: 'snapshot', snapshot: { serverId: s.server, registryVersion: s.version,
          canonicalOrigin: new URL(s.endpoint).origin, toolName: s.tool, inputSchema: s.schema, schemaHash: s.hash,
          registryUpdatedAt: s.registryUpdatedAt, collectedAt: s.fetchedAt, sourceType: 'official_registry_mcp' } });
          outcome = received.outcome ?? (received.noOp ? 'NO_CHANGE' : outcome); uploaded++; schemas++;
          if (['HIGH_CONFIDENCE_BREAKING', 'POTENTIAL_BREAKING', 'NON_BREAKING'].includes(received.outcome)) findings++;
          if (findings >= LIVE_CAPS.findings) break;
        }
        results.push({ server: server.name, result: outcome, schemas: uploaded });
      } else {
        const result = error === 'authentication_required' ? 'SKIP_AUTH_REQUIRED' : found ? 'EMPTY_TOOLS' : 'NEEDS_REVIEW';
        await sender.send({ kind: 'attempt', serverId: server.name, collectedAt: new Date().toISOString(), result });
        results.push({ server: server.name, result, reason: error ?? 'empty_tools', schemas: 0 });
      }
    }
    const successes = results.filter(r => r.schemas > 0).length;
    const summary = { mode: config.mode, registryProcessed, metadataSkipped, attempts, successes, schemas, findings, limits: LIVE_CAPS, failures: results.length - successes,
      results, uploads: sender.uploads, mockSnapshots: sender.mock?.snapshotCount ?? null, toolsExecuted: 0, elapsedMs: Date.now() - started };
    console.log(JSON.stringify(summary));
    if (config.mode === 'mock' && (successes < 3 || sender.mock.snapshotCount !== schemas)) throw new Error('baseline_gate_failed');
    return summary;
  } finally { clearTimeout(deadline); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 2) throw new Error('arguments_rejected');
    if (process.env.GITHUB_ACTIONS === 'true' && (process.env.RUNNER_ENVIRONMENT !== 'github-hosted' || process.env.RUNNER_OS !== 'Linux')) throw new Error('hosted_runner_required');
    await collect(ingestConfig(process.env.RADAR_INGEST_URL, process.env.RADAR_INGEST_SECRET));
  } catch (e) { console.error('collector_failed_closed:' + safeError(e)); process.exitCode = 1; }
}
