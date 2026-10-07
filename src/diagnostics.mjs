const STAGES = new Set([
  'state_read', 'state_read_retry', 'registry_poll', 'registry_poll_retry',
  'registry_lookup', 'registry_lookup_retry', 'ingest_registry', 'ingest_sync',
  'mcp_discovery', 'ingest_snapshot', 'ingest_attempt',
]);

const safeCode = error => /^[a-z_]+$/.test(error?.message ?? '')
  ? error.message
  : 'network_or_validation_failure';

export async function stageDiagnostic(stage, operation, log = console.error, clock = Date.now) {
  if (!STAGES.has(stage)) throw new Error('invalid_diagnostic_stage');
  const started = clock();
  log(`radar_stage_start:${stage}`);
  try {
    const result = await operation();
    log(`radar_stage_ok:${stage}:${Math.max(0, clock() - started)}ms`);
    return result;
  } catch (error) {
    log(`radar_stage_fail:${stage}:${safeCode(error)}:${Math.max(0, clock() - started)}ms`);
    throw error;
  }
}

export function transportDiagnostic(event, log = console.error) {
  if (event?.event !== 'address_selected' || !['radar_ingest', 'registry', 'mcp'].includes(event.category) ||
      ![4, 6].includes(event.family) || !Number.isInteger(event.index) || !Number.isInteger(event.count) ||
      event.index < 0 || event.count < 1 || event.index >= event.count) return;
  log(`radar_transport:address_selected:${event.category}:ipv${event.family}:${event.index + 1}/${event.count}`);
}
