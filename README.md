# Secure public MCP collector

Secure read-only collector for public MCP tool schemas. This repository contains only collection and transport code, with no application backend, billing implementation or customer data. It uses Node.js 22 or newer and has no external runtime or test dependencies.

Configured operation polls the official MCP Registry with bounded incremental pagination. Only public HTTPS streamable HTTP endpoints without credential headers are eligible. The initial mock gate uses the official single-server `versions/latest` detail endpoint to look up Cloudflare Docs, Context7, Microsoft Learn and Svelte by Registry identifier until three eligible servers are found; endpoint URLs are obtained fresh from the Registry. Records with credential headers are skipped without contacting that MCP endpoint. Context7's current Registry record advertises an authorization header, so Svelte is the fallback. See the [official Registry API](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md). Incremental cursor behavior is also tested offline.

Every A and AAAA answer must be globally routable. Connections use the validated numeric address directly, retain the original hostname for TLS SNI, certificate validation and Host, and disable connection reuse. Every redirect repeats DNS and IP validation, stays on the same origin and is limited to three hops. TLS verification remains enabled. Compressed responses are refused; responses are limited to 128 KiB with a seven-second request deadline. Schemas are limited to 8 KiB and 256 nodes, tools to eight per server and listing to two pages. JSON depth and regex restrictions also apply.

The only MCP methods allowed are `initialize`, `notifications/initialized` and `tools/list`. Tools are never executed. Session identifiers remain in memory. Descriptions, defaults and examples are removed before hashing and sending structural schemas; secret-like structural content is rejected. Logs contain counts, public Registry identifiers and fixed error codes only.

## Ingestion configuration

Configure one repository variable, `RADAR_INGEST_URL`, with the owner's HTTPS ingestion URL ending in `/internal/collector-ingest`, and one repository secret, `RADAR_INGEST_SECRET`, with a shared secret of at least 32 bytes. Do not provide other service credentials. The sender uses the unchanged `radar-ingest-v2` HMAC-SHA256 protocol: method, fixed path, timestamp, random nonce and body digest. The receiver must enforce freshness, atomic nonce replay prevention and idempotent sanitized snapshots.

With both settings absent, manual dispatch uses an in-memory mock receiver with an ephemeral random key. No key or schema is logged, persisted or uploaded as an artifact. This validates HMAC, deduplication and three live public baselines without deploying a backend. The mock is a test receiver, not a production ingestion service. Scheduled jobs wait until the ingestion URL is configured; the schedule is every six hours. An incomplete configuration fails closed.

## Workflow safety and cost

Only `schedule` and `workflow_dispatch` are enabled. The job requires a public repository and the default-branch ref, and checkout always reads the default branch. Fork PRs and workflow-change PRs do not trigger this workflow or receive its repository secret. Review proposed workflow changes before merging them into the trusted default branch.

The job uses the standard GitHub-hosted `ubuntu-latest` runner, read-only contents permission, five-minute timeout and a single cancelable concurrency group. The sole external action is GitHub's official checkout, pinned to a full commit SHA with credential persistence disabled. Tests run before secret injection. The collector receives only its two settings and hosted-runner indicators in a cleared environment.

GitHub's [Actions billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions) states that standard GitHub-hosted runners in public repositories are free. Larger runners are billed separately and are not used here. No artifact upload, cache, Codespaces or paid Marketplace action is used. Logs and job summaries do not count as artifact storage. At four runs per day and the five-minute limit, the conservative 30-day maximum is 600 standard runner minutes, costing $0 under the public-repository rule. Private repository minute allowances are irrelevant to this design. See also GitHub's [secrets reference](https://docs.github.com/en/actions/reference/security/secrets) and [workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Local verification

Run `npm test` for offline security fixtures. Run `npm run collect` with both ingestion settings absent for a live mock baseline gate. No install step is needed. The collector rejects command-line arguments and arbitrary external URL inputs. The workflow never publishes collection artifacts.

No license file is included because a project-wide redistribution license has not been established. Public visibility alone does not grant an open-source license.
