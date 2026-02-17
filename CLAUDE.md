# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Repo:** `jmasarweh/unifi-log-insight` (local clone)
**Key files:** `receiver/api.py`, `receiver/deps.py`, `receiver/db.py`, `receiver/enrichment.py`, `receiver/unifi_api.py`, `receiver/backfill.py`, `ui/src/components/FirewallRules.jsx`, `ui/src/components/SetupWizard.jsx`
**Note:** The container has a flat `/app/` structure — no `receiver/` subdirectory at runtime. All Python files sit in `/app/`.

## Build & Run

```bash
docker compose up -d --build          # Build and start
docker compose down                   # Stop
docker compose down -v                # Stop and wipe PostgreSQL data
docker logs unifi-log-insight         # View logs
docker exec unifi-log-insight /app/geoip-update.sh  # Manual MaxMind update
```

**UI development** (outside Docker):
```bash
cd ui && npm install && npm run dev   # Dev server with API proxy to localhost:8000
npm run build                         # Production build → ui/dist
```

There are no tests or linting configured. Verify changes by:
- Container logs: `docker logs unifi-log-insight -f`
- API health: `curl http://localhost:8090/api/health`
- UI at `http://localhost:8090`

## Architecture

Single Docker container running 4 supervised processes (priority order):
1. **PostgreSQL 16** — `unifi_logs` database (tuned: 128MB shared_buffers, synchronous_commit off)
2. **receiver** (`receiver/main.py`) — UDP syslog listener + enrichment + backfill + blacklist
3. **api** (`receiver/api.py`) — FastAPI REST API + static React UI on port 8000
4. **cron** — scheduled MaxMind GeoIP database updates

The Dockerfile is a multi-stage build: Node stage builds the React UI, Ubuntu stage runs everything else. Port mapping: `514/udp` (syslog), `8090→8000` (web UI).

### Modular API Architecture

`api.py` is a thin shell — it registers 6 APIRouter modules from `routes/` and serves the SPA. All shared state (database pools, enrichers, UniFi client) lives in `deps.py` as singletons initialized at import time. Route modules import what they need via `from deps import ...`.

**Route modules:**
| Module | Key Endpoints |
|---|---|
| `routes/logs.py` | `GET /api/logs`, `GET /api/logs/{id}`, `GET /api/export` |
| `routes/stats.py` | `GET /api/stats`, `GET /api/stats/{timeRange}` |
| `routes/setup.py` | `GET /api/config`, `GET /api/setup/status`, `POST /api/setup/complete`, `GET /api/setup/wan-candidates`, `GET /api/setup/network-segments` |
| `routes/unifi.py` | `GET /api/firewall/policies`, `PATCH /api/firewall/policies/{id}`, `POST /api/firewall/policies/bulk-logging`, `GET /api/unifi/clients`, `GET /api/unifi/devices`, `GET /api/unifi/status`, `GET/PUT /api/settings/unifi`, `POST /api/settings/unifi/test` |
| `routes/abuseipdb.py` | `POST /api/enrich/{ip}`, `GET /api/abuseipdb/status` |
| `routes/health.py` | `GET /api/health` |

### Log Processing Pipeline

```
UDP packet → SyslogReceiver._handle_message()
  → parsers.parse_log()       # regex extraction, IP validation, direction classification
  → enricher.enrich()         # GeoIP/ASN (local), rDNS, AbuseIPDB (blocked firewall only)
  → batch buffer (50 msgs or 2s timeout)
  → db.insert_logs_batch()    # execute_batch with row-by-row fallback
```

### UniFi Controller Integration

`UniFiAPI` class (`unifi_api.py`, ~800 lines) connects to the UniFi Controller via both Classic and Integration APIs.

**Phase 1 — Settings & Firewall:**
- Setup wizard: WAN interface discovery, network segment detection, firewall rule audit
- Firewall policy management: fetch all policies/zones, toggle `loggingEnabled` per-policy or in bulk
- Credential storage: API key encrypted with Fernet (PBKDF2 from `POSTGRES_PASSWORD`) in `system_config` table
- Config hierarchy: env vars > `system_config` DB > defaults. `get_config_source()` returns `'env'`, `'db'`, or `'default'`

**Phase 2 — Client/Device Polling:**
- Background thread polls UniFi clients + infrastructure devices at configurable interval (default 300s)
- Maintains thread-safe in-memory `_ip_to_name` and `_mac_to_name` caches
- Persists to `unifi_clients` / `unifi_devices` tables; log queries JOIN these for device name enrichment
- Feature flags in `unifi_features` dict: `client_names`, `device_discovery`, `network_config`, `firewall_management`

**WAN Physical Interface Mapping** (`_WAN_PHYSICAL_MAP`):
Maps UniFi API `wan_type` + `wan_networkgroup` to physical interfaces (e.g., `('pppoe', 'WAN') → 'ppp0'`). Resolved from gateway's `uplink_ifname` in `/stat/device`, with static map fallback.

### Three-Tier Threat Cache

AbuseIPDB lookups follow this hierarchy (see `AbuseIPDBEnricher.lookup()`):

1. **In-memory TTLCache** (24h) — thread-safe Python dict, zero I/O
2. **PostgreSQL `ip_threats` table** (4-day freshness) — survives container rebuilds
3. **AbuseIPDB API** — only on combined cache miss, writes back to both tiers

Rate limiting uses API response headers (`X-RateLimit-Remaining`) as single source of truth — no internal counters. Stats written to `/tmp/abuseipdb_stats.json` for cross-process coordination (separate supervisord programs don't share Python memory). The API process has its own `AbuseIPDBEnricher` instance for the manual enrich endpoint; it uses the stats file as the primary budget gate rather than its local enricher state.

### Enrichment Scope

The enricher (`enrichment.py:Enricher.enrich()`) applies AbuseIPDB lookups to **all blocked firewall events** with no direction filter. It picks whichever IP is public: `src_ip` preferred, then `dst_ip` fallback. This means both inbound and outbound blocked traffic get enriched.

### Backfill Daemon

`BackfillTask` (backfill.py) runs every 30 minutes with a multi-step cycle:
1. **Step 0a/0b**: Re-derive direction if WAN interfaces changed; fix logs enriched on own WAN IP (gated by `enrichment_wan_fix_pending` flag)
2. **Step 1**: Patch NULL `service_name` for historical firewall logs (IANA lookup)
3. Patch NULL `threat_score` logs from `ip_threats` cache (src_ip first, then dst_ip)
4. Patch logs with scores but missing verbose abuse detail fields
5. Re-enrich stale `ip_threats` entries missing verbose fields (two-stage: 100 most recently seen, then top 25 by score)
6. Find orphan IPs not in `ip_threats` (UNION of src_ip + dst_ip, public IPs only)
7. Look up orphans via AbuseIPDB (budget-gated)
8. Final patch pass

The backfill shares the same `AbuseIPDBEnricher` instance as live enrichment — rate limit state, memory cache, and budget are coordinated.

### Blacklist Pre-seeding

`BlacklistFetcher` pulls 10K highest-risk IPs daily into `ip_threats`. Uses `GREATEST()` to never downgrade existing richer check-API scores and preserves richer category arrays over blacklist-only `["blacklist"]` entries. Separate API quota from check lookups.

## Database

Five tables in `unifi_logs` database:

- **`logs`** — all parsed log entries with enrichment columns (including `src_device_name`, `dst_device_name`, `service_name`). 60-day retention (10-day for DNS). Cleanup runs daily at 03:00.
- **`ip_threats`** — persistent AbuseIPDB cache. Primary key: `ip` (INET). Includes verbose fields: `abuse_usage_type`, `abuse_hostnames`, `abuse_total_reports`, `abuse_last_reported`, `abuse_is_whitelisted`, `abuse_is_tor`. No retention — entries accumulate but are considered stale after 4 days.
- **`system_config`** — JSONB key-value store for dynamic settings (UniFi credentials, WAN interfaces, feature flags, wizard state). Primary key: `key` (TEXT).
- **`unifi_clients`** — UniFi client cache for device name enrichment. Primary key: `mac` (MACADDR). Indexed on `ip`, `device_name`.
- **`unifi_devices`** — UniFi infrastructure device cache (APs, gateways, switches). Primary key: `mac` (MACADDR). Indexed on `ip`.

Schema migrations run idempotently on every boot via `db.py:_ensure_schema()`. Initial schema is in `init.sql`. Table ownership is transferred to the `unifi` user in `entrypoint.sh` so that `ALTER TABLE` migrations succeed (PostgreSQL requires ownership for DDL, not just `GRANT ALL`).

### API Key Encryption

UniFi API keys stored in `system_config` are encrypted using Fernet with a key derived from `POSTGRES_PASSWORD` via PBKDF2 (100K iterations, SHA256, salt `b'unifi-log-insight-v1'`). If `POSTGRES_PASSWORD` changes after setup, stored API keys become unrecoverable — `decrypt_api_key()` returns empty string and the UI prompts re-entry.

## Key Patterns

- **INET type**: PostgreSQL INET columns can return values with `/32` suffix depending on psycopg2 behavior. Use `host()` in SQL when extracting IPs as strings for API calls.
- **Batch insert resilience**: `insert_logs_batch()` uses `execute_batch()` with row-by-row fallback — one bad row doesn't block the batch.
- **Connection pooling**: `ThreadedConnectionPool(2, 10)` with a `contextmanager` pattern (`db.get_conn()`).
- **Signal handling**: `SIGTERM/SIGINT` → graceful shutdown, `SIGUSR1` → hot-reload GeoIP databases, `SIGUSR2` → reload config from `system_config` (used by API to signal receiver after setup wizard changes).
- **WAN IP exclusion**: Automatically learned from firewall rule names containing `WAN_LOCAL` and from UniFi API gateway detection; excluded from AbuseIPDB lookups.
- **Device name enrichment**: Log queries LEFT JOIN `unifi_clients` + `unifi_devices` on src/dst IPs. Uses `COALESCE(log.device_name, client.device_name, client.hostname, client.oui, device.device_name, device.model)` chain. MAC-based joins survive DHCP changes.
- **IANA service names**: `services.py` loads `data/service-names-port-numbers.csv` at module init. Maps (port, protocol) → service name (e.g., 53/udp → "DNS"). Used during log parsing and backfilled for historical logs.
- **Syslog timestamp year inference**: Syslog messages omit the year. The parser (`parsers.py:parse_syslog_timestamp()`) uses the current year and only rolls back to the previous year when the log month is >6 months ahead of the current month (Dec log arriving in Jan). Do **not** use a simple `ts > now` check — gateway clocks are often slightly ahead of the container clock, which would mis-stamp same-day logs with the previous year.
- **SPA path traversal protection**: `serve_spa` in `api.py` resolves the requested path with `pathlib.Path.resolve()` and validates it stays within `STATIC_DIR` before serving. URL-decodes first to prevent encoded `../` bypass.
- **Manual enrich endpoint** (`POST /api/enrich/{ip}`): clears memory cache, backdates `ip_threats.looked_up_at`, calls `lookup()` to force a fresh API hit, then patches all matching log rows. The UI (`LogDetail.jsx`) merges the response into display state immediately.
- **Timezone migration**: One-time backfill on boot re-interprets historical timestamps using the container's `TZ`. Gated by `system_config.tz_backfill_done` flag and PostgreSQL advisory lock.

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | Yes | PostgreSQL password for `unifi` user; also derives encryption key for stored API keys |
| `ABUSEIPDB_API_KEY` | No | Threat scoring (1000 checks/day + 5 blacklist pulls/day) |
| `MAXMIND_ACCOUNT_ID` | No | GeoIP auto-update |
| `MAXMIND_LICENSE_KEY` | No | Paired with account ID |
| `TZ` | No | Timezone — must match gateway's local time for correct syslog timestamps (default: UTC) |
| `LOG_LEVEL` | No | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`) |
| `UNIFI_HOST` | No | UniFi Controller URL (overrides UI setting; e.g., `https://192.168.1.1`) |
| `UNIFI_API_KEY` | No | UniFi API key (overrides UI; auto-enables integration when paired with `UNIFI_HOST`) |
| `UNIFI_SITE` | No | UniFi site name for multi-site controllers (default: `default`) |
| `UNIFI_VERIFY_SSL` | No | SSL certificate verification (default: `true`; set `false` for self-signed certs) |
| `UNIFI_POLL_INTERVAL` | No | Seconds between client/device poll cycles (default: `300`) |

## File Structure

```
receiver/
├── main.py              # UDP listener, SyslogReceiver class, scheduler thread
├── parsers.py           # Regex parsing for firewall/DNS/DHCP/WiFi, direction logic
├── db.py                # PostgreSQL pool, batch insert, schema migrations, encryption
├── enrichment.py        # GeoIPEnricher, AbuseIPDBEnricher, RDNSEnricher, TTLCache
├── api.py               # FastAPI app shell — registers route modules, serves SPA
├── deps.py              # Shared singletons: db_pool, enricher_db, abuseipdb, unifi_api
├── unifi_api.py         # UniFi Controller API client (Classic + Integration APIs)
├── backfill.py          # BackfillTask daemon for NULL threat score patching
├── blacklist.py         # Daily AbuseIPDB blacklist fetcher
├── services.py          # IANA service name lookup (port/protocol → name)
├── query_helpers.py     # Shared query building for log/export endpoints
├── requirements.txt
├── data/
│   └── service-names-port-numbers.csv
└── routes/
    ├── __init__.py
    ├── health.py        # GET /api/health
    ├── logs.py          # Log queries, detail, export
    ├── stats.py         # Dashboard statistics with time bucketing
    ├── setup.py         # Setup wizard: WAN detection, network segments, config save
    ├── unifi.py         # Firewall policies, UniFi settings, clients, devices
    └── abuseipdb.py     # Manual enrich, rate limit status
ui/                      # React 18 + Vite + Tailwind frontend
├── src/main.jsx         # App entry point
├── src/App.jsx          # Root component with routing
├── src/api.js           # API client functions
├── src/utils.js         # Shared utility helpers
└── src/components/
    ├── Dashboard.jsx         # Recharts-based analytics dashboard
    ├── FilterBar.jsx         # Log filter controls
    ├── LogStream.jsx         # Live log streaming view
    ├── LogTable.jsx          # Paginated log table
    ├── LogDetail.jsx         # Log detail panel with threat data
    ├── Pagination.jsx        # Pagination controls
    ├── SetupWizard.jsx       # Multi-path onboarding wizard (UniFi API or log detection)
    ├── UniFiConnectionForm.jsx  # UniFi credential input with connection test
    ├── WizardStepWAN.jsx     # Wizard step: WAN interface configuration
    ├── WizardStepLabels.jsx  # Wizard step: network segment labels
    ├── FirewallRules.jsx     # Zone matrix, policy logging toggles, blanket policy detection
    └── SettingsOverlay.jsx   # Settings panel: UniFi connection, WAN, network segments
```

## Release & Version Management

The version flows: `VERSION` file → Dockerfile COPY → `/app/VERSION` → `deps.py:_read_version()` → `/api/health` response. The frontend fetches the latest GitHub release and compares it to the app's version. If they don't match, an "Update available" banner appears.

**CI (automated):** The `docker-publish.yml` workflow writes the git tag into `VERSION` before building, so published images always have the correct version. No manual step needed.

**Local builds:** The repo's `VERSION` file is used as-is. Update it when cutting a new release so local `docker compose build` matches too.

Currently at: **v2.1.0**

## Parser Direction Logic

`WAN_INTERFACES` is a **dynamic set** (default: `{'ppp0'}`), loaded from `system_config.wan_interfaces` on startup and via `SIGUSR2` reload. The setup wizard or UniFi API populates this with detected WAN interfaces (e.g., `{'ppp0'}`, `{'eth4', 'eth5'}`). `INTERFACE_LABELS` (also from `system_config`) provides display-friendly names. `_wan_ip` is persisted in `system_config` and auto-learned from `WAN_LOCAL` firewall rules.

Direction derived from interfaces in `parsers.py:derive_direction()`:
- `iface_in ∈ WAN_INTERFACES` and `iface_out` is LAN → `'inbound'`
- `iface_in` is LAN and `iface_out ∈ WAN_INTERFACES` → `'outbound'`
- Both LAN but different interfaces → `'inter_vlan'`
- `DNAT` or `PREROUTING` in rule name → `'nat'`
- Broadcast/multicast dst or traffic from own WAN IP → `'local'`
- No `iface_out` (to router itself) → `'inbound'` if WAN, else `'local'`

Firewall action from UniFi rule naming convention in `derive_action()`:
- `-A-` = `'allow'`, `-B-` or `-D-` = `'block'`, `-R-` = `'block'`
- `DNAT` or `PREROUTING` in name = `'redirect'`
- No convention match = `'allow'` (default for custom rules)

## Firewall Zone Matrix Algorithm

The zone matrix label (Allow All / Block All / Allow Return) displayed in `FirewallRules.jsx` is determined by the **first blanket policy** in index order (ascending). A "blanket" policy is one with NO meaningful conditions — filters may EXIST with sentinel values like `"ALL"`, `"ANY"`, port range `1-65535`, etc. The algorithm recursively checks that values aren't just sentinels. Key fields: `source.trafficFilter`, `destination.trafficFilter`, `connectionStateFilter`, `ipProtocolScope.protocolFilter`. DERIVED policies are excluded. Disabled policies (`enabled: false`) are excluded. Both USER_DEFINED and SYSTEM_DEFINED policies are considered. See `getDefaultAction()` in `FirewallRules.jsx`.
