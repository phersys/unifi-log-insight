# UniFi Log Viewer — Requirements Handoff Document

---

## Background & Context

**User:** Jamil Masarweh — Salesforce Technical Architect, runs two startups (Previzia/Intellecta), extensive home infrastructure with Ubiquiti/UniFi networking.

**Problem:** Needs centralized log viewing for UniFi Dream Router (UDR) with IP enrichment. Tried Wazuh SIEM but it proved overly complex for the use case (enterprise security tool, not a log viewer). Existing solutions like Dozzle are just glorified log tails with no parsing or enrichment.

**Decision:** Build a custom Python-based solution in Docker that receives syslog from UDR, parses it, enriches IPs with external data, stores in PostgreSQL, and displays in a clean web UI.

---

## Network Environment

- **UDR IP:** 10.10.10.1
- **Docker Host:** 10.10.10.229 (Windows with Docker Desktop)
- **Internal Network:** 10.10.10.0/24
- **IoT Network:** 10.10.20.0/24
- **Syslog:** UDP 514 (already configured on UDR pointing to 10.10.10.229)

---

## Functional Requirements

### Log Ingestion
- Receive syslog over UDP 514 from UDR
- Handle all log types: firewall rules, DHCP, DNS, WiFi client events, IDS/IPS alerts
- Parse UniFi's non-standard syslog format (raw iptables/netfilter output, dnsmasq, hostapd, etc.)

### Log Types to Parse

| Type | Source Program | Example Pattern |
|------|----------------|-----------------|
| Firewall | kernel (iptables) | `SRC=x.x.x.x DST=x.x.x.x PROTO=TCP SPT=xxx DPT=xxx` |
| DHCP | dnsmasq-dhcp | `DHCPACK(br0) 10.10.10.50 aa:bb:cc:dd:ee:ff hostname` |
| DNS | dnsmasq | `query[A] example.com from 10.10.10.50` |
| WiFi | hostapd, stamgr | `STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated` |
| IDS/IPS | suricata (if enabled) | Alert format TBD |

### IP Enrichment

| Data | Provider | Notes |
|------|----------|-------|
| GeoIP (country, city, coords) | MaxMind GeoLite2 City | Free, requires account — user has one |
| ASN (name, number) | MaxMind GeoLite2 ASN | Free |
| Threat Intelligence | AbuseIPDB | Free tier: 1000 checks/day — user will sign up |
| Reverse DNS | Local DNS resolver | PTR lookup |

**Enrichment Logic:**
- Only enrich public IPs (skip RFC1918 private ranges)
- Cache enrichment results to avoid repeated API calls
- Background enrichment to not block log ingestion

### Storage

- **Database:** PostgreSQL
- **Retention:** 90 days (auto-cleanup via scheduled job or trigger)
- **Schema:** Structured fields + raw_log for full text search

### Data Model

```sql
CREATE TABLE logs (
  id BIGSERIAL PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  log_type VARCHAR(20) NOT NULL, -- firewall, dhcp, dns, wifi, ids
  src_ip INET,
  src_port INTEGER,
  dst_ip INET,
  dst_port INTEGER,
  protocol VARCHAR(10),
  rule_name VARCHAR(100),
  rule_action VARCHAR(20), -- allow, block, redirect
  interface VARCHAR(20),
  mac_address MACADDR,
  hostname VARCHAR(255),
  dns_query VARCHAR(255),
  dns_answer VARCHAR(255),
  geo_country VARCHAR(2),
  geo_city VARCHAR(100),
  geo_lat DECIMAL(9,6),
  geo_lon DECIMAL(9,6),
  asn_number INTEGER,
  asn_name VARCHAR(255),
  threat_score INTEGER, -- 0-100
  threat_categories TEXT[],
  rdns VARCHAR(255),
  raw_log TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_logs_type ON logs(log_type);
CREATE INDEX idx_logs_src_ip ON logs(src_ip);
CREATE INDEX idx_logs_dst_ip ON logs(dst_ip);
CREATE INDEX idx_logs_rule_action ON logs(rule_action);
CREATE INDEX idx_logs_threat_score ON logs(threat_score);
```

### API (FastAPI)

Endpoints:
- `GET /logs` — paginated, with filters (type, time range, IP, rule, country, threat level)
- `GET /logs/{id}` — single log detail
- `GET /stats` — dashboard summaries (top blocked IPs, top countries, threat counts)
- `GET /export` — CSV export with current filters

### UI (React + Tailwind)

**Main View:**
- Table with columns: Time, Type, Source (IP + flag), Destination, Protocol, Ports, Rule, Action, Country, ASN, Threat
- Sortable columns
- Pagination

**Filters:**
- Log type (multi-select)
- Time range (preset: 1h, 24h, 7d, custom)
- Source/Destination IP (text search)
- Rule name
- Country (dropdown)
- Threat level (none, low, medium, high)

**Visual Indicators:**
- Red row/badge: blocked traffic
- Orange row/badge: threat IP (score > 50)
- Green: allowed traffic
- Country flags next to IPs

**Features:**
- Click row to expand full raw log
- Export filtered results to CSV
- Auto-refresh toggle (5s, 30s, off)

---

## Non-Functional Requirements

- **Performance:** Handle ~100 logs/second sustained
- **Reliability:** Don't lose logs if enrichment APIs are slow/down
- **Startup:** Auto-start with Docker Compose
- **Updates:** MaxMind databases auto-update weekly

---

## Technical Stack

| Layer | Technology |
|-------|------------|
| Syslog Receiver | Python `asyncio` + `socketserver` |
| Parser | Regex (patterns from Wazuh decoder work can be reused) |
| Enrichment | `geoip2` (MaxMind), `requests` (AbuseIPDB), `socket.gethostbyaddr` (rDNS) |
| Database | PostgreSQL 16 |
| ORM/DB Access | SQLAlchemy or asyncpg |
| API | FastAPI |
| UI | React 18 + Tailwind CSS + shadcn/ui |
| Containerization | Docker Compose |

---

## Docker Compose Structure

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    container_name: unifi-logs-db
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql
    environment:
      POSTGRES_DB: unifi_logs
      POSTGRES_USER: unifi
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U unifi -d unifi_logs"]
      interval: 10s
      timeout: 5s
      retries: 5

  receiver:
    build: ./receiver
    container_name: unifi-logs-receiver
    restart: unless-stopped
    ports:
      - "514:514/udp"
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://unifi:${POSTGRES_PASSWORD}@postgres/unifi_logs
      ABUSEIPDB_API_KEY: ${ABUSEIPDB_API_KEY}
    volumes:
      - ./maxmind:/app/maxmind:ro

  api:
    build: ./api
    container_name: unifi-logs-api
    restart: unless-stopped
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://unifi:${POSTGRES_PASSWORD}@postgres/unifi_logs

  ui:
    build: ./ui
    container_name: unifi-logs-ui
    restart: unless-stopped
    ports:
      - "3000:80"
    depends_on:
      - api

volumes:
  postgres_data:
```

---

## External Dependencies (User Actions Required)

1. **AbuseIPDB API Key** — Sign up at https://www.abuseipdb.com/register (free tier)
2. **MaxMind GeoLite2** — User already has account; download City and ASN databases to `./maxmind/`

---

## Existing Work to Reuse

From the Wazuh session, these regex patterns were validated against real UDR logs:

**Firewall:**
```python
# Extract IPs
r'SRC=([0-9.]+) DST=([0-9.]+)'
# Extract protocol
r'PROTO=([A-Z]+)'
# Extract ports
r'SPT=([0-9]+) DPT=([0-9]+)'
# Extract MAC
r'MAC=([0-9a-f:]+)'
# Extract rule name and description
r'\[([^\]]+)\] DESCR="([^"]*)"'
```

**DNS (dnsmasq):**
```python
# Query
r'query\[([A-Z]+)\] ([a-zA-Z0-9.-]+) from ([0-9.]+)'
# Reply
r'reply ([a-zA-Z0-9.-]+) is ([0-9.]+)'
```

**DHCP (dnsmasq-dhcp):**
```python
# DHCPACK
r'DHCPACK\(([a-zA-Z0-9]+)\) ([0-9.]+) ([0-9a-f:]+) ([a-zA-Z0-9.-]+)'
# DHCPDISCOVER
r'DHCPDISCOVER\(([a-zA-Z0-9]+)\) ([0-9a-f:]+)'
# DHCPOFFER
r'DHCPOFFER\(([a-zA-Z0-9]+)\) ([0-9.]+) ([0-9a-f:]+)'
# DHCPREQUEST
r'DHCPREQUEST\(([a-zA-Z0-9]+)\) ([0-9.]+) ([0-9a-f:]+)'
```

**WiFi (stamgr):**
```python
r'([a-zA-Z_]+): STA ([0-9a-f:]+)'
```

---

## Sample Log Messages (from UDR)

**Firewall Allow:**
```
Feb  8 16:43:49 UDR-UK [CUSTOM1_LAN-A-10001] DESCR="Allow IoT to HomeKit & iDevices" IN=br20 OUT=br0 MAC=84:78:48:98:af:19:a0:78:17:a9:57:68:08:00 SRC=10.10.20.90 DST=10.10.10.217 LEN=32 TOS=00 PREC=0x00 TTL=63 ID=31248 PROTO=UDP SPT=3722 DPT=3722 LEN=12 MARK=1a0000
```

**Firewall DNAT:**
```
Feb  8 16:43:49 UDR-UK [PREROUTING-DNAT-1] DESCR="Redirect NTP to UDR NTP" IN=br20 OUT= MAC=84:78:48:98:af:19:44:73:d6:1e:54:4e:08:00 SRC=10.10.20.8 DST=139.162.255.65 LEN=76 TOS=10 PREC=0x00 TTL=64 ID=22973 DF PROTO=UDP SPT=53892 DPT=123 LEN=56 MARK=1a0000
```

---

## Success Criteria

1. Logs appear in UI within 5 seconds of UDR generating them
2. Public IPs show country flag, ASN name, and threat indicator
3. Can filter to "show me all blocked traffic from China in the last 24 hours"
4. 90-day retention works automatically
5. Survives Docker restart without data loss

---

## Project Name

**UniFi Log Insight** (open to change)
