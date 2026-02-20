# Self-Hosted Controller Test Plan

UniFi Log Insight currently only supports Cloud Gateways (UDM, UDR, UCG Ultra) via the UniFi OS Integration API. Self-hosted controllers (the standalone "UniFi Network Application") use a completely different authentication method and API structure. This beta adds self-hosted controller support so the app can poll clients/devices and detect network topology on self-hosted setups.

The **most important goal** of this test is collecting raw API responses from your controller (Test 6). That data lets us understand the firewall rule structure on self-hosted controllers, which is needed to build firewall syslog management in a future release.

---

## Setup

### 1. Pull the beta image

```bash
docker pull ghcr.io/jmasarweh/unifi-log-insight:beta-self-host
```

### 2. Update your `docker-compose.yml`

Change the `image:` line to use the beta tag. Everything else stays the same — your existing data volume is preserved.

```yaml
# docker-compose.yml
services:
  unifi-log-insight:
    image: ghcr.io/jmasarweh/unifi-log-insight:beta-self-host
    ports:
      - "8090:8000"    # Web UI
      - "514:514/udp"  # Syslog
    volumes:
      - db_data:/var/lib/postgresql/16/main
    environment:
      POSTGRES_PASSWORD: YourSameSecurePassword123!
      TZ: America/New_York          # match your gateway timezone
      LOG_LEVEL: DEBUG               # verbose logging for diagnostics
    restart: unless-stopped

volumes:
  db_data:
```

### 3. Start the container

```bash
docker compose up -d
```

### 4. Open the UI

Open `http://<docker-host>:8090` in your browser.

---

## Test 1: Setup Wizard — Self-Hosted Connection

1. The setup wizard should appear on first load
2. On the UniFi connection step, select **"Local Gateway (Self-Hosted)"**
3. Enter:
   - **Gateway/Controller IP**: your controller address (e.g. `192.168.1.10:8443`)
   - **Username**: your controller admin username
   - **Password**: your controller password
4. Under **Advanced**, check **"Skip SSL verification"** (self-hosted typically uses self-signed certs)
5. Click **"Test & Connect"**

**Expected**: Green success message showing controller name and version.

**If it fails**: Note the exact error message. Check container logs:
```bash
docker logs unifi-log-insight 2>&1 | grep -i "unifi\|error\|auth"
```

### What to report:
- [ ] Did the connection succeed? (yes/no)
- [ ] Controller name and version shown
- [ ] Screenshot of the success/error message

---

## Test 2: Verify Wizard Skips Firewall Step

After successful connection:

1. The wizard should proceed to WAN interface configuration (step 2)
2. The "Next" button on step 3 (Network Labels) should go directly to **Finish** — NOT to a firewall rules step
3. Complete the wizard

**Expected**: No firewall rules step appears for self-hosted controllers.

### What to report:
- [ ] Was the firewall step skipped? (yes/no)
- [ ] Screenshot of the wizard flow

---

## Test 3: Settings Page — Firewall Section

1. Go to **Settings** (gear icon)
2. Look at the **Firewall Rules** section

**Expected**: An info banner saying "Firewall management requires a UniFi OS gateway (UDM, UDR, UCG Ultra)."

### What to report:
- [ ] Does the info banner appear? (yes/no)
- [ ] Screenshot

---

## Test 4: Client/Device Polling

Wait ~60 seconds after setup, then:

1. Go to **Settings** → **UniFi Connection** section
2. Check that it shows "Connected" with client/device counts

Alternatively:
```bash
curl http://<docker-host>:8090/api/unifi/clients | python3 -m json.tool | head -20
curl http://<docker-host>:8090/api/unifi/devices | python3 -m json.tool | head -20
```

**Expected**: Both endpoints return data with `total > 0`.

### What to report:
- [ ] Client count shown
- [ ] Device count shown
- [ ] Any errors in container logs related to polling

---

## Test 5: Network Configuration (WAN Detection)

```bash
curl http://<docker-host>:8090/api/setup/unifi-network-config | python3 -m json.tool
```

**Expected**: Returns WAN interfaces and network segments detected from your controller.

### What to report:
- [ ] Does the response include `wan_interfaces`? How many?
- [ ] Does the response include `networks`? How many?
- [ ] Full JSON output (paste or save to file)

---

## Test 6: API Exploration Endpoint (MOST IMPORTANT)

This endpoint probes every relevant API endpoint on your controller and returns raw responses. This data will help us build firewall syslog support for self-hosted controllers.

```bash
curl http://<docker-host>:8090/api/debug/selfhosted/explore | python3 -m json.tool > selfhosted-explore.json
```

**Save the entire output to `selfhosted-explore.json` and send it back.**

### Key things we're looking for in the output:

| Key | What we need to know |
|-----|---------------------|
| `5_firewallrule` | Classic firewall rules — do they have a `log` field? What's the structure? |
| `6_firewallgroup` | Firewall groups — what groups exist? |
| `10_integration_sites` | Should return 404 or error (confirming no integration API) |
| `12_firewallpolicy` | Does the zone-based policy endpoint exist on self-hosted? |
| `15_firewallzone` | Do firewall zones exist on self-hosted? |
| `16_setting_firewall` | Firewall settings object |

### What to report:
- [ ] Upload the full `selfhosted-explore.json` file
- [ ] Controller version (shown in `_meta.controller_version`)

---

## Test 7: Syslog Reception (if gateway sends syslog)

If your gateway is configured to send syslog to this container (UDP 514):

1. Wait a few minutes for logs to arrive
2. Check the dashboard — do firewall logs appear?
3. Do device names resolve in the log entries?

```bash
curl "http://<docker-host>:8090/api/logs?limit=5" | python3 -m json.tool
```

### What to report:
- [ ] Are logs arriving? (yes/no)
- [ ] Do `src_device_name` / `dst_device_name` fields populate?

---

## Test 8: Reconnection with Saved Credentials

1. Go to **Settings** → **UniFi Connection**
2. Click the **"Run Setup Wizard"** button (or disconnect/reconnect)
3. On the connection form, it should show "saved credentials" with a **"Change"** button
4. Click **"Test & Connect"** using the saved credentials

**Expected**: Reconnects without entering credentials again.

### What to report:
- [ ] Did saved credentials work? (yes/no)
- [ ] Any errors

---

## Test 9: Config Export (Security Check)

```bash
curl http://<docker-host>:8090/api/config/export | python3 -m json.tool
```

**Expected**: The export should contain `unifi_controller_type: "self_hosted"` but should **NOT** contain `unifi_username`, `unifi_password`, or `unifi_site_id`.

### What to report:
- [ ] Confirm no credentials in export (yes/no)
- [ ] Does `unifi_controller_type` appear?

---

## Troubleshooting

If things go wrong, grab the full container logs:

```bash
docker logs unifi-log-insight > container-logs.txt 2>&1
```

For extra verbosity, ensure `LOG_LEVEL: DEBUG` is in your docker-compose environment.

---

## Summary Checklist

| # | Test | Pass? |
|---|------|-------|
| 1 | Self-hosted connection via wizard | |
| 2 | Firewall step skipped in wizard | |
| 3 | Firewall info banner in settings | |
| 4 | Client/device polling works | |
| 5 | Network config detection | |
| 6 | **API exploration dump** (send JSON) | |
| 7 | Syslog reception + device names | |
| 8 | Saved credentials reconnection | |
| 9 | Config export excludes credentials | |
