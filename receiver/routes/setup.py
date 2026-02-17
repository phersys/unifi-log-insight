"""Setup wizard and configuration endpoints."""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException
from psycopg2.extras import RealDictCursor

from db import get_config, set_config, count_logs, encrypt_api_key, decrypt_api_key
from deps import get_conn, put_conn, enricher_db, unifi_api, signal_receiver, APP_VERSION

logger = logging.getLogger('api.setup')

router = APIRouter()


@router.get("/api/config")
def get_current_config():
    """Return current system configuration."""
    return {
        "wan_interfaces": get_config(enricher_db, "wan_interfaces", ["ppp0"]),
        "interface_labels": get_config(enricher_db, "interface_labels", {}),
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "config_version": get_config(enricher_db, "config_version", 1),
        "upgrade_v2_dismissed": get_config(enricher_db, "upgrade_v2_dismissed", False),
        "unifi_enabled": unifi_api.enabled,
    }


@router.get("/api/setup/status")
def setup_status():
    """Check if setup wizard is complete."""
    return {
        "setup_complete": get_config(enricher_db, "setup_complete", False),
        "logs_count": count_logs(enricher_db, 'firewall'),
    }


@router.get("/api/setup/wan-candidates")
def wan_candidates():
    """Return non-bridge firewall interfaces with their associated WAN IP."""
    return {
        'candidates': enricher_db.get_wan_ip_candidates(),
    }


@router.get("/api/setup/network-segments")
def network_segments(wan_interfaces: Optional[str] = None):
    """Discover ALL network interfaces with sample local IPs and suggested labels.

    wan_interfaces: comma-separated list from Step 1. Auto-labelled WAN/WAN1/WAN2.
    """
    wan_list = wan_interfaces.split(',') if wan_interfaces else []

    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get ALL interfaces with sample local IPs (no exclusions)
            cur.execute("""
                WITH interface_ips AS (
                    SELECT interface_in as iface, src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_in IS NOT NULL
                      AND (src_ip << '10.0.0.0/8'::inet
                           OR src_ip << '172.16.0.0/12'::inet
                           OR src_ip << '192.168.0.0/16'::inet
                           OR src_ip << 'fc00::/7'::inet
                           OR src_ip << 'fe80::/10'::inet)
                    UNION
                    SELECT interface_out as iface, dst_ip as src_ip
                    FROM logs
                    WHERE log_type = 'firewall'
                      AND interface_out IS NOT NULL
                      AND (dst_ip << '10.0.0.0/8'::inet
                           OR dst_ip << '172.16.0.0/12'::inet
                           OR dst_ip << '192.168.0.0/16'::inet
                           OR dst_ip << 'fc00::/7'::inet
                           OR dst_ip << 'fe80::/10'::inet)
                )
                SELECT
                    iface,
                    ARRAY_AGG(DISTINCT host(src_ip) ORDER BY host(src_ip)) as sample_ips
                FROM interface_ips
                GROUP BY iface
                ORDER BY iface
                LIMIT 30
            """)
            interfaces = cur.fetchall()
    except Exception as e:
        logger.exception("Error querying network segments")
        raise HTTPException(status_code=500, detail="Failed to query network segments") from e
    finally:
        put_conn(conn)

    # For WAN interfaces, fetch their public IP instead of a local IP
    wan_ips = enricher_db.get_wan_ips_by_interface(wan_list) if wan_list else {}

    # Generate suggested labels
    segments = []
    for row in interfaces:
        iface = row['iface']
        ips = row['sample_ips'] or []
        is_wan = iface in wan_list

        # WAN interfaces auto-labelled from Step 1
        if is_wan:
            if len(wan_list) == 1:
                suggested = 'WAN'
            else:
                suggested = f'WAN{wan_list.index(iface) + 1}'
            # Show WAN IP, not a random local IP
            display_ip = wan_ips.get(iface, '')
        elif iface == 'br0':
            suggested = 'Main LAN'
            display_ip = ips[0] if ips else ''
        elif iface.startswith('br'):
            num = iface[2:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('vlan'):
            num = iface[4:]
            suggested = f'VLAN {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        elif iface.startswith('eth'):
            num = iface[3:]
            suggested = f'Ethernet {num}' if num.isdigit() else iface
            display_ip = ips[0] if ips else ''
        else:
            suggested = ''
            display_ip = ips[0] if ips else ''

        segments.append({
            'interface': iface,
            'sample_local_ip': display_ip,
            'suggested_label': suggested,
            'is_wan': is_wan,
        })

    return {'segments': segments}


@router.post("/api/setup/complete")
def complete_setup(body: dict):
    """Save wizard configuration and trigger receiver reload."""
    if not body.get('wan_interfaces'):
        raise HTTPException(status_code=400, detail="wan_interfaces required")

    # Read current WAN config before overwriting (for backfill comparison)
    current_wan = set(get_config(enricher_db, "wan_interfaces", ["ppp0"]))

    set_config(enricher_db, "wan_interfaces", body["wan_interfaces"])
    set_config(enricher_db, "interface_labels", body.get("interface_labels", {}))
    set_config(enricher_db, "setup_complete", True)
    set_config(enricher_db, "config_version", 2)

    # Save wizard path (unifi_api or log_detection)
    wizard_path = body.get("wizard_path", "log_detection")
    set_config(enricher_db, "wizard_path", wizard_path)

    # Enable UniFi API if wizard used the API path
    if wizard_path == "unifi_api":
        set_config(enricher_db, "unifi_enabled", True)
        unifi_api.reload_config()

    # Trigger direction backfill if WAN interfaces actually changed
    new_wan = set(body["wan_interfaces"])
    if new_wan != current_wan:
        set_config(enricher_db, "direction_backfill_pending", True)

    # Signal receiver process to reload config
    signal_receiver()

    return {"success": True}


@router.get("/api/interfaces")
def list_interfaces():
    """Return all discovered interfaces with their labels."""
    labels = get_config(enricher_db, "interface_labels", {})

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT DISTINCT unnest(ARRAY[interface_in, interface_out]) as iface
                FROM logs
                WHERE log_type = 'firewall'
                  AND (interface_in IS NOT NULL OR interface_out IS NOT NULL)
            """)
            interfaces = [row[0] for row in cur.fetchall() if row[0]]
    except Exception as e:
        logger.exception("Error querying interfaces")
        raise HTTPException(status_code=500, detail="Failed to query interfaces") from e
    finally:
        put_conn(conn)

    result = []
    for iface in sorted(interfaces):
        result.append({
            'name': iface,
            'label': labels.get(iface, iface)
        })

    return {'interfaces': result}


# ── Config Export/Import ─────────────────────────────────────────────────────

# Keys that are always exported (user-configured settings)
_EXPORTABLE_KEYS = [
    'wan_interfaces', 'interface_labels', 'setup_complete', 'config_version',
    'wizard_path', 'unifi_enabled', 'unifi_host', 'unifi_site',
    'unifi_verify_ssl', 'unifi_poll_interval', 'unifi_features',
    'unifi_controller_name', 'retention_days', 'dns_retention_days',
]

# Key that is only exported when explicitly requested
_API_KEY_CONFIG_KEY = 'unifi_api_key'


@router.get("/api/config/export")
def export_config(include_api_key: bool = False):
    """Export user configuration as JSON.

    Query params:
        include_api_key: if true, decrypts and includes the UniFi API key in plaintext.
    """
    config = {}
    for key in _EXPORTABLE_KEYS:
        val = get_config(enricher_db, key)
        if val is not None:
            config[key] = val

    includes_api_key = False
    if include_api_key:
        encrypted = get_config(enricher_db, _API_KEY_CONFIG_KEY, '')
        if encrypted:
            decrypted = decrypt_api_key(encrypted)
            if decrypted:
                config[_API_KEY_CONFIG_KEY] = decrypted
                includes_api_key = True

    return {
        "version": APP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "includes_api_key": includes_api_key,
        "config": config,
    }


@router.post("/api/config/import")
def import_config(body: dict):
    """Import configuration from a previously exported JSON.

    If the payload contains unifi_api_key (plaintext), it is re-encrypted before storage.
    If unifi_api_key is absent, the existing key is left untouched.
    """
    config = body.get("config")
    if not config or not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="Invalid config format — expected {config: {...}}")

    imported_keys = []
    failed_keys = []
    for key in _EXPORTABLE_KEYS:
        if key not in config:
            continue
        set_config(enricher_db, key, config[key])
        imported_keys.append(key)

    # Handle API key separately — re-encrypt for storage
    if _API_KEY_CONFIG_KEY in config and config[_API_KEY_CONFIG_KEY]:
        try:
            encrypted = encrypt_api_key(config[_API_KEY_CONFIG_KEY])
            set_config(enricher_db, _API_KEY_CONFIG_KEY, encrypted)
            imported_keys.append(_API_KEY_CONFIG_KEY)
        except Exception as e:
            logger.warning("Failed to encrypt imported API key: %s", e)
            failed_keys.append(_API_KEY_CONFIG_KEY)

    # Signal receiver to reload config
    signal_receiver()

    # Reload UniFi API if any unifi settings changed
    if any(k.startswith('unifi_') for k in imported_keys):
        unifi_api.reload_config()

    result = {"success": True, "imported_keys": imported_keys}
    if failed_keys:
        result["failed_keys"] = failed_keys
    return result


# ── Retention Configuration ──────────────────────────────────────────────────

@router.get("/api/config/retention")
def get_retention():
    """Return current retention configuration with effective values and source."""
    ui_general = get_config(enricher_db, 'retention_days')
    ui_dns = get_config(enricher_db, 'dns_retention_days')

    env_general = os.environ.get('RETENTION_DAYS')
    env_dns = os.environ.get('DNS_RETENTION_DAYS')

    # Resolve effective values: UI > env > defaults
    if ui_general is not None:
        general = int(ui_general)
        general_source = 'ui'
    elif env_general:
        try:
            general = int(env_general)
            general_source = 'env'
        except ValueError:
            logger.warning("Invalid RETENTION_DAYS env value: %r, using default", env_general)
            general = 60
            general_source = 'default'
    else:
        general = 60
        general_source = 'default'

    if ui_dns is not None:
        dns = int(ui_dns)
        dns_source = 'ui'
    elif env_dns:
        try:
            dns = int(env_dns)
            dns_source = 'env'
        except ValueError:
            logger.warning("Invalid DNS_RETENTION_DAYS env value: %r, using default", env_dns)
            dns = 10
            dns_source = 'default'
    else:
        dns = 10
        dns_source = 'default'

    # Estimate log counts for slider steps
    estimates = _estimate_log_counts()

    return {
        'retention_days': general,
        'dns_retention_days': dns,
        'general_source': general_source,
        'dns_source': dns_source,
        'estimates': estimates,
    }


@router.post("/api/config/retention")
def update_retention(body: dict):
    """Update retention configuration. Values saved to system_config (overrides env vars)."""
    days = body.get('retention_days')
    dns_days = body.get('dns_retention_days')

    if days is not None:
        try:
            days = int(days)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="retention_days must be an integer") from None
        if not (1 <= days <= 3650):
            raise HTTPException(status_code=400, detail="retention_days must be between 1 and 3650")
        set_config(enricher_db, 'retention_days', days)

    if dns_days is not None:
        try:
            dns_days = int(dns_days)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="dns_retention_days must be an integer") from None
        if not (1 <= dns_days <= 3650):
            raise HTTPException(status_code=400, detail="dns_retention_days must be between 1 and 3650")
        set_config(enricher_db, 'dns_retention_days', dns_days)

    return {"success": True}


def _estimate_log_counts() -> dict:
    """Estimate total log count for each retention slider step.

    Uses the average daily rate from the last 7 days to extrapolate.
    Returns dict of {days_str: estimated_count}.
    """
    steps = [60, 120, 180, 270, 365]
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Get actual count and date range for last 7 days
            cur.execute("""
                SELECT COUNT(*),
                       EXTRACT(EPOCH FROM (MAX(timestamp) - MIN(timestamp))) / 86400.0
                FROM logs
                WHERE log_type != 'dns'
                  AND timestamp >= NOW() - INTERVAL '7 days'
            """)
            row = cur.fetchone()
            count_7d = row[0] or 0
            span_days = row[1] or 0

            if span_days < 0.5 or count_7d < 10:
                # Not enough data to estimate
                return {str(s): None for s in steps}

            daily_rate = count_7d / span_days
            return {str(s): int(daily_rate * s) for s in steps}
    except Exception:
        logger.debug("Failed to estimate log counts", exc_info=True)
        return {str(s): None for s in steps}
    finally:
        put_conn(conn)
