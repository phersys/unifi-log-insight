"""UniFi settings, connection test, and firewall proxy endpoints."""

import logging
import os

from fastapi import APIRouter, HTTPException

from db import get_config, set_config, encrypt_api_key, decrypt_api_key
from deps import enricher_db, unifi_api, signal_receiver

logger = logging.getLogger('api.unifi')

router = APIRouter()


@router.get("/api/settings/unifi")
def get_unifi_settings():
    """Current UniFi settings (merged: env + DB + defaults)."""
    return unifi_api.get_settings_info()


@router.put("/api/settings/unifi")
def update_unifi_settings(body: dict):
    """Save UniFi settings to system_config."""
    if 'enabled' in body:
        set_config(enricher_db, 'unifi_enabled', body['enabled'])
    if 'host' in body:
        set_config(enricher_db, 'unifi_host', body['host'])
    if 'api_key' in body:
        key_val = body['api_key']
        if key_val == '':
            set_config(enricher_db, 'unifi_api_key', '')
        elif key_val is not None:
            set_config(enricher_db, 'unifi_api_key', encrypt_api_key(key_val))
    if 'site' in body:
        set_config(enricher_db, 'unifi_site', body['site'])
    if 'verify_ssl' in body:
        set_config(enricher_db, 'unifi_verify_ssl', body['verify_ssl'])
    if 'poll_interval' in body:
        set_config(enricher_db, 'unifi_poll_interval', body['poll_interval'])
    if 'features' in body:
        set_config(enricher_db, 'unifi_features', body['features'])

    unifi_api.reload_config()
    signal_receiver()

    return {"success": True}


@router.post("/api/settings/unifi/test")
def test_unifi_connection(body: dict):
    """Test connection AND save settings on success."""
    host = body.get('host', '').strip()
    site = body.get('site', 'default').strip()
    verify_ssl = body.get('verify_ssl', True)
    use_env_key = body.get('use_env_key', False)
    use_saved_key = body.get('use_saved_key', False)

    if use_env_key:
        api_key = os.environ.get('UNIFI_API_KEY', '')
    elif use_saved_key:
        encrypted = get_config(enricher_db, 'unifi_api_key', '')
        api_key = decrypt_api_key(encrypted) if encrypted else ''
    else:
        api_key = body.get('api_key', '').strip()

    if not host or not api_key:
        raise HTTPException(status_code=400, detail="host and api_key are required")

    result = unifi_api.test_connection(host, api_key, site, verify_ssl)

    if result.get('success'):
        # Save to DB on successful test
        set_config(enricher_db, 'unifi_host', host)
        if not use_env_key and not use_saved_key:
            set_config(enricher_db, 'unifi_api_key', encrypt_api_key(api_key))
        set_config(enricher_db, 'unifi_site', site)
        set_config(enricher_db, 'unifi_verify_ssl', verify_ssl)
        set_config(enricher_db, 'unifi_controller_name', result.get('controller_name', ''))
        set_config(enricher_db, 'unifi_controller_version', result.get('version', ''))
        # Enable the API so wizard step 4 (firewall rules) can use it
        set_config(enricher_db, 'unifi_enabled', True)
        unifi_api.reload_config()

    return result


@router.get("/api/setup/unifi-network-config")
def unifi_network_config():
    """UniFi API-based network topology for wizard."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    try:
        return unifi_api.get_network_config()
    except Exception as e:
        logger.error("Failed to fetch UniFi network config: %s", e)
        raise HTTPException(status_code=502, detail=str(e))


@router.post("/api/settings/unifi/dismiss-upgrade")
def dismiss_upgrade():
    """Permanently dismiss the v2.0 upgrade modal."""
    set_config(enricher_db, 'upgrade_v2_dismissed', True)
    return {"success": True}


@router.get("/api/firewall/policies")
def get_firewall_policies():
    """Fetch all policies + zones (handles pagination internally)."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")
    if not unifi_api.features.get('firewall_management', True):
        raise HTTPException(status_code=400, detail="Firewall management is disabled")
    try:
        return unifi_api.get_firewall_data()
    except Exception as e:
        logger.error("Failed to fetch firewall policies: %s", e)
        raise HTTPException(status_code=502, detail=str(e))


@router.patch("/api/firewall/policies/{policy_id}")
def patch_firewall_policy(policy_id: str, body: dict):
    """Update a single policy's loggingEnabled."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")

    # Reject DERIVED policies
    origin = body.get('origin', '')
    if origin == 'DERIVED':
        raise HTTPException(
            status_code=400,
            detail="This rule is auto-generated and cannot be modified. Manage it in your UniFi Controller under Traffic Rules."
        )

    logging_enabled = body.get('loggingEnabled')
    if logging_enabled is None:
        raise HTTPException(status_code=400, detail="loggingEnabled is required")

    try:
        result = unifi_api.patch_firewall_policy(policy_id, logging_enabled)
        return {"success": True, "data": result}
    except Exception as e:
        status = 502
        msg = str(e)
        if hasattr(e, 'response'):
            if e.response.status_code == 403:
                msg = "Insufficient permissions. Ensure your UniFi API key belongs to a Local Admin account with Network permissions."
                status = 403
            elif e.response.status_code == 422:
                msg = "The controller rejected this change. The rule may have been modified or removed in the UniFi Controller."
                status = 422
            else:
                status = e.response.status_code
        raise HTTPException(status_code=status, detail=msg)


@router.post("/api/firewall/policies/bulk-logging")
def bulk_update_logging(body: dict):
    """Batch-update loggingEnabled for multiple policies."""
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured")

    policies = body.get('policies', [])
    if not policies:
        raise HTTPException(status_code=400, detail="policies list is required")

    try:
        return unifi_api.bulk_patch_logging(policies)
    except Exception as e:
        logger.error("Bulk firewall update failed: %s", e)
        raise HTTPException(status_code=502, detail=str(e))
