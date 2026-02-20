"""TEMPORARY diagnostic endpoints for self-hosted controller API exploration.

DELETE THIS FILE once self-hosted firewall support is implemented.

Probes every relevant classic API endpoint and returns raw JSON so we can
understand data structures without back-and-forth with the tester.
"""

import logging
import time

from fastapi import APIRouter, HTTPException

from deps import unifi_api

logger = logging.getLogger('api.debug')

router = APIRouter(prefix="/api/debug/selfhosted", tags=["debug"])


def _probe(session, url, timeout=10):
    """GET a URL and return {status, data, error, elapsed_ms}."""
    t0 = time.monotonic()
    try:
        resp = session.get(url, timeout=timeout)
        elapsed = round((time.monotonic() - t0) * 1000)
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:2000]
        return {
            'status': resp.status_code,
            'data': body,
            'error': None,
            'elapsed_ms': elapsed,
        }
    except Exception as e:
        elapsed = round((time.monotonic() - t0) * 1000)
        return {
            'status': None,
            'data': None,
            'error': str(e),
            'elapsed_ms': elapsed,
        }


@router.get("/explore")
def explore_selfhosted_apis():
    """Probe all relevant API endpoints and return raw responses.

    Requires an active self-hosted connection (run setup wizard first).
    Returns a dict keyed by endpoint description with raw API responses.
    """
    if not unifi_api.enabled:
        raise HTTPException(status_code=400, detail="UniFi API not configured. Run setup wizard first.")
    if unifi_api._controller_type != 'self_hosted':
        raise HTTPException(status_code=400, detail="This endpoint is only for self-hosted controllers.")

    session = unifi_api._get_session()
    host = unifi_api.host
    site_id = unifi_api._site_id or unifi_api.site
    site_name = unifi_api.site

    results = {}

    # ── Site discovery ────────────────────────────────────────────────────
    results['1_sites'] = {
        'url': f'{host}/api/self/sites',
        'description': 'All sites on this controller',
        **_probe(session, f'{host}/api/self/sites'),
    }

    # ── System info ───────────────────────────────────────────────────────
    results['2_sysinfo'] = {
        'url': f'{host}/api/s/{site_id}/stat/sysinfo',
        'description': 'Controller version and system info',
        **_probe(session, f'{host}/api/s/{site_id}/stat/sysinfo'),
    }

    # ── Health (WAN status) ───────────────────────────────────────────────
    results['3_health'] = {
        'url': f'{host}/api/s/{site_id}/stat/health',
        'description': 'Network health including WAN status',
        **_probe(session, f'{host}/api/s/{site_id}/stat/health'),
    }

    # ── Network configuration ─────────────────────────────────────────────
    results['4_networkconf'] = {
        'url': f'{host}/api/s/{site_id}/rest/networkconf',
        'description': 'All network configs (VLANs, VPNs, WANs)',
        **_probe(session, f'{host}/api/s/{site_id}/rest/networkconf'),
    }

    # ── FIREWALL RULES (the key exploration target) ───────────────────────
    results['5_firewallrule'] = {
        'url': f'{host}/api/s/{site_id}/rest/firewallrule',
        'description': 'Classic firewall rules (iptables-style, has "log" property)',
        **_probe(session, f'{host}/api/s/{site_id}/rest/firewallrule'),
    }

    results['6_firewallgroup'] = {
        'url': f'{host}/api/s/{site_id}/rest/firewallgroup',
        'description': 'Firewall groups (port groups, address groups)',
        **_probe(session, f'{host}/api/s/{site_id}/rest/firewallgroup'),
    }

    # ── Routing / static routes ───────────────────────────────────────────
    results['7_routing'] = {
        'url': f'{host}/api/s/{site_id}/rest/routing',
        'description': 'Static routes',
        **_probe(session, f'{host}/api/s/{site_id}/rest/routing'),
    }

    # ── Clients (trimmed to first 5) ──────────────────────────────────────
    results['8_clients_sample'] = {
        'url': f'{host}/api/s/{site_id}/stat/sta',
        'description': 'Connected clients (trimmed to first 5)',
        **_probe(session, f'{host}/api/s/{site_id}/stat/sta'),
    }
    if (results['8_clients_sample'].get('data')
            and isinstance(results['8_clients_sample']['data'], dict)):
        data_list = results['8_clients_sample']['data'].get('data', [])
        results['8_clients_sample']['total_count'] = len(data_list)
        results['8_clients_sample']['data'] = {'data': data_list[:5]}
        results['8_clients_sample']['note'] = 'Trimmed to first 5 of %d' % len(data_list)

    # ── Devices ───────────────────────────────────────────────────────────
    results['9_devices'] = {
        'url': f'{host}/api/s/{site_id}/stat/device',
        'description': 'Infrastructure devices (APs, switches, gateways)',
        **_probe(session, f'{host}/api/s/{site_id}/stat/device'),
    }
    if (results['9_devices'].get('data')
            and isinstance(results['9_devices']['data'], dict)):
        data_list = results['9_devices']['data'].get('data', [])
        results['9_devices']['total_count'] = len(data_list)
        results['9_devices']['data'] = {'data': data_list[:3]}
        results['9_devices']['note'] = 'Trimmed to first 3 of %d' % len(data_list)

    # ── Integration API probes (expect 404 on self-hosted) ────────────────
    results['10_integration_sites'] = {
        'url': f'{host}/proxy/network/integration/v1/sites',
        'description': 'Integration API — EXPECTED TO FAIL on self-hosted',
        **_probe(session, f'{host}/proxy/network/integration/v1/sites'),
    }

    results['11_integration_firewall'] = {
        'url': f'{host}/proxy/network/integration/v1/sites/placeholder/firewall/policies',
        'description': 'Integration API firewall — EXPECTED TO FAIL on self-hosted',
        **_probe(session, f'{host}/proxy/network/integration/v1/sites/placeholder/firewall/policies'),
    }

    # ── Additional firewall-related endpoints to explore ──────────────────
    extra_paths = [
        ('12_firewallpolicy', f'/api/s/{site_id}/rest/firewallpolicy',
         'Zone-based firewall policies (may not exist on classic)'),
        ('13_trafficrule', f'/api/s/{site_id}/rest/trafficrule',
         'Traffic rules (newer controllers)'),
        ('14_trafficroute', f'/api/s/{site_id}/rest/trafficroute',
         'Traffic routes (newer controllers)'),
        ('15_firewallzone', f'/api/s/{site_id}/rest/firewallzone',
         'Firewall zones via classic API (may not exist)'),
        ('16_setting_firewall', f'/api/s/{site_id}/get/setting/firewall',
         'Firewall settings object'),
    ]

    for key, path, desc in extra_paths:
        results[key] = {
            'url': f'{host}{path}',
            'description': desc,
            **_probe(session, f'{host}{path}'),
        }

    # ── Metadata ──────────────────────────────────────────────────────────
    results['_meta'] = {
        'controller_type': unifi_api._controller_type,
        'host': host,
        'site_name': site_name,
        'site_id': site_id,
        'controller_version': unifi_api._db.get_config('unifi_controller_version', 'unknown'),
        'verify_ssl': unifi_api.verify_ssl,
    }

    return results
