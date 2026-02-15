"""
UniFi Log Insight - UniFi Controller API Client

Handles all interactions with the UniFi Controller's Classic and Integration APIs.
Phase 1: Settings, wizard network config, firewall policy management.
"""

import logging
import os
import time

import requests
from requests.exceptions import ConnectionError, Timeout, SSLError

from db import encrypt_api_key, decrypt_api_key

logger = logging.getLogger(__name__)

# WAN physical interface mapping from API wan_type + wan_networkgroup
_WAN_PHYSICAL_MAP = {
    ('pppoe', 'WAN'): 'ppp0',
    ('pppoe', 'WAN2'): 'ppp1',
    ('dhcp', 'WAN'): 'eth4',
    ('static', 'WAN'): 'eth4',
    ('dhcp', 'WAN2'): 'eth5',
    ('static', 'WAN2'): 'eth5',
}


class UniFiAPI:
    """UniFi Controller API client - Phase 1: settings, wizard, firewall."""

    TIMEOUT = 10  # seconds per request

    def __init__(self, db):
        self._db = db
        self._session = None
        self._site_uuid = None
        self.host = ''
        self.api_key = ''
        self.site = 'default'
        self.verify_ssl = True
        self.enabled = False
        self.features = {}
        try:
            self._resolve_config()
        except Exception as e:
            logger.warning("UniFiAPI: config resolution failed (DB may not be ready): %s", e)

    # ── Config Resolution ─────────────────────────────────────────────────────

    def _resolve_config(self):
        """Load settings: env var > system_config DB > default."""
        self.host = (os.environ.get('UNIFI_HOST') or
                     self._db.get_config('unifi_host', '')).rstrip('/')
        self.api_key = (os.environ.get('UNIFI_API_KEY') or
                        self._decrypt_db_key())
        self.site = (os.environ.get('UNIFI_SITE') or
                     self._db.get_config('unifi_site', 'default'))

        ssl_env = os.environ.get('UNIFI_VERIFY_SSL', '').lower()
        if ssl_env in ('false', '0', 'no'):
            self.verify_ssl = False
        elif ssl_env:
            self.verify_ssl = True
        else:
            self.verify_ssl = self._db.get_config('unifi_verify_ssl', True)

        self.features = self._db.get_config('unifi_features', {
            'client_names': True, 'device_discovery': True,
            'network_config': True, 'firewall_management': True,
        })

        # Master toggle AND credentials must both be present
        unifi_enabled_env = os.environ.get('UNIFI_ENABLED', '').lower()
        if unifi_enabled_env in ('true', '1', 'yes'):
            unifi_enabled = True
        elif unifi_enabled_env in ('false', '0', 'no'):
            unifi_enabled = False
        else:
            unifi_enabled = self._db.get_config('unifi_enabled', False)

        self.enabled = bool(unifi_enabled) and bool(self.host and self.api_key)

        # Auto-enable when both env vars are set
        if (not unifi_enabled and self.host and self.api_key
                and os.environ.get('UNIFI_HOST') and os.environ.get('UNIFI_API_KEY')):
            try:
                self._db.set_config('unifi_enabled', True)
                self.enabled = True
                logger.info("UniFi API auto-enabled (UNIFI_HOST + UNIFI_API_KEY env vars detected)")
            except Exception:
                pass

    def _decrypt_db_key(self) -> str:
        """Read and decrypt API key from system_config."""
        encrypted = self._db.get_config('unifi_api_key', '')
        if not encrypted:
            return ''
        return decrypt_api_key(encrypted)

    def reload_config(self):
        """Re-read settings, invalidate session + site UUID."""
        self._session = None
        self._site_uuid = None
        self._resolve_config()
        logger.info("UniFi API config reloaded (enabled=%s, host=%s)", self.enabled, self.host or '(none)')

    def get_config_source(self, key: str) -> str:
        """Return 'env', 'db', or 'default' for a config key."""
        env_map = {
            'host': 'UNIFI_HOST',
            'api_key': 'UNIFI_API_KEY',
            'site': 'UNIFI_SITE',
            'verify_ssl': 'UNIFI_VERIFY_SSL',
        }
        env_var = env_map.get(key)
        if env_var and os.environ.get(env_var):
            return 'env'
        db_key = f'unifi_{key}'
        val = self._db.get_config(db_key)
        if val is not None and val != '':
            return 'db'
        return 'default'

    # ── HTTP Session ──────────────────────────────────────────────────────────

    def _get_session(self):
        """Lazily create and configure requests.Session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers['X-API-KEY'] = self.api_key
            self._session.verify = self.verify_ssl
        return self._session

    def _make_session(self, api_key: str, verify_ssl: bool):
        """Create a temporary session for test_connection."""
        s = requests.Session()
        s.headers['X-API-KEY'] = api_key
        s.verify = verify_ssl
        return s

    # ── Classic API Helpers ───────────────────────────────────────────────────

    def _get(self, path, host=None, session=None):
        """GET from classic API: /proxy/network/api/s/{site}/{path}"""
        h = host or self.host
        s = session or self._get_session()
        site = self.site
        url = f"{h}/proxy/network/api/s/{site}/{path.lstrip('/')}"
        resp = s.get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Integration API Helpers ───────────────────────────────────────────────

    def _get_integration(self, path, host=None, session=None):
        """GET from integration API (no site prefix)."""
        h = host or self.host
        s = session or self._get_session()
        url = f"{h}/proxy/network{path}"
        resp = s.get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _get_integration_site(self, path):
        """GET from integration API with site UUID prefix."""
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().get(url, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def _patch_integration_site(self, path, body):
        """PATCH to integration API with site UUID prefix."""
        if not self._site_uuid:
            self._discover_site_uuid()
        url = f"{self.host}/proxy/network/integration/v1/sites/{self._site_uuid}{path}"
        resp = self._get_session().patch(url, json=body, timeout=self.TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    # ── Site UUID Discovery ───────────────────────────────────────────────────

    def _discover_site_uuid(self, host=None, session=None):
        """Map classic site name to integration API UUID."""
        sites = self._get_integration('/integration/v1/sites', host=host, session=session)
        for s in sites.get('data', []):
            if s.get('internalReference') == self.site:
                self._site_uuid = s['id']
                logger.info("Discovered site UUID: %s for site '%s'", self._site_uuid, self.site)
                return
        raise ValueError(f"Site '{self.site}' not found in integration API")

    # ── Phase 1: Connection & Config ──────────────────────────────────────────

    def test_connection(self, host: str, api_key: str, site: str = 'default',
                        verify_ssl: bool = True) -> dict:
        """Test connectivity with provided credentials.

        Returns {success, controller_name, version, site_name} on success,
        or {success: false, error, error_code} on failure.
        Does NOT modify self — uses temporary session.
        """
        host = host.rstrip('/')
        session = self._make_session(api_key, verify_ssl)

        try:
            # Test basic connectivity with sysinfo
            url = f"{host}/proxy/network/api/s/{site}/stat/sysinfo"
            resp = session.get(url, timeout=self.TIMEOUT)

            if resp.status_code == 401:
                return {'success': False, 'error': 'Authentication failed. Check your API key.',
                        'error_code': 'auth_error'}
            if resp.status_code == 403:
                return {'success': False,
                        'error': 'Insufficient permissions. Ensure your API key belongs to a Local Admin account.',
                        'error_code': 'auth_error'}
            resp.raise_for_status()

            data = resp.json()
            info = data.get('data', [{}])[0] if data.get('data') else {}
            controller_name = info.get('name') or info.get('hostname', 'Unknown')
            version = info.get('version', 'Unknown')

            # Also verify integration API access (needed for firewall management)
            sites_url = f"{host}/proxy/network/integration/v1/sites"
            sites_resp = session.get(sites_url, timeout=self.TIMEOUT)
            sites_resp.raise_for_status()
            sites_data = sites_resp.json()

            site_name = None
            for s in sites_data.get('data', []):
                if s.get('internalReference') == site:
                    site_name = s.get('name', site)
                    break

            if site_name is None:
                return {'success': False,
                        'error': f"Site '{site}' not found on this controller.",
                        'error_code': 'invalid_response'}

            return {
                'success': True,
                'controller_name': controller_name,
                'version': version,
                'site_name': site_name,
            }

        except SSLError:
            return {'success': False,
                    'error': 'SSL certificate verification failed. Enable "Skip SSL verification" for self-signed certificates.',
                    'error_code': 'ssl_error'}
        except ConnectionError:
            return {'success': False,
                    'error': 'Could not connect to the controller. Check the URL and ensure it is reachable.',
                    'error_code': 'connection_error'}
        except Timeout:
            return {'success': False,
                    'error': 'Connection timed out. The controller may be unreachable.',
                    'error_code': 'timeout'}
        except requests.HTTPError as e:
            return {'success': False,
                    'error': f'Controller returned error: {e.response.status_code}',
                    'error_code': 'invalid_response'}
        except Exception as e:
            return {'success': False,
                    'error': str(e),
                    'error_code': 'connection_error'}
        finally:
            session.close()

    def get_network_config(self) -> dict:
        """Fetch network topology from Classic + Integration APIs for wizard."""
        if not self.enabled:
            return {'source': 'unifi_api', 'wan_interfaces': [], 'networks': []}

        # ── WAN interfaces from Classic API (/rest/networkconf + /stat/health) ──
        netconf = self._get('rest/networkconf')
        networks_raw = netconf.get('data', [])

        # Per-WAN health: 'wan' subsystem -> WAN, 'wan2' subsystem -> WAN2
        health = self._get('stat/health')
        wan_health = {}
        for subsystem in health.get('data', []):
            sub_name = subsystem.get('subsystem', '')
            if sub_name == 'wan':
                wan_health['WAN'] = subsystem
            elif sub_name == 'wan2':
                wan_health['WAN2'] = subsystem
        logger.debug("stat/health WAN subsystems: %s",
                     {k: {'wan_ip': v.get('wan_ip'), 'status': v.get('status')}
                      for k, v in wan_health.items()})

        wan_interfaces = []
        for net in networks_raw:
            if not net.get('enabled', True):
                continue
            if net.get('purpose') != 'wan':
                continue

            name = net.get('name', '')
            # API field is wan_networkgroup (not networkgroup)
            networkgroup = net.get('wan_networkgroup', '') or net.get('networkgroup', '')
            wan_type = net.get('wan_type', 'dhcp')
            wan_type_lower = wan_type.lower()
            logger.debug("WAN entry: name=%s, wan_type=%s, wan_networkgroup=%s",
                         name, wan_type, networkgroup)

            physical = _WAN_PHYSICAL_MAP.get(
                (wan_type_lower, networkgroup),
                'eth4' if networkgroup == 'WAN' else 'eth5'
            )
            if (wan_type_lower, networkgroup) not in _WAN_PHYSICAL_MAP:
                logger.warning("Unmapped WAN type: wan_type=%r, wan_networkgroup=%s -> defaulting to %s",
                               wan_type, networkgroup, physical)

            health_sub = wan_health.get(networkgroup, {})
            net_wan_ip = health_sub.get('wan_ip')
            wan_interfaces.append({
                'name': name,
                'wan_ip': net_wan_ip,
                'type': wan_type,
                'networkgroup': networkgroup,
                'physical_interface': physical,
                'active': bool(net_wan_ip),
            })

        # ── Network segments from Integration API (/networks) ──
        # Subnet lookup from classic API /rest/networkconf (keyed by name)
        subnet_by_name = {}
        for net in networks_raw:
            n = net.get('name', '')
            if n and net.get('ip_subnet'):
                subnet_by_name[n] = net['ip_subnet']

        networks = []
        try:
            int_networks = self._get_integration_site('/networks')
            for net in int_networks.get('data', []):
                if not net.get('enabled', True):
                    continue
                vlan_id = net.get('vlanId')
                if vlan_id is None:
                    continue

                name = net.get('name', '')
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': name,
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': subnet_by_name.get(name, ''),
                })
        except Exception as e:
            logger.warning("Integration API /networks failed, falling back to classic: %s", e)
            for net in networks_raw:
                if not net.get('enabled', True):
                    continue
                purpose = net.get('purpose', '')
                if purpose not in ('corporate', 'guest', 'vlan-only'):
                    continue
                vlan = net.get('vlan')
                vlan_enabled = net.get('vlan_enabled', False)
                vlan_id = vlan if vlan and vlan_enabled else 1
                iface = 'br0' if vlan_id == 1 else f'br{vlan_id}'
                networks.append({
                    'name': net.get('name', ''),
                    'interface': iface,
                    'vlan': vlan_id,
                    'ip_subnet': net.get('ip_subnet', ''),
                })

        return {
            'source': 'unifi_api',
            'wan_interfaces': wan_interfaces,
            'networks': networks,
        }

    def get_settings_info(self) -> dict:
        """Return current config with source indicators for Settings UI."""
        return {
            'enabled': self.enabled,
            'host': self.host,
            'host_source': self.get_config_source('host'),
            'api_key_set': bool(self.api_key),
            'api_key_source': self.get_config_source('api_key'),
            'site': self.site,
            'verify_ssl': self.verify_ssl,
            'poll_interval': int(os.environ.get('UNIFI_POLL_INTERVAL', 0) or
                                 self._db.get_config('unifi_poll_interval', 300)),
            'features': self.features,
            'controller_name': self._db.get_config('unifi_controller_name', ''),
            'controller_version': self._db.get_config('unifi_controller_version', ''),
            'status': {
                'connected': False,  # Phase 2: set from last poll result
                'last_poll': None,
                'last_error': None,
                'client_count': 0,
                'device_count': 0,
            },
        }

    # ── Phase 1: Firewall Management ─────────────────────────────────────────

    def get_firewall_zones(self) -> list:
        """Fetch all firewall zones."""
        data = self._get_integration_site('/firewall/zones')
        return data.get('data', [])

    def get_firewall_policies(self) -> list:
        """Fetch ALL firewall policies (handles pagination internally)."""
        all_policies = []
        offset = 0
        limit = 50
        while True:
            data = self._get_integration_site(
                f'/firewall/policies?offset={offset}&limit={limit}'
            )
            page = data.get('data', [])
            all_policies.extend(page)
            total_count = data.get('totalCount', 0)
            if offset + len(page) >= total_count:
                break
            offset += len(page)
        return all_policies

    def get_firewall_data(self) -> dict:
        """Fetch policies + zones in one call for the frontend."""
        policies = self.get_firewall_policies()
        zones = self.get_firewall_zones()

        logging_enabled = sum(1 for p in policies if p.get('loggingEnabled'))
        logging_disabled = len(policies) - logging_enabled

        return {
            'policies': policies,
            'zones': zones,
            'totalCount': len(policies),
            'loggingEnabled': logging_enabled,
            'loggingDisabled': logging_disabled,
        }

    def patch_firewall_policy(self, policy_id: str, logging_enabled: bool) -> dict:
        """Update loggingEnabled on a single policy."""
        return self._patch_integration_site(
            f'/firewall/policies/{policy_id}',
            {'loggingEnabled': logging_enabled}
        )

    def bulk_patch_logging(self, updates: list[dict]) -> dict:
        """Batch-update loggingEnabled for multiple policies.

        updates: [{"id": "uuid", "loggingEnabled": bool}, ...]
        Returns summary: {total, success, failed, skipped, errors}
        """
        total = len(updates)
        success = 0
        failed = 0
        skipped = 0
        errors = []

        for item in updates:
            policy_id = item.get('id', '')
            logging_val = item.get('loggingEnabled')

            if logging_val is None:
                skipped += 1
                continue

            try:
                self.patch_firewall_policy(policy_id, logging_val)
                success += 1
            except requests.HTTPError as e:
                failed += 1
                errors.append({
                    'id': policy_id,
                    'error': f'HTTP {e.response.status_code}: {e.response.text[:200]}'
                })
            except Exception as e:
                failed += 1
                errors.append({'id': policy_id, 'error': str(e)})

            # Be controller-friendly: 100ms delay between requests
            time.sleep(0.1)

        return {
            'total': total,
            'success': success,
            'failed': failed,
            'skipped': skipped,
            'errors': errors[:20],  # Cap error details
        }
