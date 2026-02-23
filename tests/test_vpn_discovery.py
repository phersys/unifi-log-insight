"""
Test VPN network discovery with mock /rest/networkconf payloads.

Exercises interface derivation for all VPN types, with special focus on
OpenVPN Client (tunovpnc prefix) — Issue #41.

Self-contained: extracts the logic under test to avoid heavy import chains.

Run:  python tests/test_vpn_discovery.py
"""

# ── Extract the exact logic from unifi_api.py and parsers.py ───────────────
# This mirrors the production code so we can test without psycopg2/requests.

_VPN_TYPE_MAP = {
    'wireguard-server': ('wgsrv', 'WGD SRV'),
    'wireguard-client': ('wgclt', 'WGD CLT'),
    'site-magic-wan':   ('wgsts', 'S MAGIC'),
    'teleport':         ('tlprt', 'TELEPORT'),
    'ipsec-vpn':        ('vti',   'S2S IPSEC'),
    'openvpn-server':   ('tun',   'OVPN SRV'),
    'openvpn-client':   ('tunovpnc', 'OVPN CLT'),
    'l2tp-server':      ('l2tp',  'L2TP SRV'),
}

def get_vpn_networks(mock_data):
    """Mirror of UniFiClient.get_vpn_networks() with our fixes applied."""
    networks = mock_data.get('data', [])
    results = []
    for net in networks:
        vpn_type = net.get('vpn_type', '')
        if not vpn_type:
            continue
        mapping = _VPN_TYPE_MAP.get(vpn_type)
        if not mapping:
            continue
        prefix, badge = mapping

        # Derive interface name from prefix + numeric id
        iface = None
        if prefix:
            wg_id = net.get('wireguard_id')
            if wg_id is not None:
                iface = f'{prefix}{wg_id}'
            elif vpn_type in ('openvpn-server', 'openvpn-client'):
                # OpenVPN records lack wireguard_id; use tunnel_id,
                # x_openvpn_tunnel_id, or fall back to index 1
                ovpn_id = net.get('tunnel_id')
                if ovpn_id is None:
                    ovpn_id = net.get('x_openvpn_tunnel_id')
                iface = f'{prefix}{ovpn_id}' if ovpn_id is not None else f'{prefix}1'

        cidr = net.get('ip_subnet', '')
        results.append({
            'interface': iface,
            'name': (net.get('name') or '').strip(),
            'badge': badge,
            'cidr': cidr,
            'vpn_type': vpn_type,
            'enabled': net.get('enabled', True),
        })
    return results

# Parsers.py constants (post-fix)
VPN_PREFIX_BADGES = {
    'wgsrv': 'WGD SRV',
    'wgclt': 'WGD CLT',
    'wgsts': 'S MAGIC',
    'tlprt': 'TELEPORT',
    'vti':   'S2S IPSEC',
    'tunovpnc': 'OVPN CLT',
    'tun':   'OVPN TUN',
    'vtun':  'OVPN VTN',
    'l2tp':  'L2TP SRV',
}

VPN_INTERFACE_PREFIXES = ('wgsrv', 'wgclt', 'wgsts', 'tlprt', 'vti', 'tunovpnc', 'tun', 'vtun', 'l2tp')

VPN_PREFIX_DESCRIPTIONS = {
    'wgsrv': 'WireGuard Server',
    'wgclt': 'WireGuard Client',
    'wgsts': 'Site Magic',
    'tlprt': 'Teleport',
    'vti':   'Site-to-Site IPsec',
    'tunovpnc': 'OpenVPN Client',
    'tun':   'OpenVPN / Tunnel 1',
    'vtun':  'OpenVPN / Tunnel 2',
    'l2tp':  'L2TP Server',
}


# ── Mock /rest/networkconf payloads ────────────────────────────────────────

MOCK_NETWORKCONF = {
    'data': [
        # WireGuard Server (has wireguard_id)
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d1',
            'name': 'WG Server Home',
            'vpn_type': 'wireguard-server',
            'enabled': True,
            'wireguard_id': 0,
            'ip_subnet': '10.10.50.1/24',
        },
        # WireGuard Client (has wireguard_id)
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d2',
            'name': 'WG Client Remote',
            'vpn_type': 'wireguard-client',
            'enabled': True,
            'wireguard_id': 1,
            'ip_subnet': '10.10.60.1/24',
        },
        # OpenVPN Server (no wireguard_id, has tunnel_id)
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d3',
            'name': 'OVPN Server Office',
            'vpn_type': 'openvpn-server',
            'enabled': True,
            'tunnel_id': 0,
            'ip_subnet': '10.10.70.1/29',
        },
        # OpenVPN Client with tunnel_id — Issue #41 primary case
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d4',
            'name': 'VPN Provider',
            'vpn_type': 'openvpn-client',
            'enabled': True,
            'tunnel_id': 1,
            'ip_subnet': '',
        },
        # OpenVPN Client without tunnel_id (falls back to 1)
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d5',
            'name': 'Minimal OVPN Client',
            'vpn_type': 'openvpn-client',
            'enabled': True,
            'ip_subnet': '10.10.80.0/24',
        },
        # OpenVPN Client with x_openvpn_tunnel_id
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d6',
            'name': 'OVPN Client Alt Field',
            'vpn_type': 'openvpn-client',
            'enabled': True,
            'x_openvpn_tunnel_id': 3,
            'ip_subnet': '10.10.90.0/24',
        },
        # Site Magic WAN
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d7',
            'name': 'Site Magic Link',
            'vpn_type': 'site-magic-wan',
            'enabled': True,
            'wireguard_id': 2,
            'ip_subnet': '10.10.100.1/30',
        },
        # IPsec VPN
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d8',
            'name': 'Branch Office IPsec',
            'vpn_type': 'ipsec-vpn',
            'enabled': True,
            'wireguard_id': 0,
            'ip_subnet': '10.10.110.0/24',
        },
        # L2TP Server
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0d9',
            'name': 'L2TP Remote Access',
            'vpn_type': 'l2tp-server',
            'enabled': True,
            'wireguard_id': 0,
            'ip_subnet': '10.10.120.1/24',
        },
        # Non-VPN network (should be skipped)
        {
            '_id': '60f1a2b3c4d5e6f7a8b9c0da',
            'name': 'Default LAN',
            'purpose': 'corporate',
            'ip_subnet': '192.168.1.1/24',
        },
    ]
}


# ── Tests ──────────────────────────────────────────────────────────────────

def test_get_vpn_networks():
    """Validate interface derivation for all VPN types."""
    results = get_vpn_networks(MOCK_NETWORKCONF)
    by_name = {r['name']: r for r in results}

    assert 'Default LAN' not in by_name, "Non-VPN network should be skipped"

    # WireGuard (uses wireguard_id)
    assert by_name['WG Server Home']['interface'] == 'wgsrv0'
    assert by_name['WG Server Home']['badge'] == 'WGD SRV'

    assert by_name['WG Client Remote']['interface'] == 'wgclt1'
    assert by_name['WG Client Remote']['badge'] == 'WGD CLT'

    # OpenVPN Server (uses tunnel_id)
    assert by_name['OVPN Server Office']['interface'] == 'tun0'
    assert by_name['OVPN Server Office']['badge'] == 'OVPN SRV'

    # OpenVPN Client with tunnel_id — Issue #41 primary case
    assert by_name['VPN Provider']['interface'] == 'tunovpnc1'
    assert by_name['VPN Provider']['badge'] == 'OVPN CLT'

    # OpenVPN Client without tunnel_id (falls back to 1)
    assert by_name['Minimal OVPN Client']['interface'] == 'tunovpnc1'
    assert by_name['Minimal OVPN Client']['badge'] == 'OVPN CLT'

    # OpenVPN Client with x_openvpn_tunnel_id
    assert by_name['OVPN Client Alt Field']['interface'] == 'tunovpnc3'
    assert by_name['OVPN Client Alt Field']['badge'] == 'OVPN CLT'

    # Site Magic
    assert by_name['Site Magic Link']['interface'] == 'wgsts2'
    assert by_name['Site Magic Link']['badge'] == 'S MAGIC'

    # IPsec
    assert by_name['Branch Office IPsec']['interface'] == 'vti0'
    assert by_name['Branch Office IPsec']['badge'] == 'S2S IPSEC'

    # L2TP
    assert by_name['L2TP Remote Access']['interface'] == 'l2tp0'
    assert by_name['L2TP Remote Access']['badge'] == 'L2TP SRV'

    print(f"  PASS  get_vpn_networks: {len(results)} VPN entries derived correctly")
    for r in results:
        print(f"         {r['interface']:14s}  {r['badge']:10s}  {r['name']}")


def test_prefix_ordering():
    """Verify tunovpnc matches before tun in prefix-based lookups."""
    # tunovpnc must appear before tun in all ordered structures
    prefixes_list = list(VPN_PREFIX_BADGES.keys())
    assert prefixes_list.index('tunovpnc') < prefixes_list.index('tun'), \
        "tunovpnc must appear before tun in VPN_PREFIX_BADGES"

    assert VPN_INTERFACE_PREFIXES.index('tunovpnc') < VPN_INTERFACE_PREFIXES.index('tun'), \
        "tunovpnc must appear before tun in VPN_INTERFACE_PREFIXES"

    desc_list = list(VPN_PREFIX_DESCRIPTIONS.keys())
    assert desc_list.index('tunovpnc') < desc_list.index('tun'), \
        "tunovpnc must appear before tun in VPN_PREFIX_DESCRIPTIONS"

    # Simulate startswith() iteration (as used by /api/interfaces and log enrichment)
    for test_iface, expected_prefix in [('tunovpnc1', 'tunovpnc'), ('tun0', 'tun'), ('wgsrv0', 'wgsrv')]:
        matched = None
        for prefix in VPN_PREFIX_BADGES:
            if test_iface.startswith(prefix):
                matched = prefix
                break
        assert matched == expected_prefix, \
            f"{test_iface} should match {expected_prefix} first, got {matched}"

    print("  PASS  Prefix ordering: tunovpnc before tun in all structures")


def test_tunnel_id_zero():
    """Ensure tunnel_id=0 is handled correctly (not falsy)."""
    mock = {'data': [{
        '_id': 'test',
        'name': 'OVPN Zero',
        'vpn_type': 'openvpn-client',
        'enabled': True,
        'tunnel_id': 0,
        'ip_subnet': '10.0.0.0/24',
    }]}
    results = get_vpn_networks(mock)
    # tunnel_id=0 is falsy in Python — our `or` chain should still handle it
    # Current code: `net.get('tunnel_id') or net.get('x_openvpn_tunnel_id')`
    # With tunnel_id=0, `0 or None` → None, so we fall back to prefix1
    # This is a known limitation documented here
    assert results[0]['interface'] == 'tunovpnc0', \
        f"tunnel_id=0 should produce tunovpnc0: got {results[0]['interface']}"
    print("  PASS  tunnel_id=0 edge case: correctly produces tunovpnc0")


if __name__ == '__main__':
    print()
    test_get_vpn_networks()
    print()
    test_prefix_ordering()
    print()
    test_tunnel_id_zero()
    print("\n  All tests passed!\n")
