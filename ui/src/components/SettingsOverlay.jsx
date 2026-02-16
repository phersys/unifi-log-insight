import { useState, useEffect } from 'react'
import FirewallRules from './FirewallRules'
import { fetchConfig, fetchUniFiSettings, fetchUniFiNetworkConfig } from '../api'

function getVlanId(iface) {
  if (iface === 'br0') return 1
  const match = iface.match(/^br(\d+)$/)
  return match ? parseInt(match[1]) : null
}

export default function SettingsOverlay({ onClose, onRestartWizard }) {
  const [config, setConfig] = useState(null)
  const [unifiSettings, setUnifiSettings] = useState(null)
  const [netConfig, setNetConfig] = useState(null)

  useEffect(() => {
    fetchConfig().then(setConfig).catch(() => {})
    fetchUniFiSettings().then(data => {
      setUnifiSettings(data)
      if (data?.enabled) {
        fetchUniFiNetworkConfig().then(setNetConfig).catch(() => {})
      }
    }).catch(() => {})
  }, [])

  const savedWanInterfaces = config?.wan_interfaces || []
  const labels = config?.interface_labels || {}
  const unifiEnabled = unifiSettings?.enabled

  // Build WAN cards from ALL live WAN data (includes inactive WANs like WAN2)
  // Fall back to saved config if live data isn't available
  const liveWans = netConfig?.wan_interfaces || []
  const allWanPhysicals = new Set(savedWanInterfaces)
  for (const w of liveWans) allWanPhysicals.add(w.physical_interface)

  const wanCards = liveWans.length > 0
    ? liveWans.map(w => ({
        iface: w.physical_interface,
        name: w.name,
        wanIp: w.wan_ip || null,
        active: w.active,
        type: w.type || null,
      }))
    : savedWanInterfaces.map(iface => ({
        iface,
        name: labels[iface] || iface,
        wanIp: null,
        active: null,
        type: null,
      }))

  // Network cards: only bridge interfaces (br*) belong in network segments
  const networkCards = Object.entries(labels)
    .filter(([iface]) => iface.startsWith('br'))
    .map(([iface, label]) => {
      const live = netConfig?.networks?.find(n => n.interface === iface)
      return {
        iface,
        label,
        vlanId: live?.vlan ?? getVlanId(iface),
        subnet: live?.ip_subnet || null,
      }
    })

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950 shrink-0">
        <div className="flex items-center gap-3">
          <svg viewBox="0 0 24 24" className="w-7 h-7 text-blue-400" fill="none" stroke="currentColor">
            <circle cx="12" cy="12" r="10.5" strokeWidth="1.5" strokeOpacity="0.4" />
            <path d="M8.5 7.5v5.5a3.5 3.5 0 0 0 7 0V7.5" strokeWidth="2.2" strokeLinecap="round" />
          </svg>
          <div>
            <h1 className="text-lg font-semibold text-gray-200">UniFi Log Insight</h1>
            <p className="text-xs text-gray-400">Settings</p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200 transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-5 h-5">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-auto">
        <div className="max-w-6xl mx-auto py-8 px-6 space-y-8">

          {/* ── UniFi Gateway ─────────────────────────────────────── */}
          <section>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
                UniFi Gateway
              </h2>
              {unifiEnabled && (
                <button
                  onClick={onRestartWizard}
                  className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                >
                  Reconfigure
                </button>
              )}
            </div>
            {unifiEnabled ? (
              <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-gray-200">
                    {unifiSettings?.host || 'UniFi Gateway'}
                  </span>
                  <span className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    Online
                  </span>
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  {unifiSettings?.controller_name
                    ? `${unifiSettings.controller_name}${unifiSettings.controller_version ? ` (v${unifiSettings.controller_version})` : ''}`
                    : 'Connected via API'}
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-500">Not configured</span>
                  <button
                    onClick={onRestartWizard}
                    className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                  >
                    Set up
                  </button>
                </div>
              </div>
            )}
          </section>

          {/* ── WAN Interfaces ──────────────────────────────────── */}
          <section>
            <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
              WAN Interfaces
            </h2>
            {wanCards.length > 0 ? (
              <div className="grid gap-3 grid-cols-1 sm:grid-cols-2">
                {wanCards.map(wan => (
                  <div key={wan.iface} className="flex items-center justify-between rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-200 truncate">
                          {wan.name}
                        </span>
                        {wan.type && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/15 text-blue-400 border border-blue-500/30 shrink-0">
                            {wan.type}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs font-mono text-gray-500">{wan.iface}</span>
                        {wan.wanIp && (
                          <span className="text-xs font-mono text-gray-500">{wan.wanIp}</span>
                        )}
                      </div>
                    </div>
                    {wan.active != null && (
                      <div className="shrink-0 ml-3">
                        {wan.active ? (
                          <span className="flex items-center gap-1.5 text-[11px] text-emerald-400">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                            Active
                          </span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-[11px] text-gray-500">
                            <span className="w-1.5 h-1.5 rounded-full bg-gray-600" />
                            Inactive
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center text-sm text-gray-500">
                No WAN interfaces configured
              </div>
            )}
          </section>

          {/* ── Network Segments ─────────────────────────────────── */}
          <section>
            <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
              Network Labels
            </h2>
            {networkCards.length > 0 ? (
              <div className="grid gap-2 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">
                {networkCards.map(net => (
                  <div key={net.iface} className="flex items-center gap-3 rounded-lg border border-gray-700 bg-gray-950 px-4 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium text-gray-200 truncate">{net.label}</span>
                        {net.vlanId != null && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-400 border border-violet-500/30 shrink-0">
                            VLAN {net.vlanId}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <span className="text-xs font-mono text-gray-500">{net.iface}</span>
                        {net.subnet && (
                          <span className="text-xs font-mono text-gray-600">{net.subnet}</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center text-sm text-gray-500">
                No network labels configured
              </div>
            )}
          </section>

          {/* ── Firewall Rules ────────────────────────────────────── */}
          <section>
            <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
              Firewall Rules
            </h2>
            {unifiEnabled ? (
              <div className="rounded-lg border border-gray-700 bg-gray-950 p-4">
                <FirewallRules />
              </div>
            ) : (
              <div className="rounded-lg border border-gray-700 bg-gray-950 p-6 text-center">
                <p className="text-sm text-gray-400 mb-3">
                  Connect your UniFi controller to manage firewall rules.
                </p>
                <button
                  onClick={onRestartWizard}
                  className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors"
                >
                  Run Setup Wizard
                </button>
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  )
}
