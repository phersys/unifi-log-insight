import { useState } from 'react'

export default function SettingsWanNetworks({ unifiEnabled, unifiSettings, wanCards, networkCards, onRestartWizard }) {
  const [imgLoaded, setImgLoaded] = useState(false)
  const gatewayImgUrl = unifiEnabled ? '/api/unifi/gateway-image' : null

  return (
    <div className="space-y-8">
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
            <div className="flex items-center gap-3">
              {gatewayImgUrl && (
                <img
                  src={gatewayImgUrl}
                  alt=""
                  className={`shrink-0${imgLoaded ? '' : ' hidden'}`}
                  width={48}
                  height={48}
                  onLoad={() => setImgLoaded(true)}
                  onError={() => setImgLoaded(false)}
                />
              )}
              <div className="flex-1 min-w-0">
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
    </div>
  )
}
