import { useState, useEffect, useMemo } from 'react'
import { fetchFirewallPolicies, patchFirewallPolicy, bulkUpdateFirewallLogging } from '../api'

// ── Helpers ──────────────────────────────────────────────────────────────────

// Standard zones in UniFi's default display order; custom zones go after these
const STANDARD_ZONE_ORDER = ['Internal', 'External', 'Gateway', 'VPN', 'Hotspot', 'DMZ']

// Abbreviations that should always be UPPERCASE
const UPPER_NAMES = { vpn: 'VPN', dmz: 'DMZ' }

function normalizeZoneName(name) {
  return UPPER_NAMES[name.toLowerCase()] || name
}

function sortZones(zones) {
  return [...zones].sort((a, b) => {
    const ai = STANDARD_ZONE_ORDER.indexOf(normalizeZoneName(a.name))
    const bi = STANDARD_ZONE_ORDER.indexOf(normalizeZoneName(b.name))
    // Standard zones first (by defined order), then custom zones alphabetically
    if (ai !== -1 && bi !== -1) return ai - bi
    if (ai !== -1) return -1
    if (bi !== -1) return 1
    return a.name.localeCompare(b.name)
  })
}

function buildZoneMap(zones) {
  const m = {}
  for (const z of zones) m[z.id] = normalizeZoneName(z.name)
  return m
}

function getDefaultAction(policies) {
  const derived = policies.find(p => p.metadata?.origin === 'DERIVED')
  if (!derived) {
    const sorted = [...policies].sort((a, b) => (b.index || 0) - (a.index || 0))
    if (sorted.length > 0) {
      return sorted[0].action?.type === 'BLOCK' ? 'Block All' : 'Allow All'
    }
    return null
  }
  const actionType = derived.action?.type || 'BLOCK'
  if (actionType === 'BLOCK') return 'Block All'
  const name = (derived.name || '').toLowerCase()
  if (name.includes('return') || name.includes('established')) return 'Allow Return'
  return 'Allow All'
}

function buildMatrixData(policies, zones) {
  const zoneIds = zones.map(z => z.id)
  const cells = {}
  for (const srcId of zoneIds) {
    for (const dstId of zoneIds) {
      const key = `${srcId}:${dstId}`
      const pair = policies.filter(
        p => p.source?.zoneId === srcId && p.destination?.zoneId === dstId
      )
      const customCount = pair.filter(p => p.metadata?.origin !== 'DERIVED').length
      const defaultAction = srcId === dstId && pair.length === 0
        ? null
        : getDefaultAction(pair)
      cells[key] = { defaultAction, customCount }
    }
  }
  return cells
}

function cellStyle(action, selected) {
  // Translucent colors + borders matching the log-stream action badges
  switch (action) {
    case 'Allow All':
      return selected
        ? 'border-chase border-chase-emerald text-emerald-300'
        : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/25'
    case 'Block All':
      return selected
        ? 'border-chase border-chase-red text-red-300'
        : 'bg-red-500/20 text-red-400 border border-red-500/40 hover:bg-red-500/30'
    case 'Allow Return':
      return selected
        ? 'border-chase border-chase-cyan text-cyan-300'
        : 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/25'
    default:
      return 'bg-white/[0.04] text-[#676f79] border border-white/[0.07]'
  }
}

// ── Toggle Switch (matches UniFi: 32×16 track, 14×14 knob) ─────────────────

function SyslogToggle({ checked, disabled, onChange }) {
  return (
    <button
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className="relative"
      aria-label="Toggle syslog"
    >
      <div
        className={`w-8 h-4 rounded-full transition-colors duration-200 ${
          disabled
            ? (checked ? 'bg-[#0b4ead]' : 'bg-[#282b2f]')
            : (checked ? 'bg-[#4797ff]' : 'bg-[#42474d]')
        } ${disabled ? 'cursor-not-allowed' : 'cursor-pointer'}`}
      >
        <div
          className="absolute top-[1px] w-[14px] h-[14px] rounded-full bg-white"
          style={{
            left: checked ? '17px' : '1px',
            transition: 'left .25s cubic-bezier(.8, 0, .6, 1.4)',
            boxShadow: '0 4px 12px 0 rgba(0,0,0,.4), 0 0 1px 0 hsla(214,8%,98%,.08)',
          }}
        />
      </div>
    </button>
  )
}

// ── ZoneMatrix ───────────────────────────────────────────────────────────────

function ZoneMatrix({ zones, cells, selectedCell, onSelectCell, totalPolicyCount, syslogLabel, onRefresh, refreshDisabled }) {
  const allSelected = selectedCell === null

  return (
    <div className="mb-5">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 text-[13px] text-[#cbced2] font-medium">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" className="w-4 h-4 text-[#676f79]">
            <path fillRule="evenodd" d="M4.25 2A2.25 2.25 0 002 4.25v2.5A2.25 2.25 0 004.25 9h2.5A2.25 2.25 0 009 6.75v-2.5A2.25 2.25 0 006.75 2h-2.5zm0 9A2.25 2.25 0 002 13.25v2.5A2.25 2.25 0 004.25 18h2.5A2.25 2.25 0 009 15.75v-2.5A2.25 2.25 0 006.75 11h-2.5zm9-9A2.25 2.25 0 0011 4.25v2.5A2.25 2.25 0 0013.25 9h2.5A2.25 2.25 0 0018 6.75v-2.5A2.25 2.25 0 0015.75 2h-2.5zm0 9A2.25 2.25 0 0011 13.25v2.5A2.25 2.25 0 0013.25 18h2.5A2.25 2.25 0 0018 15.75v-2.5A2.25 2.25 0 0015.75 11h-2.5z" clipRule="evenodd" />
          </svg>
          Zone Matrix
          <span className="text-[11px] font-normal text-[#676f79] ml-1">
            Click on any zone pair to filter policies below
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[11px] text-[#676f79]">{syslogLabel}</span>
          <button
            onClick={onRefresh}
            disabled={refreshDisabled}
            className="px-3 py-1.5 rounded text-xs font-medium border border-gray-600 text-gray-300 hover:bg-gray-700 hover:text-white disabled:opacity-40 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="w-full rounded-lg scroll-fade">
        <table className="w-full border-separate text-[11px]" style={{ borderSpacing: 0 }}>
          <thead>
            <tr>
              <th />
              <th />
              <th
                colSpan={zones.length}
                className="text-center text-[10px] font-normal text-[#676f79] pb-1 uppercase tracking-widest"
              >
                Destination
              </th>
            </tr>
            <tr>
              <th className="w-4" />
              <th className="p-0">
                <button
                  onClick={() => onSelectCell(null)}
                  className={`block w-full px-2.5 py-1.5 text-left font-medium whitespace-nowrap transition-colors rounded-tl-lg ${
                    allSelected
                      ? 'border-chase text-[#4797ff]'
                      : 'bg-black text-[#cbced2] border border-white/[0.07] hover:bg-gray-900'
                  }`}
                >
                  All Policies ({totalPolicyCount})
                </button>
              </th>
              {zones.map((z, i) => (
                <th
                  key={z.id}
                  className={`px-2.5 py-1.5 font-medium text-[#cbced2] text-center border border-white/[0.07] bg-black whitespace-nowrap ${
                    i === zones.length - 1 ? 'rounded-tr-lg' : ''
                  }`}
                >
                  {normalizeZoneName(z.name)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {zones.map((src, ri) => (
              <tr key={src.id}>
                {ri === 0 && (
                  <td
                    rowSpan={zones.length}
                    className="text-[10px] text-[#676f79] font-normal uppercase tracking-widest w-4 select-none"
                    style={{ writingMode: 'vertical-lr', transform: 'rotate(180deg)' }}
                  >
                    <div className="flex items-center justify-center h-full">Source</div>
                  </td>
                )}
                <td className={`px-2.5 py-1.5 font-medium text-[#cbced2] border border-white/[0.07] bg-black whitespace-nowrap text-[11px] ${
                  ri === zones.length - 1 ? 'rounded-bl-lg' : ''
                }`}>
                  {normalizeZoneName(src.name)}
                </td>
                {zones.map((dst, ci) => {
                  const key = `${src.id}:${dst.id}`
                  const cell = cells[key]
                  const sel = selectedCell?.srcZoneId === src.id && selectedCell?.dstZoneId === dst.id
                  const isLastRow = ri === zones.length - 1
                  const isLastCol = ci === zones.length - 1
                  const cornerClass = isLastRow && isLastCol ? 'rounded-br-lg' : ''

                  if (!cell || cell.defaultAction === null) {
                    return (
                      <td key={dst.id} className={`p-0 ${cornerClass}`}>
                        <div className={`px-2.5 py-1.5 text-center text-[#676f79] bg-white/[0.04] border border-white/[0.07] ${cornerClass}`}>
                          &ndash;
                        </div>
                      </td>
                    )
                  }

                  return (
                    <td key={dst.id} className={`p-0 ${cornerClass}`}>
                      <button
                        onClick={() => onSelectCell({ srcZoneId: src.id, dstZoneId: dst.id })}
                        className={`block w-full px-2.5 py-1.5 text-center font-medium whitespace-nowrap transition-colors cursor-pointer ${cornerClass} ${cellStyle(cell.defaultAction, sel)}`}
                      >
                        {cell.defaultAction}
                        {cell.customCount > 0 && (
                          <span className="ml-1 opacity-70">({cell.customCount})</span>
                        )}
                      </button>
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── FilterBar ────────────────────────────────────────────────────────────────

const FILTER_OPTIONS = [
  { key: 'ipv4', label: 'IPv4' },
  { key: 'ipv6', label: 'IPv6' },
  { key: 'builtIn', label: 'Built-In' },
  { key: 'custom', label: 'Custom' },
  { key: 'inUse', label: 'In Use' },
  { key: 'paused', label: 'Paused' },
]

function FilterBar({ filters, onFilterChange, onBulk, bulkAction, zoneScopeLabel }) {
  return (
    <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
      <div className="flex items-center gap-4">
        {FILTER_OPTIONS.map(opt => (
          <label
            key={opt.key}
            className="flex items-center gap-1.5 text-[12px] text-[#cbced2] cursor-pointer select-none hover:text-[#f9fafa] transition-colors"
          >
            <input
              type="checkbox"
              checked={filters[opt.key]}
              onChange={() => onFilterChange({ ...filters, [opt.key]: !filters[opt.key] })}
              className="w-3.5 h-3.5 rounded-sm border-[#42474d] bg-transparent text-[#4797ff] focus:ring-0 focus:ring-offset-0 cursor-pointer accent-[#4797ff]"
            />
            {opt.label}
          </label>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <span className="text-[11px] text-[#676f79] hidden md:flex items-center gap-1">
          {zoneScopeLabel ? (
            <>
              <span className="text-[#cbced2]">{zoneScopeLabel}</span> Toggles
            </>
          ) : (
            <>
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="currentColor" className="w-3.5 h-3.5 text-amber-400 shrink-0">
                <path fillRule="evenodd" d="M6.701 2.25c.577-1 2.02-1 2.598 0l5.196 9a1.5 1.5 0 01-1.299 2.25H2.804a1.5 1.5 0 01-1.3-2.25l5.197-9zM8 4a.75.75 0 01.75.75v3a.75.75 0 01-1.5 0v-3A.75.75 0 018 4zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
              </svg>
              All Policies Toggle
            </>
          )}
        </span>
        <button
          onClick={() => onBulk(true)}
          disabled={!!bulkAction}
          className="px-2.5 py-1 rounded text-[11px] font-medium text-[#4797ff] bg-[#4797ff]/10 hover:bg-[#4797ff]/20 border border-[#4797ff]/20 disabled:opacity-40 transition-colors"
        >
          {bulkAction === 'enable' ? 'Enabling...' : 'Enable All Logging'}
        </button>
        <button
          onClick={() => onBulk(false)}
          disabled={!!bulkAction}
          className="px-2.5 py-1 rounded text-[11px] font-medium text-[#cbced2] hover:text-[#f9fafa] border border-white/[0.07] hover:border-white/[0.15] disabled:opacity-40 transition-colors"
        >
          {bulkAction === 'disable' ? 'Disabling...' : 'Disable All Logging'}
        </button>
      </div>
    </div>
  )
}

// ── PolicyRow ────────────────────────────────────────────────────────────────

function PolicyRow({ policy, zoneMap, onToggle, toggling }) {
  const origin = policy.metadata?.origin
  const isDerived = origin === 'DERIVED'
  const isDisabled = policy.enabled === false
  const action = policy.action?.type || ''
  const logging = policy.loggingEnabled
  const canToggle = !isDerived && !isDisabled && !toggling

  return (
    <tr className={`border-b border-white/[0.07] hover:bg-white/[0.02] ${isDisabled ? 'opacity-40 pointer-events-none' : ''}`}>
      {/* Name */}
      <td className="px-2 pr-8 py-0 h-8">
        <span
          className={`block truncate text-[12px] ${isDerived ? 'text-[#676f79]' : 'text-[#f9fafa]'}`}
          title={policy.name}
        >
          {policy.name || '(unnamed)'}
        </span>
      </td>
      {/* Description */}
      <td className="px-2 pr-8 py-0 h-8">
        <span className="block truncate text-[11px] text-[#676f79]" title={policy.description || ''}>
          {policy.description || ''}
        </span>
      </td>
      {/* Action */}
      <td className="px-2 pr-8 py-0 h-8">
        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
          action === 'BLOCK'
            ? 'bg-[#f0383b]/15 text-[#f36267]'
            : action === 'ALLOW'
              ? 'bg-[#38cc65]/15 text-[#61d684]'
              : 'bg-white/[0.04] text-[#676f79]'
        }`}>
          {action || '\u2014'}
        </span>
      </td>
      {/* Protocol */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] text-[#676f79] uppercase truncate">
        {policy.ipProtocolScope?.protocolFilter?.name || policy.protocol || 'All'}
      </td>
      {/* Src Zone */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] text-[#cbced2] truncate">
        {zoneMap[policy.source?.zoneId] || '\u2014'}
      </td>
      {/* Dst Zone */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] text-[#cbced2] truncate">
        {zoneMap[policy.destination?.zoneId] || '\u2014'}
      </td>
      {/* ID */}
      <td className="px-2 pr-8 py-0 h-8 text-[11px] font-mono text-[#676f79]">
        {policy.index != null && policy.index < 2147483647 ? policy.index : '\u2014'}
      </td>
      {/* Syslog toggle */}
      <td className="px-2 py-0 h-8">
        <SyslogToggle
          checked={logging}
          disabled={!canToggle}
          onChange={(val) => onToggle(policy.id, val, origin)}
        />
      </td>
    </tr>
  )
}

// ── Confirmation Modal ──────────────────────────────────────────────────────

function BulkConfirmModal({ action, count, srcZone, dstZone, onConfirm, onCancel }) {
  const verb = action === 'enable' ? 'Enable' : 'Disable'

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60" onClick={onCancel}>
      <div
        className="bg-gray-900 border border-white/[0.07] rounded-xl shadow-2xl w-full max-w-sm mx-4 p-5"
        onClick={e => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold text-[#f9fafa] mb-3">
          {verb} Syslog Logging
        </h3>

        <div className="text-[12px] text-[#cbced2] space-y-2 mb-4">
          <p>
            {verb} logging for <span className="font-semibold text-[#f9fafa]">{count}</span> eligible
            {count === 1 ? ' rule' : ' rules'}
            {srcZone && dstZone ? (
              <> in zone pair <span className="font-semibold text-[#f9fafa]">{srcZone}</span> → <span className="font-semibold text-[#f9fafa]">{dstZone}</span></>
            ) : (
              <> across <span className="font-semibold text-amber-400">all policies</span></>
            )}
          </p>
          <p className="text-[11px] text-[#676f79]">
            Changes are applied immediately on the UniFi Gateway, but may take up to 5 minutes to take effect and reflect in the Log Stream.
          </p>
        </div>

        <div className="flex items-center justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-3.5 py-1.5 rounded text-[12px] font-medium text-[#cbced2] hover:text-[#f9fafa] border border-white/[0.07] hover:border-white/[0.15] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`px-3.5 py-1.5 rounded text-[12px] font-medium text-white transition-colors ${
              action === 'enable'
                ? 'bg-[#4797ff] hover:bg-[#338bff]'
                : 'bg-red-600 hover:bg-red-500'
            }`}
          >
            {verb} Logging
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function FirewallRules() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [toggling, setToggling] = useState(false)
  const [bulkAction, setBulkAction] = useState(null)
  const [pendingBulk, setPendingBulk] = useState(null) // { enableAll, eligible }
  const [selectedCell, setSelectedCell] = useState(null)
  const [filters, setFilters] = useState({
    ipv4: true, ipv6: true, builtIn: true, custom: true, inUse: true, paused: true,
  })

  useEffect(() => { loadPolicies() }, [])

  async function loadPolicies() {
    setLoading(true)
    setError(null)
    try {
      setData(await fetchFirewallPolicies())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const sortedZones = useMemo(() => {
    if (!data?.zones) return []
    return sortZones(data.zones)
  }, [data])

  const zoneMap = useMemo(() => {
    if (!data?.zones) return {}
    return buildZoneMap(data.zones)
  }, [data])

  const matrixCells = useMemo(() => {
    if (!data?.policies || !sortedZones.length) return {}
    return buildMatrixData(data.policies, sortedZones)
  }, [data, sortedZones])

  const filteredPolicies = useMemo(() => {
    if (!data?.policies) return []
    let result = data.policies

    if (selectedCell) {
      result = result.filter(p =>
        p.source?.zoneId === selectedCell.srcZoneId &&
        p.destination?.zoneId === selectedCell.dstZoneId
      )
    }

    result = result.filter(p => {
      const isDerived = p.metadata?.origin === 'DERIVED'
      const isEnabled = p.enabled !== false
      const ipv = (p.ipProtocolScope?.ipVersion || p.ipVersion || 'IPv4').toLowerCase()
      const isV4 = ipv.includes('ipv4') || ipv.includes('v4')
      const isV6 = ipv.includes('ipv6') || ipv.includes('v6')
      const isBoth = isV4 && isV6

      if (!filters.builtIn && isDerived) return false
      if (!filters.custom && !isDerived) return false
      if (!filters.inUse && isEnabled) return false
      if (!filters.paused && !isEnabled) return false
      if (!filters.ipv4 && !filters.ipv6) return false
      if (!filters.ipv4 && isV4 && !isBoth) return false
      if (!filters.ipv6 && isV6 && !isBoth) return false

      return true
    })

    return result.sort((a, b) => (a.index || 0) - (b.index || 0))
  }, [data, selectedCell, filters])

  const { controllableTotal, controllableLoggingEnabled } = useMemo(() => {
    if (!data?.policies) return { controllableTotal: 0, controllableLoggingEnabled: 0 }
    const controllable = data.policies.filter(p =>
      p.metadata?.origin !== 'DERIVED' && p.enabled !== false
    )
    return {
      controllableTotal: controllable.length,
      controllableLoggingEnabled: controllable.filter(p => p.loggingEnabled).length,
    }
  }, [data])

  async function handleToggle(policyId, loggingEnabled, origin) {
    setToggling(true)
    try {
      await patchFirewallPolicy(policyId, loggingEnabled, origin)
      setData(prev => ({
        ...prev,
        policies: prev.policies.map(p =>
          p.id === policyId ? { ...p, loggingEnabled } : p
        ),
      }))
    } catch (err) {
      setError(err.message)
      setTimeout(() => setError(null), 5000)
    } finally {
      setToggling(false)
    }
  }

  function handleBulkAction(enableAll) {
    const eligible = filteredPolicies.filter(p =>
      p.metadata?.origin !== 'DERIVED' &&
      p.enabled !== false &&
      p.loggingEnabled !== enableAll
    )
    if (!eligible.length) return
    setPendingBulk({ enableAll, eligible })
  }

  async function confirmBulkAction() {
    if (!pendingBulk) return
    const { enableAll, eligible } = pendingBulk
    setPendingBulk(null)

    setBulkAction(enableAll ? 'enable' : 'disable')
    try {
      const result = await bulkUpdateFirewallLogging(
        eligible.map(p => ({ id: p.id, loggingEnabled: enableAll }))
      )
      await loadPolicies()
      if (result.failed > 0) {
        setError(`${result.success} updated, ${result.failed} failed`)
        setTimeout(() => setError(null), 5000)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setBulkAction(null)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) {
    return <div className="text-center py-8 text-[#676f79] text-sm">Loading firewall rules...</div>
  }

  if (error && !data) {
    return (
      <div className="text-center py-8">
        <p className="text-[#f36267] text-sm mb-3">{error}</p>
        <button onClick={loadPolicies} className="text-xs text-[#4797ff] hover:text-[#338bff]">Retry</button>
      </div>
    )
  }

  if (!data || !data.policies?.length) {
    return <div className="text-center py-8 text-[#676f79] text-sm">No firewall policies found.</div>
  }

  return (
    <div>
      {/* Bulk confirm modal */}
      {pendingBulk && (
        <BulkConfirmModal
          action={pendingBulk.enableAll ? 'enable' : 'disable'}
          count={pendingBulk.eligible.length}
          srcZone={selectedCell ? zoneMap[selectedCell.srcZoneId] : null}
          dstZone={selectedCell ? zoneMap[selectedCell.dstZoneId] : null}
          onConfirm={confirmBulkAction}
          onCancel={() => setPendingBulk(null)}
        />
      )}

      {/* Zone Matrix */}
      <ZoneMatrix
        zones={sortedZones}
        cells={matrixCells}
        selectedCell={selectedCell}
        onSelectCell={setSelectedCell}
        totalPolicyCount={data.totalCount}
        syslogLabel={`${controllableLoggingEnabled} of ${controllableTotal} with syslog enabled`}
        onRefresh={loadPolicies}
        refreshDisabled={loading || !!bulkAction}
      />

      {/* Error banner */}
      {error && data && (
        <div className="mb-3 px-3 py-2 rounded bg-[#f0383b]/10 border border-[#f0383b]/30 text-xs text-[#f36267]">
          {error}
        </div>
      )}

      {/* Filters + bulk actions */}
      <FilterBar
        filters={filters}
        onFilterChange={setFilters}
        onBulk={handleBulkAction}
        bulkAction={bulkAction}
        zoneScopeLabel={selectedCell ? `${zoneMap[selectedCell.srcZoneId]} → ${zoneMap[selectedCell.dstZoneId]}` : null}
      />

      {/* Policy table */}
      <div className="scroll-fade border-b border-white/[0.07]">
        <table className="w-full table-fixed border-collapse">
          <colgroup>
            <col style={{ width: '22%' }} />
            <col style={{ width: '18%' }} />
            <col style={{ width: '9%' }} />
            <col style={{ width: '8%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '13%' }} />
            <col style={{ width: '7%' }} />
            <col style={{ width: '10%' }} />
          </colgroup>
          <thead>
            <tr className="border-b border-white/[0.07]">
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Name</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Description</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Action</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Protocol</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Src Zone</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Dst Zone</th>
              <th className="px-2 pr-8 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">ID</th>
              <th className="px-2 py-0 h-8 text-[11px] font-semibold text-[#f9fafa] uppercase tracking-[0.5px] text-left">Syslog</th>
            </tr>
          </thead>
          <tbody>
            {filteredPolicies.map(p => (
              <PolicyRow
                key={p.id}
                policy={p}
                zoneMap={zoneMap}
                onToggle={handleToggle}
                toggling={toggling}
              />
            ))}
            {filteredPolicies.length === 0 && (
              <tr>
                <td colSpan={8} className="px-2 py-10 text-center text-sm text-[#676f79]">
                  No policies match the current filters
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Footer */}
      <div className="mt-2.5 text-[11px] text-[#676f79] px-0.5">
        Showing {filteredPolicies.length} of {data.totalCount} rules
      </div>
    </div>
  )
}
