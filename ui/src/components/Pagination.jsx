import React from 'react'
import { formatNumber } from '../utils'

export default function Pagination({ page, pages, total, perPage, onChange }) {
  const start = (page - 1) * perPage + 1
  const end = Math.min(page * perPage, total)

  return (
    <div className="flex items-center justify-between px-3 py-2 border-t border-gray-800">
      <span className="text-[11px] text-gray-500">
        {total > 0 ? `${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(total)}` : 'No results'}
      </span>
      <div className="flex items-center gap-1">
        <button
          disabled={page <= 1}
          onClick={() => onChange(1)}
          className="px-2 py-1 text-xs text-gray-500 hover:text-gray-300 disabled:text-gray-700 disabled:cursor-not-allowed"
        >
          ««
        </button>
        <button
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
          className="px-2 py-1 text-xs text-gray-500 hover:text-gray-300 disabled:text-gray-700 disabled:cursor-not-allowed"
        >
          «
        </button>
        <span className="px-3 py-1 text-xs text-gray-400">
          {page} / {pages || 1}
        </span>
        <button
          disabled={page >= pages}
          onClick={() => onChange(page + 1)}
          className="px-2 py-1 text-xs text-gray-500 hover:text-gray-300 disabled:text-gray-700 disabled:cursor-not-allowed"
        >
          »
        </button>
        <button
          disabled={page >= pages}
          onClick={() => onChange(pages)}
          className="px-2 py-1 text-xs text-gray-500 hover:text-gray-300 disabled:text-gray-700 disabled:cursor-not-allowed"
        >
          »»
        </button>
      </div>
    </div>
  )
}
