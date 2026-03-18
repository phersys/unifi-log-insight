import { useState, useCallback } from 'react'
import { fetchApiTokens, createApiToken, revokeApiToken } from '../api'

/**
 * Shared hook for token CRUD operations.
 * @param {string} [clientType] - Optional client_type filter for fetchApiTokens.
 */
export default function useApiTokens(clientType) {
  const [tokens, setTokens] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const reload = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const resp = await fetchApiTokens(clientType)
      setTokens(resp.tokens || [])
    } catch (err) {
      setTokens([])
      setError(err.message || 'Failed to load tokens')
    } finally {
      setLoading(false)
    }
  }, [clientType])

  const create = useCallback(async (payload) => {
    let resp
    try {
      resp = await createApiToken(payload)
    } catch (err) {
      setError(err.message || 'Failed to create token')
      throw err
    }
    // Reload list in the background — don't let reload failure mask a successful create
    try { await reload() } catch (err) { setError(err.message || 'Failed to refresh tokens') }
    return resp
  }, [reload])

  const revoke = useCallback(async (id) => {
    try {
      await revokeApiToken(id)
    } catch (err) {
      setError(err.message || 'Failed to revoke token')
      throw err
    }
    // Reload list in the background — don't let reload failure mask a successful revoke
    try { await reload() } catch (err) { setError(err.message || 'Failed to refresh tokens') }
  }, [reload])

  return { tokens, loading, error, reload, create, revoke }
}
