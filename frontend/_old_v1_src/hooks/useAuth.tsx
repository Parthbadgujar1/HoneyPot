import { createContext, useCallback, useContext, useState } from 'react'
import type { ReactNode } from 'react'
import type { User } from '../types'
import { api, getToken, setToken } from '../services/api'

interface AuthState {
  user: User | null
  token: string | null
  login: (username: string, password: string) => Promise<User>
  logout: () => void
  loading: boolean
}

const AuthContext = createContext<AuthState>(null as unknown as AuthState)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setTokenState] = useState<string | null>(getToken())
  const [loading, setLoading] = useState(false)

  const login = useCallback(async (username: string, password: string) => {
    setLoading(true)
    try {
      const res = await api.login(username, password)
      setToken(res.access_token)
      setTokenState(res.access_token)
      setUser(res.user)
      return res.user
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(() => {
    setToken(null)
    setTokenState(null)
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, token, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  return useContext(AuthContext)
}
