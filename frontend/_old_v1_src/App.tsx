import { Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import { Layout } from './components/Layout'
import { LoginPage } from './features/auth/LoginPage'
import DashboardPage from './features/dashboard/index'
import EventsPage from './features/events/index'
import LiveEventsPage from './features/events/LivePage'
import SessionsPage from './features/sessions/index'
import SessionDetailPage from './features/sessions/detail'
import AnomaliesPage from './features/anomalies/index'
import BehavioursPage from './features/behaviours/index'
import RiskPage from './features/risk/index'
import AnalyticsPage from './features/analytics/index'
import DeceptionPage from './features/deception/index'
import ModelsPage from './features/models/index'
import HoneypotPage from './features/honeypot/index'
import AuditPage from './features/audit/index'
import SystemPage from './features/system/index'

export default function App() {
  const { token } = useAuth()

  if (!token) {
    return (
      <Routes>
        <Route path="*" element={<LoginPage />} />
      </Routes>
    )
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/live" element={<LiveEventsPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:id" element={<SessionDetailPage />} />
        <Route path="/anomalies" element={<AnomaliesPage />} />
        <Route path="/behaviours" element={<BehavioursPage />} />
        <Route path="/risk" element={<RiskPage />} />
        <Route path="/analytics" element={<AnalyticsPage />} />
        <Route path="/deception" element={<DeceptionPage />} />
        <Route path="/models" element={<ModelsPage />} />
        <Route path="/honeypot" element={<HoneypotPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/system" element={<SystemPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}
