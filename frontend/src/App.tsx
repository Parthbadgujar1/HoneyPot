import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Layout from './components/Layout'
import { DemoProvider } from './services/demoContext'
import Dashboard from './pages/Dashboard'
import LiveMonitor from './pages/LiveMonitor'
import AttackAnalysis from './pages/AttackAnalysis'
import AIAnalysis from './pages/AIAnalysis'
import Honeypots from './pages/Honeypots'
import ThreatIntelligence from './pages/ThreatIntelligence'
import Sessions from './pages/Sessions'
import Analytics from './pages/Analytics'
import AttackerDetail from './pages/AttackerDetail'
import HoneypotDetail from './pages/HoneypotDetail'
import SessionDetail from './pages/SessionDetail'
import NotFound from './pages/NotFound'

const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'live', element: <LiveMonitor /> },
      { path: 'attacks', element: <AttackAnalysis /> },
      { path: 'attacks/:id', element: <AttackerDetail /> },
      { path: 'ai', element: <AIAnalysis /> },
      { path: 'honeypots', element: <Honeypots /> },
      { path: 'honeypots/:id', element: <HoneypotDetail /> },
      { path: 'intel', element: <ThreatIntelligence /> },
      { path: 'sessions', element: <Sessions /> },
      { path: 'sessions/:id', element: <SessionDetail /> },
      { path: 'analytics', element: <Analytics /> },
      { path: '*', element: <NotFound /> },
    ],
  },
])

export default function App() {
  return (
    <DemoProvider>
      <RouterProvider router={router} />
    </DemoProvider>
  )
}
