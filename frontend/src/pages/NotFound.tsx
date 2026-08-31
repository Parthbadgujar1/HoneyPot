import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="text-5xl font-bold text-slate-700">404</div>
      <div className="mt-2 text-slate-400">Page not found</div>
      <Link to="/" className="mt-4 rounded border border-cyan-500/50 px-3 py-1.5 text-xs text-cyan-300 hover:bg-cyan-500/10">Back to Dashboard</Link>
    </div>
  )
}
