import { useState } from 'react'
import type { GraphData } from '../../types'

const TYPE_COLORS: Record<string, string> = {
  session: '#22d3ee',
  identity: '#f59e0b',
  service: '#a78bfa',
  action: '#34d399',
  resource: '#f43f5e',
  stage: '#fb7185',
}

const LAYER_X: Record<string, number> = {
  session: 40,
  identity: 130,
  service: 220,
  action: 320,
  resource: 420,
  stage: 520,
}

/**
 * Minimal force-less layered renderer for Cytoscape-format graph data.
 * Nodes are positioned by type on the x-axis and stacked by row on the y-axis.
 */
export function AttackGraph({ graph }: { graph: GraphData }) {
  const [selected, setSelected] = useState<string | null>(null)

  const W = 760
  const H = 460
  const positions: Record<string, { x: number; y: number }> = {}
  const rowCounts: Record<string, number> = {}

  for (const n of graph.nodes) {
    const type = n.data.node_type || 'action'
    const x = LAYER_X[type] ?? 320
    const row = rowCounts[type] ?? 0
    rowCounts[type] = row + 1
    const numTypes = Object.keys(rowCounts).length || 1
    const spacing = H / (rowCounts[type] + 0.5)
    const y = 30 + row * Math.min(spacing, 80)
    positions[n.data.id] = { x, y }
  }

  const selectedNode = graph.nodes.find((n) => n.data.id === selected)

  return (
    <div className="overflow-auto rounded border border-soc-border bg-soc-panel2">
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="block">
        {graph.edges.map((e) => {
          const s = positions[e.data.source]
          const t = positions[e.data.target]
          if (!s || !t) return null
          const isSel =
            selected && (e.data.source === selected || e.data.target === selected)
          const predicted = e.data.edge_type === 'predicted_next'
          return (
            <line
              key={e.data.id}
              x1={s.x}
              y1={s.y}
              x2={t.x}
              y2={t.y}
              stroke={isSel ? '#22d3ee' : predicted ? '#f59e0b' : '#334155'}
              strokeWidth={isSel ? 2 : predicted ? 1.5 : 1}
              strokeDasharray={predicted ? '4 3' : undefined}
            />
          )
        })}
        {graph.nodes.map((n) => {
          const p = positions[n.data.id]
          if (!p) return null
          const color = TYPE_COLORS[n.data.node_type] || '#64748b'
          const isSel = n.data.id === selected
          return (
            <g key={n.data.id} onClick={() => setSelected(isSel ? null : n.data.id)} className="cursor-pointer">
              <circle
                cx={p.x}
                cy={p.y}
                r={isSel ? 13 : 10}
                fill={color}
                fillOpacity={0.2}
                stroke={color}
                strokeWidth={isSel ? 2.5 : 1.5}
              />
              <text
                x={p.x}
                y={p.y + 4}
                textAnchor="middle"
                fontSize={9}
                fill="#e2e8f0"
                pointerEvents="none"
              >
                {n.data.node_type === 'session' || n.data.node_type === 'identity'
                  ? (n.data.label || '').slice(0, 10)
                  : (n.data.label || '').slice(0, 12)}
              </text>
            </g>
          )
        })}
      </svg>
      <div className="flex flex-wrap items-center gap-3 border-t border-soc-border px-3 py-2 text-xs text-soc-muted">
        <span className="text-slate-500">
          {graph.stats?.node_count ?? graph.nodes.length} nodes ·{' '}
          {graph.stats?.edge_count ?? graph.edges.length} edges
        </span>
        {Object.entries(TYPE_COLORS).map(([t, c]) => (
          <span key={t} className="inline-flex items-center gap-1">
            <span className="h-2 w-2 rounded-full" style={{ background: c }} />
            {t}
          </span>
        ))}
        {selectedNode && (
          <span className="text-soc-accent">→ {selectedNode.data.label}</span>
        )}
      </div>
    </div>
  )
}
