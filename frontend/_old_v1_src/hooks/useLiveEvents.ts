import { useEffect, useRef, useState } from 'react'
import type { LiveEvent, WsMessage } from '../types'

/**
 * Subscribe to the live telemetry WebSocket. Replays up to 100 recent events on
 * connect, then streams new events as they are published by the collector.
 */
export function useLiveEvents(onEvent?: (e: LiveEvent) => void) {
  const [connected, setConnected] = useState(false)
  const [recent, setRecent] = useState<LiveEvent[]>([])
  const handlerRef = useRef(onEvent)
  handlerRef.current = onEvent

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    let ws: WebSocket | null = null
    let retry: ReturnType<typeof setTimeout> | null = null
    let stopped = false

    const connect = () => {
      ws = new WebSocket(`${proto}://${window.location.host}/ws`)
      ws.onopen = () => setConnected(true)
      ws.onclose = () => {
        setConnected(false)
        if (!stopped) retry = setTimeout(connect, 3000)
      }
      ws.onmessage = (ev) => {
        let msg: WsMessage
        try {
          msg = JSON.parse(ev.data)
        } catch {
          return
        }
        if (msg.kind === 'event' && msg.data) {
          handlerRef.current?.(msg.data as LiveEvent)
          setRecent((prev) => {
            const next = [msg.data as LiveEvent, ...prev]
            return next.slice(0, 100)
          })
        }
      }
    }

    connect()
    return () => {
      stopped = true
      if (retry) clearTimeout(retry)
      ws?.close()
    }
  }, [])

  return { connected, recent }
}
