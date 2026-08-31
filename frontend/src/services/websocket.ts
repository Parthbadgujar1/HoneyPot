// WebSocket layer (§18). Emits the documented event names backed by the demo engine.
// In browser dev mode we use the in-app event bus; swap `subscribe` for a real
// `new WebSocket(url)` when a backend is available.

import { demo } from '../data/demo'
import type { WsEventName, WsEvent } from '../data/demo'

export type { WsEventName, WsEvent }

const WS_URL = (location.protocol === 'https:' ? 'wss' : 'ws') + '://' + location.host + '/ws'

export function subscribe(eventName: WsEventName | 'all', cb: (e: WsEvent) => void): () => void {
  const raw = demo.subscribe((e) => {
    if (eventName === 'all' || e.event === eventName) cb(e)
  })
  return raw
}

export { WS_URL }
