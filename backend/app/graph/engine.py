"""Attack behaviour graph.

Builds a graph of observed relationships (nodes: identity, service, action,
resource, stage; edges: connected_to, authenticated_to, accessed, executed,
followed_by). Only relationships supported by telemetry evidence are created.
"""

from typing import Dict, List, Optional

import networkx as nx

from app.models.models import HoneypotEvent


def _fkey(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


def build_graph(events: List[HoneypotEvent], predicted: Optional[List] = None) -> Dict:
    """Return {'nodes': [...], 'edges': [...]} in Cytoscape.js format."""
    G = nx.DiGraph()
    evidence: Dict[str, List[str]] = {}

    def add_node(key, node_type, label, ev_id):
        if not G.has_node(key):
            G.add_node(key, node_type=node_type, label=label)
            evidence.setdefault(key, [])
        evidence.setdefault(key, []).append(ev_id)

    def add_edge(src, dst, etype, label, ev_id):
        if src in G and dst in G:
            if not G.has_edge(src, dst):
                G.add_edge(src, dst, edge_type=etype, label=label, evidence=[])
            evidence.setdefault(f"{src}|{dst}", []).append(ev_id)

    for ev in sorted(events, key=lambda e: e.timestamp):
        ev_id = str(ev.id)
        session_key = _fkey("session", ev.session_id or "unknown")
        add_node(session_key, "session", f"Session {ev.session_id}" if ev.session_id else "Session", ev_id)

        # identity / service nodes
        if ev.source:
            id_key = _fkey("identity", ev.source)
            add_node(id_key, "identity", ev.source, ev_id)
            add_edge(id_key, session_key, "connected_to", "connected_to", ev_id)

        if ev.service:
            svc_key = _fkey("service", ev.service)
            add_node(svc_key, "service", ev.service, ev_id)
            add_edge(session_key, svc_key, "used_service", "used_service", ev_id)

        # authentication edges
        if ev.event_type in ("authentication_success", "authentication_failure", "authentication"):
            if ev.username:
                user_key = _fkey("identity", ev.username)
                add_node(user_key, "identity", ev.username, ev_id)
            add_edge(session_key, svc_key if ev.service else session_key, "authenticated_to", ev.event_type, ev_id)

        # action node
        if ev.action:
            act_key = _fkey("action", ev.action)
            add_node(act_key, "action", ev.action, ev_id)
            add_edge(session_key, act_key, "executed", "executed", ev_id)

        # resource node
        if ev.target and ev.action not in ("connect", "close"):
            res_key = _fkey("resource", ev.target)
            add_node(res_key, "resource", ev.target, ev_id)
            add_edge(session_key, res_key, "accessed", ev.action, ev_id)
            # action -> resource
            if ev.action in G and res_key in G:
                add_edge(act_key, res_key, "acted_on", "acted_on", ev_id)

    # follow relations between consecutive distinct actions (behaviour progression)
    ordered = sorted(events, key=lambda e: e.timestamp)
    prev = None
    for ev in ordered:
        if ev.action and ev.action not in ("connect", "close"):
            cur = _fkey("action", ev.action)
            if prev and prev != cur:
                add_edge(prev, cur, "followed_by", "followed_by", str(ev.id))
            prev = cur

    # optional predicted next stage edges
    predicted_edges = []
    for pred in predicted or []:
        src = _fkey("stage", pred.get("from", ""))
        dst = _fkey("stage", pred.get("to", ""))
        add_node(src, "stage", pred.get("from", ""), "prediction")
        add_node(dst, "stage", pred.get("to", ""), "prediction")
        prob = pred.get("probability", 0.0)
        if not G.has_edge(src, dst):
            G.add_edge(src, dst, edge_type="predicted_next", label=f"predicted_next ({prob:.2f})", evidence=["prediction"])
        predicted_edges.append({"source": src, "target": dst, "edge_type": "predicted_next"})

    nodes = [
        {
            "data": {
                "id": n,
                "label": G.nodes[n].get("label", n),
                "node_type": G.nodes[n].get("node_type", "unknown"),
            }
        }
        for n in G.nodes
    ]
    edges = []
    for u, v, d in G.edges(data=True):
        edges.append(
            {
                "data": {
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    "edge_type": d.get("edge_type", "followed_by"),
                    "label": d.get("label", d.get("edge_type", "followed_by")),
                }
            }
        )
    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "evidence_count": sum(len(v) for v in evidence.values()),
        },
    }
