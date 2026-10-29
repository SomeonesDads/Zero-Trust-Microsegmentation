from __future__ import annotations

import networkx as nx

from app.models import NetworkEvent


class GraphObserver:
    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self.events_seen = 0
        self._ids: set[str] = set()

    def observe(self, event: NetworkEvent) -> bool:
        """Record one event. Returns False for an already-seen event."""
        event_id = event.stable_id()
        if event_id in self._ids:
            return False
        self._ids.add(event_id)
        self.events_seen += 1
        self.graph.add_node(event.src_service, container=event.src_container)
        self.graph.add_node(event.dst_service, container=event.dst_container)
        edge = self.graph.get_edge_data(event.src_service, event.dst_service, {})
        self.graph.add_edge(event.src_service, event.dst_service, count=edge.get("count", 0) + 1,
                            ports=sorted(set(edge.get("ports", [])) | {event.dst_port}),
                            last_timestamp=event.timestamp_mono)
        return True

    def snapshot(self) -> dict:
        return {"nodes": [{"id": n, **data} for n, data in self.graph.nodes(data=True)],
                "edges": [{"source": s, "target": d, **data} for s, d, data in self.graph.edges(data=True)]}

