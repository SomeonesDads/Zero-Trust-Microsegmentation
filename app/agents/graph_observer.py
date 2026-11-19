from __future__ import annotations

from collections import OrderedDict
import networkx as nx

from app.models import NetworkEvent


class GraphObserver:
    def __init__(self, retention: int = 10000) -> None:
        self.graph = nx.DiGraph()
        self.instances = nx.DiGraph()
        self.events_seen = 0
        self.duplicates = 0
        self.retention = retention
        self._ids: OrderedDict[str, None] = OrderedDict()

    def observe(self, event: NetworkEvent) -> bool:
        """Record one event. Returns False for an already-seen event."""
        event_id = event.stable_id()
        if event_id in self._ids:
            self.duplicates += 1
            return False
        self._ids[event_id] = None
        if len(self._ids) > self.retention:
            self._ids.popitem(last=False)
        self.events_seen += 1
        if not event.counts_as_connection:
            return True
        for graph, src, dst in ((self.graph, event.src_service, event.dst_service),
                               (self.instances, event.source_key(), event.destination_key())):
            for key, name, service in ((src, event.src_container, event.src_service),
                                       (dst, event.dst_container, event.dst_service)):
                graph.add_node(key, service=service, last_timestamp=event.timestamp_mono)
                if graph is self.instances:
                    graph.nodes[key]["container"] = name
            edge = graph.get_edge_data(src, dst, {})
            graph.add_edge(src, dst, count=edge.get("count", 0) + 1,
                ports=sorted(set(edge.get("ports", [])) | {event.dst_port}),
                first_timestamp=edge.get("first_timestamp", event.timestamp_mono),
                last_timestamp=event.timestamp_mono)
            if graph.number_of_edges() > self.retention:
                oldest = min(graph.edges, key=lambda pair: graph.edges[pair]["last_timestamp"])
                graph.remove_edge(*oldest)
                graph.remove_nodes_from(list(nx.isolates(graph)))
        return True

    def snapshot(self, view: str = "services") -> dict:
        graph = self.instances if view == "instances" else self.graph
        return {"view": view, "nodes": [{"id": n, **data} for n, data in graph.nodes(data=True)],
                "edges": [{"source": s, "target": d, **data} for s, d, data in graph.edges(data=True)]}

