"""
engine/asset_graph.py
---------------------
Directed asset graph implementation for Raven adaptive security assessment.

Maintains discovered assets as nodes and their semantic connections as directed edges.
Provides query interfaces for finding attack surfaces, tracing dependency/call chains,
and discovering multi-step attack paths across components.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from engine_models.assets import AssetRelationship, AssetType, DiscoveredAsset


class AssetGraph:
    """
    Adjacency-list directed graph of assessment assets and relationships.
    Zero external graph dependencies. Thread-safe read operations.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, DiscoveredAsset] = {}
        self._relationships: Dict[str, AssetRelationship] = {}
        # Outgoing edges: source_asset_id -> list of relationship_ids
        self._out_edges: Dict[str, List[str]] = {}
        # Incoming edges: target_asset_id -> list of relationship_ids
        self._in_edges: Dict[str, List[str]] = {}
        # Fast lookup by (AssetType, value)
        self._value_index: Dict[Tuple[str, str], str] = {}

    def add_asset(self, asset: DiscoveredAsset) -> DiscoveredAsset:
        """
        Add a discovered asset to the graph.
        If an asset of the same type and value already exists, updates metadata and returns existing.
        """
        key = (str(asset.asset_type.value), asset.value.strip())
        if key in self._value_index:
            existing_id = self._value_index[key]
            existing = self._nodes[existing_id]
            # Merge metadata
            existing.metadata.update(asset.metadata)
            if asset.confidence == "High":
                existing.confidence = "High"
            return existing

        self._nodes[asset.asset_id] = asset
        self._out_edges.setdefault(asset.asset_id, [])
        self._in_edges.setdefault(asset.asset_id, [])
        self._value_index[key] = asset.asset_id

        # Auto-create hierarchy edge if parent_asset_id provided
        if asset.parent_asset_id and asset.parent_asset_id in self._nodes:
            self.add_relationship(
                AssetRelationship(
                    source_asset_id=asset.parent_asset_id,
                    target_asset_id=asset.asset_id,
                    relationship_type="contains",
                    confidence="High",
                )
            )

        return asset

    def get_asset(self, asset_id: str) -> Optional[DiscoveredAsset]:
        """Fetch asset by unique ID."""
        return self._nodes.get(asset_id)

    def find_asset_by_value(self, asset_type: AssetType, value: str) -> Optional[DiscoveredAsset]:
        """Find an existing asset by type and value."""
        key = (str(asset_type.value), value.strip())
        asset_id = self._value_index.get(key)
        return self._nodes.get(asset_id) if asset_id else None

    def add_relationship(self, relationship: AssetRelationship) -> AssetRelationship:
        """Add a directed relationship between two assets."""
        # Validate that both assets exist or create placeholder nodes if needed
        src = relationship.source_asset_id
        tgt = relationship.target_asset_id

        if not src or not tgt:
            return relationship

        self._relationships[relationship.relationship_id] = relationship
        self._out_edges.setdefault(src, []).append(relationship.relationship_id)
        self._in_edges.setdefault(tgt, []).append(relationship.relationship_id)
        return relationship

    def get_children(
        self,
        asset_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[DiscoveredAsset]:
        """Return all destination assets connected by outgoing edges."""
        if asset_id not in self._out_edges:
            return []
        results = []
        for rel_id in self._out_edges[asset_id]:
            rel = self._relationships.get(rel_id)
            if not rel:
                continue
            if relationship_type and rel.relationship_type != relationship_type:
                continue
            child = self._nodes.get(rel.target_asset_id)
            if child and child not in results:
                results.append(child)
        return results

    def get_parents(
        self,
        asset_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[DiscoveredAsset]:
        """Return all source assets connected by incoming edges."""
        if asset_id not in self._in_edges:
            return []
        results = []
        for rel_id in self._in_edges[asset_id]:
            rel = self._relationships.get(rel_id)
            if not rel:
                continue
            if relationship_type and rel.relationship_type != relationship_type:
                continue
            parent = self._nodes.get(rel.source_asset_id)
            if parent and parent not in results:
                results.append(parent)
        return results

    def get_relationships_for_asset(self, asset_id: str) -> List[AssetRelationship]:
        """Return all incoming and outgoing relationships for an asset."""
        rel_ids = self._out_edges.get(asset_id, []) + self._in_edges.get(asset_id, [])
        return [self._relationships[r_id] for r_id in rel_ids if r_id in self._relationships]

    def get_by_type(self, asset_type: AssetType) -> List[DiscoveredAsset]:
        """Return all discovered assets of a particular type."""
        return [a for a in self._nodes.values() if a.asset_type == asset_type]

    def get_attack_surface(self) -> List[DiscoveredAsset]:
        """
        Identify exposed surface assets most critical for security assessment.
        Includes entrypoints, endpoints, open ports, exposed APIs, public cloud resources.
        """
        surface_types = {
            AssetType.URL,
            AssetType.ENDPOINT,
            AssetType.PORT,
            AssetType.SERVICE,
            AssetType.HOST,
            AssetType.DOMAIN,
            AssetType.IP_ADDRESS,
            AssetType.ROUTE,
            AssetType.BUCKET,
            AssetType.SMART_CONTRACT,
        }
        return [a for a in self._nodes.values() if a.asset_type in surface_types]

    def find_paths(
        self,
        start_asset_id: str,
        end_asset_id: str,
        max_depth: int = 5,
    ) -> List[List[str]]:
        """
        Find all directed paths (sequences of asset IDs) from start to end node.
        Uses BFS with path exploration up to max_depth.
        """
        if start_asset_id not in self._nodes or end_asset_id not in self._nodes:
            return []
        if start_asset_id == end_asset_id:
            return [[start_asset_id]]

        found_paths: List[List[str]] = []
        queue: deque[Tuple[str, List[str]]] = deque([(start_asset_id, [start_asset_id])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue

            for rel_id in self._out_edges.get(current, []):
                rel = self._relationships.get(rel_id)
                if not rel:
                    continue
                neighbor = rel.target_asset_id
                if neighbor == end_asset_id:
                    found_paths.append(path + [neighbor])
                elif neighbor not in path:  # Prevent cycles
                    queue.append((neighbor, path + [neighbor]))

        return found_paths

    def all_assets(self) -> List[DiscoveredAsset]:
        """Return all assets in the graph."""
        return list(self._nodes.values())

    def all_relationships(self) -> List[AssetRelationship]:
        """Return all relationships in the graph."""
        return list(self._relationships.values())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary."""
        return {
            "assets": [a.model_dump() for a in self._nodes.values()],
            "relationships": [r.model_dump() for r in self._relationships.values()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetGraph:
        """Reconstitute graph from dictionary."""
        graph = cls()
        for a_dict in data.get("assets", []):
            graph.add_asset(DiscoveredAsset(**a_dict))
        for r_dict in data.get("relationships", []):
            graph.add_relationship(AssetRelationship(**r_dict))
        return graph

    @classmethod
    def from_state(cls, state: Any) -> AssetGraph:
        """Construct graph directly from an AssessmentState instance."""
        graph = cls()
        for asset in getattr(state, "discovered_assets", []):
            graph.add_asset(asset)
        for rel in getattr(state, "asset_relationships", []):
            graph.add_relationship(rel)
        return graph

    def sync_to_state(self, state: Any) -> None:
        """Sync graph nodes and edges back to an AssessmentState."""
        state.discovered_assets = self.all_assets()
        state.asset_relationships = self.all_relationships()
