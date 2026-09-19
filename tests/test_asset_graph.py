"""
tests/test_asset_graph.py
-------------------------
Unit tests for AssetGraph queries, relationship traversal, and path finding.
"""

from engine.asset_graph import AssetGraph
from engine_models.assets import AssetRelationship, AssetType, DiscoveredAsset


def test_asset_graph_construction_and_hierarchy():
    g = AssetGraph()

    host = g.add_asset(
        DiscoveredAsset(
            asset_type=AssetType.HOST,
            value="10.0.0.5",
        )
    )

    port = g.add_asset(
        DiscoveredAsset(
            asset_type=AssetType.PORT,
            value="443",
            parent_asset_id=host.asset_id,
        )
    )

    service = g.add_asset(
        DiscoveredAsset(
            asset_type=AssetType.SERVICE,
            value="nginx/1.22",
        )
    )

    rel = g.add_relationship(
        AssetRelationship(
            source_asset_id=port.asset_id,
            target_asset_id=service.asset_id,
            relationship_type="runs_service",
        )
    )

    assert len(g.all_assets()) == 3
    # Verify auto-created contains relationship
    children = g.get_children(host.asset_id)
    assert any(c.asset_id == port.asset_id for c in children)

    # Verify path finding from host to service
    paths = g.find_paths(host.asset_id, service.asset_id)
    assert len(paths) >= 1
    assert paths[0] == [host.asset_id, port.asset_id, service.asset_id]


def test_asset_graph_attack_surface_extraction():
    g = AssetGraph()
    g.add_asset(DiscoveredAsset(asset_type=AssetType.URL, value="https://app.com"))
    g.add_asset(DiscoveredAsset(asset_type=AssetType.PORT, value="80"))
    g.add_asset(DiscoveredAsset(asset_type=AssetType.SECRET, value="aws_key"))
    g.add_asset(DiscoveredAsset(asset_type=AssetType.FILE, value="app.py"))

    surfaces = g.get_attack_surface()
    surface_values = [s.value for s in surfaces]

    assert "https://app.com" in surface_values
    assert "80" in surface_values
    # Internal secrets and generic files are not external attack surfaces
    assert "aws_key" not in surface_values
