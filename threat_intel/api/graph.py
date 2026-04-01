"""Graph API routes for IOC co-occurrence clustering."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import UTC, datetime
from itertools import combinations
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from threat_intel.api.ioc import detect_ioc_type
from threat_intel.db import crud
from threat_intel.db.database import get_db_session
from threat_intel.models.ioc import (
    GraphAlertIngestRequest,
    GraphAlertIngestResponse,
    IOCClusterNode,
    IOCClusterResponse,
    IOCType,
    Verdict,
)

router = APIRouter(tags=["graph"])


@router.post("/graph/alerts", response_model=GraphAlertIngestResponse)
async def post_graph_alert(
    payload: GraphAlertIngestRequest,
    db: AsyncSession = Depends(get_db_session),
) -> GraphAlertIngestResponse:
    """Register IOC co-occurrence edges from one alert context."""
    existing_alert = await crud.get_alert_event_by_external_id(payload.alert_id, db)
    if existing_alert is not None:
        return GraphAlertIngestResponse(
            alert_id=payload.alert_id,
            status="duplicate",
            resolved_ioc_count=0,
            edges_upserted=0,
        )

    observed_at = payload.observed_at or datetime.now(UTC)
    await crud.create_alert_event(
        external_alert_id=payload.alert_id,
        observed_at=observed_at,
        db=db,
    )

    unique_ioc_values = list(dict.fromkeys(payload.iocs))
    resolved_ioc_ids: list[UUID] = []
    for ioc_value in unique_ioc_values:
        ioc_type = detect_ioc_type(ioc_value)
        ioc = await crud.get_ioc_by_value_type(ioc_value, ioc_type.value, db)
        if ioc is None:
            continue
        resolved_ioc_ids.append(ioc.id)

    unique_ioc_ids = sorted(set(resolved_ioc_ids), key=lambda item: item.hex)

    edge_count = 0
    for left_id, right_id in combinations(unique_ioc_ids, 2):
        edge = await crud.upsert_ioc_graph_edge(
            ioc_a_id=left_id,
            ioc_b_id=right_id,
            observed_at=observed_at,
            db=db,
        )
        if edge is not None:
            edge_count += 1

    await db.commit()

    return GraphAlertIngestResponse(
        alert_id=payload.alert_id,
        status="created",
        resolved_ioc_count=len(unique_ioc_ids),
        edges_upserted=edge_count,
    )


@router.get("/graph/clusters", response_model=list[IOCClusterResponse])
async def get_graph_clusters(
    min_size: int = Query(default=2, ge=2, le=1000),
    min_cooccurrence: int = Query(default=1, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
) -> list[IOCClusterResponse]:
    """Return connected IOC clusters from co-occurrence graph edges."""
    edge_rows = await crud.get_graph_edges(min_cooccurrence=min_cooccurrence, db=db)
    adjacency: dict[UUID, set[UUID]] = defaultdict(set)

    for left_id, right_id, _ in edge_rows:
        adjacency[left_id].add(right_id)
        adjacency[right_id].add(left_id)

    visited: set[UUID] = set()
    components: list[set[UUID]] = []

    for start_node in adjacency:
        if start_node in visited:
            continue

        component: set[UUID] = set()
        queue: deque[UUID] = deque([start_node])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            component.add(node)

            for neighbor in adjacency[node]:
                if neighbor not in visited:
                    queue.append(neighbor)

        if len(component) >= min_size:
            components.append(component)

    cluster_rows: list[tuple[int, int, list[IOCClusterNode]]] = []
    for component in components:
        ioc_rows = await crud.get_iocs_by_ids(list(component), db)
        nodes: list[IOCClusterNode] = []
        for ioc in sorted(ioc_rows, key=lambda row: row.confidence_score, reverse=True):
            try:
                verdict = Verdict(ioc.verdict)
            except ValueError:
                verdict = Verdict.clean

            try:
                ioc_type = IOCType(ioc.ioc_type)
            except ValueError:
                ioc_type = IOCType.domain

            nodes.append(
                IOCClusterNode(
                    ioc_value=ioc.ioc_value,
                    ioc_type=ioc_type,
                    confidence_score=float(ioc.confidence_score),
                    verdict=verdict,
                )
            )

        edge_count = sum(
            1
            for left_id, right_id, _ in edge_rows
            if left_id in component and right_id in component
        )
        cluster_rows.append((len(nodes), edge_count, nodes))

    cluster_rows.sort(
        key=lambda row: (
            row[0],
            max((node.confidence_score for node in row[2]), default=0.0),
        ),
        reverse=True,
    )

    return [
        IOCClusterResponse(
            cluster_id=index,
            size=size,
            edge_count=edge_count,
            nodes=nodes,
        )
        for index, (size, edge_count, nodes) in enumerate(cluster_rows, start=1)
    ]
