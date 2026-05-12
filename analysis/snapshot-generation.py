#!/usr/bin/env python3
"""
overnight_analysis.py

Phase 1  Download the first-of-month LN snapshots (raw PostgreSQL COPY BINARY)
         and record graph statistics to snapshots/<date>_stats.json.

Phase 2  For every saved snapshot reconstruct the graph and compute directed
         betweenness centrality; write results to snapshots/<date>_centrality.csv.

Run:
    python overnight_analysis.py

Environment variables:
    LN_HISTORY_API_KEY      API key (required)
    LN_HISTORY_BACKEND_URL  Backend base URL (default: http://localhost:5000)
    START_DATE              First snapshot date  YYYY-MM-DD (default: 2020-01-01)
    END_DATE                Last snapshot date   YYYY-MM-DD (default: 2025-12-01)

The snapshots directory is created next to this script if it does not exist.

---- Node attributes in the NetworkX graph ----------------------------------------
  node_id (graph key)  33-byte compressed public key of the node, hex-encoded
  announced            True if a node_announcement was present in the snapshot
  alias                Human-readable name chosen by the operator (up to 32 bytes)
  rgb_color            Operator-chosen RGB colour, hex string (e.g. "3399ff")
  features             Feature-bit flags, hex string
  timestamp            Unix timestamp of the latest node_announcement
  addresses            List of dicts: {typ: {id, name}, addr: str, port: int}
                       Types: 1=IPv4  2=IPv6  3=Torv2  4=Torv3  5=DNS
  signature            node_announcement signature, hex string

---- Edge (channel) attributes in the NetworkX graph --------------------------------
  From channel_announcement (always present):
    scid               Short channel ID "blockheight x txindex x output"
    features           Channel feature flags, hex string
    chain_hash         Genesis-block hash of the chain, hex string
    bitcoin_key_1/2    Funding-transaction keys for node1/node2, hex string
    node_signature_1/2 Signatures from each node over the announcement
    bitcoin_signature_1/2  Signatures from the corresponding Bitcoin keys
    direction          0 = node1→node2 edge, 1 = node2→node1 edge

  From channel_update (present when has_update=True):
    has_update              True if a channel_update was seen for this direction
    timestamp               Unix timestamp of the latest update for this direction
    fee_base_msat           Base forwarding fee in millisatoshis
    fee_proportional_millionths  Proportional fee rate in parts-per-million
    cltv_expiry_delta       Blocks added to CLTV of forwarded HTLCs
    htlc_minimum_msat       Minimum HTLC value this direction will forward
    htlc_maximum_msat       Maximum HTLC value (None if not advertised)
    message_flags           1-byte flags hex; bit0 = htlc_maximum_msat present
    channel_flags           1-byte flags hex; bit0 = direction, bit1 = disabled
------------------------------------------------------------------------------------
"""

import csv
import json
import logging
import os
import shutil
from datetime import date, datetime
from pathlib import Path
from typing import Dict, List, Optional

import networkx as nx

from lnhistoryclient.Lnhistoryrequester import LnhistoryRequester, LnhistoryRequesterError
from lnhistoryclient.common import create_network_graph

# ── Configuration ─────────────────────────────────────────────────────────────

API_KEY = os.environ.get("LN_HISTORY_API_KEY", "your-key")
BACKEND_URL = os.environ.get("LN_HISTORY_BACKEND_URL", "https://api.ln-history.info")

_start = os.environ.get("START_DATE", "2019-01-01")
_end = os.environ.get("END_DATE", "2026-04-01")
START_DATE = date.fromisoformat(_start)
END_DATE = date.fromisoformat(_end)

SNAPSHOTS_DIR = Path(__file__).parent / "snapshots"

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)



def _snap(d: date) -> Path:
    return SNAPSHOTS_DIR / f"{d.isoformat()}.pg_copy"

def _stats(d: date) -> Path:
    return SNAPSHOTS_DIR / f"{d.isoformat()}_stats.json"

def _centrality(d: date) -> Path:
    return SNAPSHOTS_DIR / f"{d.isoformat()}_centrality.csv"

def _capacities(d: date) -> Path:
    return SNAPSHOTS_DIR / f"{d.isoformat()}_capacities.json"



def first_of_months(start: date, end: date) -> List[date]:
    """Return sorted first-of-month dates between start and end (inclusive)."""
    months: List[date] = []
    cur = start.replace(day=1)
    while cur <= end:
        months.append(cur)
        cur = cur.replace(month=cur.month + 1) if cur.month < 12 else cur.replace(year=cur.year + 1, month=1)
    return months


def _channel_disabled(channel_flags_hex: str) -> bool:
    """Return True when bit1 of channel_flags is set (channel is disabled)."""
    try:
        return bool(int(channel_flags_hex, 16) & 0x02)
    except (ValueError, TypeError):
        return False


def compute_graph_stats(G: nx.DiGraph, d: date) -> Dict:
    """Collect topology statistics for a snapshot graph."""
    G_ud = G.to_undirected()
    components = sorted(nx.connected_components(G_ud), key=len, reverse=True)

    announced   = sum(1 for _, a in G.nodes(data=True) if a.get("announced"))
    unannounced = G.number_of_nodes() - announced
    isolated    = sum(1 for n in G.nodes() if G.degree(n) == 0)

    edges_with_update    = sum(1 for *_, a in G.edges(data=True) if a.get("has_update"))
    edges_disabled       = sum(
        1 for *_, a in G.edges(data=True)
        if a.get("has_update") and _channel_disabled(a.get("channel_flags", "00"))
    )
    channels = len({a["scid"] for *_, a in G.edges(data=True) if "scid" in a})

    return {
        "date":                      d.isoformat(),
        "nodes_total":               G.number_of_nodes(),
        "nodes_announced":           announced,
        "nodes_unannounced":         unannounced,
        "nodes_isolated":            isolated,
        "directed_edges":            G.number_of_edges(),
        "channels":                  channels,
        "edges_with_update":         edges_with_update,
        "edges_without_update":      G.number_of_edges() - edges_with_update,
        "edges_disabled":            edges_disabled,
        "connected_components":      len(components),
        "largest_component_nodes":   len(components[0]) if components else 0,
        "largest_component_pct":     round(len(components[0]) / G.number_of_nodes() * 100, 2)
                                     if G.number_of_nodes() and components else 0.0,
    }


# Phase 1: Download & record stats 

def phase1_download(dates: List[date]) -> None:
    """
    For each date: download the raw snapshot (pg_copy binary) and persist graph stats.

    The pg_copy binary is the exact payload returned by the ln-history API:
    a PostgreSQL COPY BINARY file with a single BYTEA column containing one
    raw gossip message per row (type prefix included).
    """
    SNAPSHOTS_DIR.mkdir(exist_ok=True)

    with LnhistoryRequester(API_KEY, backend_url=BACKEND_URL) as client:
        for d in dates:
            snap  = _snap(d)
            stats = _stats(d)

            if snap.exists() and stats.exists():
                log.info(f"[{d}] already done, skipping")
                continue

            ts = datetime(d.year, d.month, d.day)
            log.info(f"[{d}] downloading snapshot …")

            try:
                # return_graph=False → raw pg_copy temp file is NOT auto-deleted
                tmp: str = client.get_snapshot_at_timestamp(ts, return_graph=False)
                shutil.move(tmp, snap)
                size_mb = snap.stat().st_size / 1_000_000
                log.info(f"[{d}] saved {size_mb:.1f} MB → {snap.name}")

                log.info(f"[{d}] building graph for stats …")
                G = create_network_graph(str(snap), use_postgres_format=True)
                s = compute_graph_stats(G, d)
                stats.write_text(json.dumps(s, indent=2))
                log.info(
                    f"[{d}] nodes={s['nodes_total']:,}  channels={s['channels']:,}  "
                    f"isolated={s['nodes_isolated']:,}  "
                    f"components={s['connected_components']:,}  "
                    f"largest={s['largest_component_pct']:.1f}%"
                )
                del G

            except LnhistoryRequesterError as e:
                log.error(f"[{d}] API error: {e}")
            except Exception as e:
                log.error(f"[{d}] unexpected error: {e}", exc_info=True)


# Phase 2: Capacity enrichment

def phase2_enrichment(dates: List[date]) -> None:
    """
    For each saved snapshot reconstruct the graph, fetch capacity_sat for every
    channel from the backend via add_channel_capacities_to_graph, and persist
    the scid → capacity_sat mapping to <date>_capacities.json.
    """
    with LnhistoryRequester(API_KEY, backend_url=BACKEND_URL) as client:
        for d in dates:
            snap = _snap(d)
            out  = _capacities(d)

            if not snap.exists():
                log.warning(f"[{d}] snapshot not found, skipping enrichment")
                continue

            if out.exists():
                log.info(f"[{d}] capacities already enriched, skipping")
                continue

            log.info(f"[{d}] building graph …")
            G = create_network_graph(str(snap), use_postgres_format=True)

            log.info(f"[{d}] fetching channel capacities …")
            try:
                G = client.add_channel_capacities_to_graph(G)
            except LnhistoryRequesterError as e:
                log.error(f"[{d}] API error fetching capacities: {e}")
                continue
            except Exception as e:
                log.error(f"[{d}] unexpected error: {e}", exc_info=True)
                continue

            capacities: Dict[str, int] = {
                data["scid"]: data["capacity_sat"]
                for _, _, data in G.edges(data=True)
                if "scid" in data and "capacity_sat" in data
            }

            out.write_text(json.dumps(capacities, indent=2))
            log.info(f"[{d}] capacities written → {out.name}  ({len(capacities):,} channels)")
            del G


# Phase 3: Betweenness centrality

def phase3_betweenness(dates: List[date], top_n: Optional[int] = None) -> None:
    """
    For each saved snapshot reconstruct the graph, compute approximate betweenness
    centrality on the largest connected component of the undirected graph, and
    write results to a CSV.

    Speed-ups vs. the naive directed full-graph approach:
      - Undirected graph: halves the edge count and simplifies path enumeration.
      - Largest connected component only: skips isolated nodes and tiny islands
        (all of which would have BC = 0 anyway).
      - k-sampling: Brandes randomised approximation using k = 20 % of nodes
        instead of all-pairs shortest paths.  Error is O(1/sqrt(k)).

    top_n: if set, only write the top N nodes by centrality to CSV.
    """
    for d in dates:
        snap = _snap(d)
        out  = _centrality(d)

        if not snap.exists():
            log.warning(f"[{d}] snapshot not found, skipping centrality")
            continue

        if out.exists():
            log.info(f"[{d}] centrality already computed, skipping")
            continue

        log.info(f"[{d}] building graph …")
        G = create_network_graph(str(snap), use_postgres_format=True)
        if G.number_of_edges() == 0 or G.number_of_nodes == 0:
            log.info(f"[{d}] empty graph found")
            continue
        # Convert to undirected and extract the largest connected component.
        # Multi-edges (parallel channels between same pair) are collapsed to one.
        U = nx.Graph(G.to_undirected())
        largest_cc = max(nx.connected_components(U), key=len)
        H = U.subgraph(largest_cc).copy()
        n = H.number_of_nodes()

        k = max(50, int(0.2 * n))   # at least 50 pivot nodes for stability
        log.info(
            f"[{d}] approximate betweenness centrality  "
            f"nodes={n:,}  edges={H.number_of_edges():,}  k={k:,} ({k/n*100:.0f}%) …"
        )
        bc: Dict[str, float] = nx.betweenness_centrality(
            H, k=k, normalized=True, seed=42
        )

        rows = sorted(bc.items(), key=lambda x: x[1], reverse=True)
        if top_n is not None:
            rows = rows[:top_n]

        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "rank",
                "node_id",
                "betweenness_centrality",
                "alias",
                "rgb_color",
                "addresses",
                "channels",
                "announced",
            ])
            for rank, (node_id, score) in enumerate(rows, start=1):
                a = H.nodes[node_id]
                addresses = "; ".join(
                    f"{addr.get('addr', '')}:{addr.get('port', '')}"
                    for addr in a.get("addresses", [])
                )
                writer.writerow([
                    rank,
                    node_id,
                    f"{score:.8f}",
                    a.get("alias", ""),
                    a.get("rgb_color", ""),
                    addresses,
                    H.degree(node_id),
                    a.get("announced", False),
                ])

        log.info(f"[{d}] centrality written → {out.name}" if rows else f"[{d}] empty result")
        del G, U, H


if __name__ == "__main__":
    dates = first_of_months(START_DATE, END_DATE)
    log.info(f"Dates to process: {len(dates)}  ({dates[0]} → {dates[-1]})")

    log.info("=" * 60)
    log.info("Phase 1: downloading snapshots and recording stats")
    log.info("=" * 60)
    phase1_download(dates)

    log.info("=" * 60)
    log.info("Phase 2: enriching snapshots with channel capacities")
    log.info("=" * 60)
    phase2_enrichment(dates)

    log.info("=" * 60)
    log.info("Phase 3: computing betweenness centrality")
    log.info("=" * 60)
    phase3_betweenness(dates)

    log.info("All done.")
