"""
Bulk import of historic gossip_store data into the ln-history PostgreSQL database.

Reads a Core Lightning gossip_store file, parses all Lightning gossip messages,
and inserts them into the database with full SCD Type 2 history (valid_from/valid_to).

Tables populated:
  gossip_inventory, nodes, channels, channel_updates, node_announcements, node_addresses

Tables skipped:
  gossip_observations (no collector association for historic imports)
  channel_closures (not available from gossip_store)
"""

import hashlib
import io
import logging
import os
import struct
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import paramiko
if not hasattr(paramiko, "DSSKey"):
    class DummyDSSKey:
        pass
    paramiko.DSSKey = DummyDSSKey # type: ignore

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from sshtunnel import SSHTunnelForwarder

from lnhistoryclient.parser.common import parse_address, strip_known_message_type
from lnhistoryclient.parser.parser_factory import get_parser_by_message_type

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IS_LOCAL = True
GOSSIP_STORE_PATH = Path(__file__).parent / "<your-file-name>"
BATCH_SIZE = 5_000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# gossip_store reader (yields raw bytes + record timestamp)
# ---------------------------------------------------------------------------

HEADER_FORMAT = ">HHII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

KNOWN_TYPES = {256, 257, 258, 4101, 4106}


def read_gossip_store(path: Path):
    """Yield (raw_bytes, record_timestamp_unix) for every known gossip message."""
    with open(path, "rb") as f:
        while True:
            hdr = f.read(HEADER_SIZE)
            if len(hdr) < HEADER_SIZE:
                break
            length = int.from_bytes(hdr[2:4], "big")
            record_ts = int.from_bytes(hdr[8:12], "big")
            raw = f.read(length)
            if len(raw) != length:
                break
            if len(raw) < 2:
                continue
            msg_type = int.from_bytes(raw[:2], "big")
            if msg_type in KNOWN_TYPES:
                yield raw, record_ts, msg_type


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def gossip_id(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def ts_to_dt(unix_ts: int) -> datetime:
    return datetime.fromtimestamp(unix_ts, tz=timezone.utc)


def parse(msg_type: int, raw: bytes):
    return get_parser_by_message_type(msg_type)(strip_known_message_type(raw))


def parse_addresses(addr_bytes: bytes) -> list:
    stream = io.BytesIO(addr_bytes)
    addrs = []
    while stream.tell() < len(addr_bytes):
        a = parse_address(stream)
        if a is None:
            break
        addrs.append(a)
    return addrs


# ---------------------------------------------------------------------------
# Pass 1: collect and group all messages
# ---------------------------------------------------------------------------

def collect_messages(path: Path):
    log.info("Pass 1: reading %s …", path)

    # channel_announcements keyed by gossip_id, waiting for their channel_amount
    pending_chan_ann = {}       # gossip_id -> (raw, record_ts, parsed)

    channels = {}              # gossip_id -> dict
    chan_updates = defaultdict(list)   # (scid, direction) -> list of dicts
    node_anns = defaultdict(list)      # node_id_hex -> list of dicts
    nodes = {}                 # node_id_hex -> {first_seen, last_seen}

    total = skipped = 0
    prev_was_chan_ann = False
    prev_chan_ann_gid = None

    for raw, record_ts, msg_type in read_gossip_store(path):
        total += 1
        gid = gossip_id(raw)

        # --- channel_announcement (256) ---
        if msg_type == 256:
            try:
                p = parse(256, raw)
            except Exception as e:
                log.debug("chan_ann parse error: %s", e)
                skipped += 1
                prev_was_chan_ann = False
                continue

            node1 = p.node_id_1.hex()
            node2 = p.node_id_2.hex()

            for nid in (node1, node2):
                dt_rec = ts_to_dt(record_ts)
                if nid not in nodes:
                    nodes[nid] = {"first_seen": dt_rec, "last_seen": dt_rec}
                else:
                    nodes[nid]["first_seen"] = min(nodes[nid]["first_seen"], dt_rec)
                    nodes[nid]["last_seen"] = max(nodes[nid]["last_seen"], dt_rec)

            pending_chan_ann[gid] = {
                "gossip_id": gid,
                "raw": raw,
                "record_ts": record_ts,
                "scid": p.scid,
                "source_node_id": node1,
                "target_node_id": node2,
                "chain_hash": p.chain_hash.hex(),
                "features": p.features,
                "node_signature_1": p.node_signature_1.hex(),
                "node_signature_2": p.node_signature_2.hex(),
                "bitcoin_signature_1": p.bitcoin_signature_1.hex(),
                "bitcoin_signature_2": p.bitcoin_signature_2.hex(),
                "bitcoin_key_1": p.bitcoin_key_1.hex(),
                "bitcoin_key_2": p.bitcoin_key_2.hex(),
            }
            prev_was_chan_ann = True
            prev_chan_ann_gid = gid
            continue

        # --- channel_amount (4101) — always follows channel_announcement ---
        if msg_type == 4101:
            if prev_was_chan_ann and prev_chan_ann_gid in pending_chan_ann:
                try:
                    p = parse(4101, raw)
                    ann = pending_chan_ann.pop(prev_chan_ann_gid)
                    ann["capacity_sat"] = p.satoshis
                    channels[ann["gossip_id"]] = ann
                except Exception as e:
                    log.debug("chan_amount parse error: %s", e)
                    pending_chan_ann.pop(prev_chan_ann_gid, None)
                    skipped += 1
            prev_was_chan_ann = False
            continue

        prev_was_chan_ann = False

        # --- node_announcement (257) ---
        if msg_type == 257:
            try:
                p = parse(257, raw)
            except Exception as e:
                log.debug("node_ann parse error: %s", e)
                skipped += 1
                continue

            node_id = p.node_id.hex()
            valid_from = ts_to_dt(p.timestamp)

            dt_rec = ts_to_dt(record_ts)
            if node_id not in nodes:
                nodes[node_id] = {"first_seen": dt_rec, "last_seen": dt_rec}
            else:
                nodes[node_id]["first_seen"] = min(nodes[node_id]["first_seen"], dt_rec)
                nodes[node_id]["last_seen"] = max(nodes[node_id]["last_seen"], dt_rec)

            addrs = parse_addresses(p.addresses)

            node_anns[node_id].append({
                "gossip_id": gid,
                "raw": raw,
                "record_ts": record_ts,
                "node_id": node_id,
                "valid_from": valid_from,
                "alias": p.alias.decode("utf-8", errors="replace").rstrip("\x00"),
                "rgb_color": p.rgb_color.hex(),
                "features": p.features,
                "addresses": addrs,
            })
            continue

        # --- channel_update (258) ---
        if msg_type == 258:
            try:
                p = parse(258, raw)
            except Exception as e:
                log.debug("chan_upd parse error: %s", e)
                skipped += 1
                continue

            direction = p.channel_flags[0] & 1
            valid_from = ts_to_dt(p.timestamp)

            chan_updates[(p.scid, direction)].append({
                "gossip_id": gid,
                "raw": raw,
                "record_ts": record_ts,
                "scid": p.scid,
                "direction": direction,
                "valid_from": valid_from,
                "chain_hash": p.chain_hash.hex(),
                "message_flags": p.message_flags[0],
                "channel_flags": p.channel_flags[0],
                "cltv_expiry_delta": p.cltv_expiry_delta,
                "htlc_minimum_msat": p.htlc_minimum_msat,
                "fee_base_msat": p.fee_base_msat,
                "fee_proportional_millionths": p.fee_proportional_millionths,
                "htlc_maximum_msat": p.htlc_maximum_msat,
            })
            continue

        # channel_dying (4106) — skip, no DB table

    log.info(
        "Pass 1 done: %d total records, %d channels, %d node_anns, "
        "%d chan_update groups, %d nodes, %d skipped",
        total, len(channels), sum(len(v) for v in node_anns.values()),
        len(chan_updates), len(nodes), skipped,
    )
    return channels, chan_updates, node_anns, nodes


# ---------------------------------------------------------------------------
# Pass 2: compute SCD Type 2 fields (valid_to, is_fee_update, etc.)
# ---------------------------------------------------------------------------

FEE_FIELDS = ("fee_base_msat", "fee_proportional_millionths")
TOPO_FIELDS = ("cltv_expiry_delta", "htlc_minimum_msat", "htlc_maximum_msat")


def compute_channel_update_scd(chan_updates: dict) -> list:
    result = []
    for (scid, direction), updates in chan_updates.items():
        updates.sort(key=lambda x: x["valid_from"])
        prev = None
        for i, u in enumerate(updates):
            is_last = i == len(updates) - 1
            u["valid_to"] = None if is_last else updates[i + 1]["valid_from"]

            if prev is None:
                u["is_fee_update"] = True
                u["is_topology_update"] = True
            else:
                fee_changed = any(u[f] != prev[f] for f in FEE_FIELDS)
                topo_changed = any(u[f] != prev[f] for f in TOPO_FIELDS)
                disabled_changed = (u["channel_flags"] & 2) != (prev["channel_flags"] & 2)
                u["is_fee_update"] = fee_changed
                u["is_topology_update"] = topo_changed or disabled_changed

            prev = u
            result.append(u)
    return result


NODE_ANN_DATA_FIELDS = ("alias", "rgb_color")


def compute_node_ann_scd(node_anns: dict) -> list:
    result = []
    for node_id, anns in node_anns.items():
        anns.sort(key=lambda x: x["valid_from"])
        prev = None
        for i, a in enumerate(anns):
            is_last = i == len(anns) - 1
            a["valid_to"] = None if is_last else anns[i + 1]["valid_from"]

            if prev is None:
                a["is_data_update"] = True
            else:
                a["is_data_update"] = any(a[f] != prev[f] for f in NODE_ANN_DATA_FIELDS)

            prev = a
            result.append(a)
    return result


# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

def connect_remote() -> tuple:
    load_dotenv(Path(__file__).parent.parent / ".env")

    tunnel = SSHTunnelForwarder(
        (os.getenv('SSH_HOST'), 22),
        ssh_username=os.getenv('SSH_USER'),
        ssh_password=os.getenv('SSH_PASSWORD'),
        remote_bind_address=('127.0.0.1', 5432),  
        local_bind_address=('127.0.0.1', 0),     
        set_keepalive=60
    )
    
    tunnel.start()
    print(f"SSH Tunnel established. Local port mapped to: {tunnel.local_bind_port}")
    
    for key in ('SSH_HOST', 'SSH_USER', 'SSH_PASSWORD', 'POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DBNAME'):
      if not os.getenv(key):                                                                                                                                 
          raise EnvironmentError(f"Missing required env variable: {key}") 

    conn = psycopg2.connect(
        host="127.0.0.1",
        port=tunnel.local_bind_port,
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        dbname=os.getenv("POSTGRES_DBNAME"),
    )
    conn.autocommit = False
    return conn, tunnel

def connect_local():
    load_dotenv(Path(__file__).parent.parent / ".env")

    # Check only for Postgres variables
    for key in ('POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_DBNAME'):
        if not os.getenv(key):                                                                                                                                 
            raise EnvironmentError(f"Missing required env variable: {key}") 

    # Connect directly to the local PostgreSQL instance
    conn = psycopg2.connect(
        host="127.0.0.1",
        port=5432,
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        dbname=os.getenv("POSTGRES_DBNAME"),
    )
    conn.autocommit = False
    
    return conn

# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------

def insert_batch(cur, sql: str, rows: list, batch_size: int = BATCH_SIZE):
    total_rows = len(rows)
    start_time = time.time()
    processed_rows = 0

    for i in range(0, total_rows, batch_size):
        batch = rows[i : i + batch_size]
        batch_start = time.time()
        
        # Execute the batch
        psycopg2.extras.execute_values(cur, sql, batch, page_size=batch_size)
        
        # Metrics Calculation
        batch_duration = time.time() - batch_start
        processed_rows += len(batch)
        percent_complete = (processed_rows / total_rows) * 100
        
        # Predictive Logic
        elapsed_time = time.time() - start_time
        avg_time_per_row = elapsed_time / processed_rows
        remaining_rows = total_rows - processed_rows
        predicted_remaining_seconds = avg_time_per_row * remaining_rows

        log.info(
            f"Progress: {percent_complete:.2f}% | "
            f"Batch took: {batch_duration:.2f}s | "
            f"ETA: {predicted_remaining_seconds / 60:.2f} min remaining"
        )


# ---------------------------------------------------------------------------
# Insert routines
# ---------------------------------------------------------------------------

def insert_gossip_inventory(cur, channels: dict, chan_updates: list, node_anns: list):
    log.info("Inserting gossip_inventory …")
    rows = []

    for gid, c in channels.items():
        rows.append((gid, 256, ts_to_dt(c["record_ts"])))

    for u in chan_updates:
        rows.append((u["gossip_id"], 258, ts_to_dt(u["record_ts"])))

    for a in node_anns:
        rows.append((a["gossip_id"], 257, ts_to_dt(a["record_ts"])))

    sql = """
        INSERT INTO gossip_inventory (gossip_id, type, first_seen_at)
        VALUES %s
        ON CONFLICT (gossip_id) DO NOTHING
    """
    insert_batch(cur, sql, rows)
    log.info("  gossip_inventory: %d rows", len(rows))


def insert_nodes(cur, nodes: dict):
    log.info("Inserting nodes …")
    rows = [(nid, v["first_seen"], v["last_seen"]) for nid, v in nodes.items()]
    sql = """
        INSERT INTO nodes (node_id, first_seen, last_seen)
        VALUES %s
        ON CONFLICT (node_id) DO UPDATE SET
            first_seen = LEAST(nodes.first_seen, EXCLUDED.first_seen),
            last_seen  = GREATEST(nodes.last_seen, EXCLUDED.last_seen)
    """
    insert_batch(cur, sql, rows)
    log.info("  nodes: %d rows", len(rows))


def insert_channels(cur, channels: dict):
    log.info("Inserting channels …")
    rows = [
        (
            c["gossip_id"],
            c["scid"],
            c["capacity_sat"],
            c["source_node_id"],
            c["target_node_id"],
            c["chain_hash"],
            c["node_signature_1"],
            c["node_signature_2"],
            c["bitcoin_signature_1"],
            c["bitcoin_signature_2"],
            c["bitcoin_key_1"],
            c["bitcoin_key_2"],
            c["features"],
            c["raw"],
        )
        for c in channels.values()
    ]
    sql = """
        INSERT INTO channels (
            gossip_id, scid, capacity_sat,
            source_node_id, target_node_id,
            chain_hash,
            node_signature_1, node_signature_2,
            bitcoin_signature_1, bitcoin_signature_2,
            bitcoin_key_1, bitcoin_key_2,
            features, raw_gossip
        )
        VALUES %s
        ON CONFLICT (scid) DO NOTHING
    """
    insert_batch(cur, sql, rows)
    log.info("  channels: %d rows", len(rows))


def insert_channel_updates(cur, chan_updates: list):
    log.info("Inserting channel_updates …")
    # direction is bit(1) in postgres; pass as int and cast via template
    rows = [
        (
            u["gossip_id"],
            u["scid"],
            u["direction"],   # int 0 or 1, cast to bit below
            u["valid_from"],
            u["valid_to"],
            u["chain_hash"],
            u["message_flags"],
            u["channel_flags"],
            u["cltv_expiry_delta"],
            u["htlc_minimum_msat"],
            u["fee_base_msat"],
            u["fee_proportional_millionths"],
            u["htlc_maximum_msat"],
            u["is_fee_update"],
            u["is_topology_update"],
            u["raw"],
        )
        for u in chan_updates
    ]
    # %s::bit casts the direction integer to bit(1)
    sql = """
        INSERT INTO channel_updates (
            gossip_id, scid, direction,
            valid_from, valid_to,
            chain_hash, message_flags, channel_flags,
            cltv_expiry_delta, htlc_minimum_msat,
            fee_base_msat, fee_proportional_millionths, htlc_maximum_msat,
            is_fee_update, is_topology_update,
            raw_gossip
        )
        VALUES %s
        ON CONFLICT (gossip_id) DO NOTHING
    """
    template = "(%s, %s, %s::bit, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    for i in range(0, len(rows), BATCH_SIZE):
        psycopg2.extras.execute_values(
            cur, sql, rows[i : i + BATCH_SIZE],
            template=template, page_size=BATCH_SIZE,
        )
    log.info("  channel_updates: %d rows", len(chan_updates))


def insert_node_announcements(cur, node_anns: list):
    log.info("Inserting node_announcements …")
    rows = [
        (
            a["gossip_id"],
            a["node_id"],
            a["valid_from"],
            a["valid_to"],
            a["alias"],
            a["rgb_color"],
            a["features"],
            a["is_data_update"],
            a["raw"],
        )
        for a in node_anns
    ]
    sql = """
        INSERT INTO node_announcements (
            gossip_id, node_id,
            valid_from, valid_to,
            alias, rgb_color, features,
            is_data_update, raw_gossip
        )
        VALUES %s
        ON CONFLICT (gossip_id) DO NOTHING
    """
    insert_batch(cur, sql, rows)
    log.info("  node_announcements: %d rows", len(rows))


def insert_node_addresses(cur, node_anns: list):
    log.info("Inserting node_addresses …")
    rows = []
    gossip_ids = []
    for a in node_anns:
        for addr in a["addresses"]:
            rows.append((a["gossip_id"], addr.typ.id, addr.addr, addr.port))
        gossip_ids.append(a["gossip_id"])

    # Delete stale rows for any gossip_ids we're about to insert (idempotent re-runs)
    cur.execute(
        "DELETE FROM node_addresses WHERE gossip_id = ANY(%s)",
        (gossip_ids,),
    )

    sql = """
        INSERT INTO node_addresses (gossip_id, type_id, address, port)
        VALUES %s
    """
    insert_batch(cur, sql, rows)
    log.info("  node_addresses: %d rows", len(rows))


def backfill_internal_ids(cur):
    """Fill internal_id in content tables from gossip_inventory after insert."""
    log.info("Backfilling internal_ids …")
    for table in ("channels", "channel_updates", "node_announcements"):
        cur.execute(f"""
            UPDATE {table} t
            SET internal_id = gi.internal_id
            FROM gossip_inventory gi
            WHERE t.gossip_id = gi.gossip_id
              AND t.internal_id IS NULL
        """)
        log.info("  %s: %d rows updated", table, cur.rowcount)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    channels, raw_chan_updates, raw_node_anns, nodes = collect_messages(GOSSIP_STORE_PATH)

    log.info("Pass 2: computing SCD fields …")
    chan_updates = compute_channel_update_scd(raw_chan_updates)
    node_anns = compute_node_ann_scd(raw_node_anns)
    log.info(
        "  %d channel_updates, %d node_announcements ready for insert",
        len(chan_updates), len(node_anns),
    )
    if IS_LOCAL:
        conn = connect_local()
    else:
        conn, tunnel = connect_remote()
    try:
        with conn.cursor() as cur:
            insert_gossip_inventory(cur, channels, chan_updates, node_anns)
            conn.commit()

            insert_nodes(cur, nodes)
            conn.commit()

            insert_channels(cur, channels)
            conn.commit()

            insert_channel_updates(cur, chan_updates)
            conn.commit()

            insert_node_announcements(cur, node_anns)
            conn.commit()

            insert_node_addresses(cur, node_anns)
            conn.commit()

            backfill_internal_ids(cur)
            conn.commit()

        log.info("Import complete.")
    except Exception:
        conn.rollback()
        log.exception("Import failed — rolled back.")
        raise
    finally:
        conn.close()
        if not IS_LOCAL:
            tunnel.stop()


if __name__ == "__main__":
    main()
