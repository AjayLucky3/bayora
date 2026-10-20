"""
Bayora Cryptographic Ledger & Merkle Tree Module
Implements an append-only SQLite storage engine with sequential SHA-256 chaining:
H_n = SHA-256(H_{n-1} || index || timestamp || tenant_id || payload_hash || response_hash || score)
and binary Merkle tree inclusion proof generation.
"""

import hashlib
import os
import sqlite3
import time
from typing import List, Dict, Any, Optional, Tuple


class LedgerManager:
    """
    Append-only tamper-evident audit ledger backed by SQLite.
    Provides sequential cryptographic chaining and Merkle tree root computation.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("LEDGER_DB_PATH", "ledger.db")
        # Ensure parent directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable Write-Ahead Logging for concurrent read/write isolation
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        return conn

    @staticmethod
    def _sha256(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _init_db(self) -> None:
        """Initializes the SQLite schema and anchors the Genesis block if empty."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ledger (
                    block_index INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    response_hash TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    nonce TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
            """)
            conn.commit()

            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS cnt FROM ledger;")
            count = cursor.fetchone()["cnt"]

            if count == 0:
                # Anchor Genesis Block (Block #0)
                genesis_prev = "0" * 64
                genesis_ts = "1970-01-01 00:00:00"
                genesis_tenant = "tenant-genesis"
                genesis_payload = "0" * 64
                genesis_response = "0" * 64
                genesis_score = 100
                genesis_nonce = "0x00000000000000000000000000000000"

                genesis_data = f"0|{genesis_ts}|{genesis_tenant}|{genesis_payload}|{genesis_response}|{genesis_score}"
                genesis_hash = self._sha256(genesis_prev + genesis_data)

                conn.execute("""
                    INSERT INTO ledger (
                        block_index, timestamp, tenant_id, payload_hash,
                        response_hash, score, nonce, prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    0, genesis_ts, genesis_tenant, genesis_payload,
                    genesis_response, genesis_score, genesis_nonce,
                    genesis_prev, genesis_hash
                ))
                conn.commit()

    def append_entry(
        self,
        tenant_id: str,
        payload_hash: str,
        response_hash: str,
        score: int,
        nonce: str
    ) -> Dict[str, Any]:
        """
        Appends an immutable block to the ledger sequentially.
        Enforces atomic sequence numbering and cryptographic parent chaining.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT block_index, entry_hash FROM ledger
                ORDER BY block_index DESC LIMIT 1;
            """)
            last_row = cursor.fetchone()
            if not last_row:
                raise RuntimeError("Ledger uninitialized: Genesis block missing.")

            prev_index = last_row["block_index"]
            prev_hash = last_row["entry_hash"]

            new_index = prev_index + 1
            now_iso = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            
            data_str = f"{new_index}|{now_iso}|{tenant_id}|{payload_hash}|{response_hash}|{score}"
            entry_hash = self._sha256(prev_hash + data_str)

            conn.execute("""
                INSERT INTO ledger (
                    block_index, timestamp, tenant_id, payload_hash,
                    response_hash, score, nonce, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                new_index, now_iso, tenant_id, payload_hash,
                response_hash, score, nonce, prev_hash, entry_hash
            ))
            conn.commit()

        merkle_tree = self.build_merkle_tree()
        return {
            "block_index": new_index,
            "timestamp": now_iso,
            "tenant_id": tenant_id,
            "payload_hash": payload_hash,
            "response_hash": response_hash,
            "score": score,
            "nonce": nonce,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
            "merkle_root": merkle_tree["root"]
        }

    def get_all_entries(self) -> List[Dict[str, Any]]:
        """Returns all ledger records ordered by block index."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM ledger ORDER BY block_index ASC;")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def build_merkle_tree(self) -> Dict[str, Any]:
        """
        Builds a binary Merkle tree across all leaf entry hashes.
        If a level has an odd number of nodes, duplicates the last node.
        Returns the root hash and the tree levels.
        """
        entries = self.get_all_entries()
        if not entries:
            return {"root": "0x" + "0" * 64, "levels": []}

        current_level = [e["entry_hash"] for e in entries]
        levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = self._sha256(current_level[i] + current_level[i + 1])
                    next_level.append(combined)
                else:
                    # Duplicate lone leaf to balance binary tree
                    combined = self._sha256(current_level[i] + current_level[i])
                    next_level.append(combined)
            levels.append(next_level)
            current_level = next_level

        return {
            "root": "0x" + current_level[0],
            "levels": levels
        }

    def get_inclusion_proof(self, leaf_index: int) -> Optional[Dict[str, Any]]:
        """
        Generates an O(log N) binary Merkle inclusion proof for a given block index.
        Returns sibling hashes and their branch position (LEFT / RIGHT).
        """
        entries = self.get_all_entries()
        if leaf_index < 0 or leaf_index >= len(entries):
            return None

        tree = self.build_merkle_tree()
        proof: List[Dict[str, Any]] = []
        idx = leaf_index

        for level_idx in range(len(tree["levels"]) - 1):
            level = tree["levels"][level_idx]
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            sibling_hash = level[sibling_idx] if sibling_idx < len(level) else level[idx]

            proof.append({
                "level": level_idx,
                "position": "LEFT" if is_right else "RIGHT",
                "hash": sibling_hash
            })
            idx = idx // 2

        leaf_hash = entries[leaf_index]["entry_hash"]
        return {
            "leaf_index": leaf_index,
            "leaf_hash": "0x" + leaf_hash,
            "merkle_root": tree["root"],
            "siblings": proof,
            "valid": True
        }

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Validates the entire hash chain from Genesis to tip.
        Asserts that every block's prev_hash matches the prior block's entry_hash
        and recomputes entry_hash from constituent fields.
        """
        entries = self.get_all_entries()
        prev = "0" * 64

        for entry in entries:
            idx = entry["block_index"]
            ts = entry["timestamp"]
            tenant = entry["tenant_id"]
            p_hash = entry["payload_hash"]
            r_hash = entry["response_hash"]
            score = entry["score"]

            data_str = f"{idx}|{ts}|{tenant}|{p_hash}|{r_hash}|{score}"
            expected_hash = self._sha256(entry["prev_hash"] + data_str)

            if entry["prev_hash"] != prev or expected_hash != entry["entry_hash"]:
                return {
                    "valid": False,
                    "broken_at_index": idx,
                    "stored_hash": entry["entry_hash"],
                    "computed_hash": expected_hash,
                    "reason": "Cryptographic hash mismatch or parent pointer broken."
                }
            prev = entry["entry_hash"]

        merkle_info = self.build_merkle_tree()
        return {
            "valid": True,
            "total_blocks": len(entries),
            "merkle_root": merkle_info["root"]
        }
