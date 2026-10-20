"""
Bayora Cryptographic Ledger & Merkle Tree Module
Implements sequential SHA-256 hash chaining: H_n = SHA-256(H_{n-1} || D_n)
and binary Merkle tree inclusion proof generation.
"""

import hashlib
import time
from typing import List, Dict, Any, Optional

class LedgerManager:
    def __init__(self):
        self.entries: List[Dict[str, Any]] = []
        self._genesis()

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _genesis(self):
        # Genesis block anchor
        prev_hash = "0" * 64
        genesis_data = "0|1970-01-01 00:00:00|GENESIS_PAYLOAD|GENESIS_RESPONSE|100"
        entry_hash = self._hash(prev_hash + genesis_data)
        self.entries.append({
            "index": 0,
            "timestamp": "1970-01-01 00:00:00",
            "prompt": "GENESIS_PAYLOAD",
            "response": "GENESIS_RESPONSE",
            "payload_hash": self._hash("GENESIS_PAYLOAD"),
            "response_hash": self._hash("GENESIS_RESPONSE"),
            "score": 100,
            "salt": "0x0000000000000000",
            "prev_hash": prev_hash,
            "entry_hash": entry_hash
        })

    def build_merkle_tree(self) -> Dict[str, Any]:
        if not self.entries:
            return {"root": "0x" + "0" * 64, "levels": []}

        current_level = [e["entry_hash"] for e in self.entries]
        levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = self._hash(current_level[i] + current_level[i + 1])
                    next_level.append(combined)
                else:
                    combined = self._hash(current_level[i] + current_level[i])
                    next_level.append(combined)
            levels.append(next_level)
            current_level = next_level

        return {
            "root": "0x" + current_level[0],
            "levels": levels
        }

    async def append_entry(self, prompt: str, response: str, score: int, salt: str) -> Dict[str, Any]:
        prev_block = self.entries[-1]
        prev_hash = prev_block["entry_hash"]
        
        idx = len(self.entries)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        payload_hash = self._hash(prompt)
        response_hash = self._hash(response)

        data = f"{idx}|{ts}|{payload_hash}|{response_hash}|{score}"
        entry_hash = self._hash(prev_hash + data)

        record = {
            "index": idx,
            "timestamp": ts,
            "prompt": prompt,
            "response": response,
            "payload_hash": payload_hash,
            "response_hash": response_hash,
            "score": score,
            "salt": salt,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash
        }
        self.entries.append(record)

        tree = self.build_merkle_tree()
        record["merkle_root"] = tree["root"]
        return record

    async def get_inclusion_proof(self, leaf_index: int) -> Optional[Dict[str, Any]]:
        if leaf_index < 0 or leaf_index >= len(self.entries):
            return None

        tree = self.build_merkle_tree()
        proof = []
        idx = leaf_index

        for level_idx in range(len(tree["levels"]) - 1):
            level = tree["levels"][level_idx]
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            sibling_hash = level[sibling_idx] if sibling_idx < len(level) else level[idx]

            proof.append({
                "position": "LEFT" if is_right else "RIGHT",
                "hash": sibling_hash,
                "level": level_idx
            })
            idx = idx // 2

        return {
            "leaf_index": leaf_index,
            "leaf_hash": "0x" + self.entries[leaf_index]["entry_hash"],
            "merkle_root": tree["root"],
            "siblings": proof,
            "valid": True
        }

    async def verify_chain_integrity(self) -> Dict[str, Any]:
        prev = "0" * 64
        for i, entry in enumerate(self.entries):
            data = f"{entry['index']}|{entry['timestamp']}|{entry['payload_hash']}|{entry['response_hash']}|{entry['score']}"
            computed = self._hash(entry['prev_hash'] + data)
            if entry['prev_hash'] != prev or computed != entry['entry_hash']:
                return {
                    "valid": False,
                    "broken_at_index": i,
                    "stored_hash": entry['entry_hash'],
                    "computed_hash": computed
                }
            prev = entry['entry_hash']

        return {
            "valid": True,
            "total_blocks": len(self.entries),
            "merkle_root": self.build_merkle_tree()["root"]
        }
