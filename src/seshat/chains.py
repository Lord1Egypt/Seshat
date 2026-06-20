"""EVM chain registry.

Maps a stable string ``key`` to a display name and EVM ``chain_id``. The set
mirrors MaatEye's coverage so registry imports line up. Used by ingestion (to
seed the ``chains`` table) and by the explorer fetcher (chain_id for the API).
"""

from __future__ import annotations

import sqlite3
from typing import NamedTuple


class ChainInfo(NamedTuple):
    key: str
    name: str
    chain_id: int


# Stable order; keys are lowercase and match MaatEye.
CHAINS: dict[str, ChainInfo] = {
    c.key: c
    for c in (
        ChainInfo("ethereum", "Ethereum", 1),
        ChainInfo("optimism", "Optimism", 10),
        ChainInfo("bnb", "BNB Chain", 56),
        ChainInfo("gnosis", "Gnosis", 100),
        ChainInfo("polygon", "Polygon", 137),
        ChainInfo("mantle", "Mantle", 5000),
        ChainInfo("base", "Base", 8453),
        ChainInfo("arbitrum", "Arbitrum One", 42161),
        ChainInfo("celo", "Celo", 42220),
        ChainInfo("avalanche", "Avalanche C-Chain", 43114),
        ChainInfo("linea", "Linea", 59144),
        ChainInfo("blast", "Blast", 81457),
        ChainInfo("scroll", "Scroll", 534352),
        ChainInfo("metis", "Metis", 1088),
        ChainInfo("moonbeam", "Moonbeam", 1284),
    )
}


def get_chain(key: str) -> ChainInfo | None:
    return CHAINS.get(key.lower()) if key else None


def ensure_chain(conn: sqlite3.Connection, key: str) -> str:
    """Insert the chain row if missing (idempotent). Returns the normalized key.

    Unknown keys are still stored (name=key, chain_id NULL) so ingestion never
    fails on an unrecognized chain — it just won't have a chain_id.
    """
    key = key.lower()
    info = CHAINS.get(key)
    if info is not None:
        conn.execute(
            "INSERT OR IGNORE INTO chains (key, name, chain_id) VALUES (?, ?, ?)",
            (info.key, info.name, info.chain_id),
        )
    else:
        conn.execute(
            "INSERT OR IGNORE INTO chains (key, name, chain_id) VALUES (?, ?, NULL)",
            (key, key),
        )
    return key
