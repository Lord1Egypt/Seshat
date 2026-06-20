"""Address → verified-source fetch via the Etherscan V2 unified API.

This is the **only** part of Seshat that may touch the network, and only when
explicitly asked (``online=True``). Every fetch is cached to disk; a cached
address is served offline forever unless ``force=True``. With ``online=False``
and no cache, it raises rather than silently reaching out.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

from .chains import get_chain

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "seshat" / "explorer"
_API_V2 = "https://api.etherscan.io/v2/api"


class ExplorerError(RuntimeError):
    pass


def _cache_path(cache_dir: Path, chain_key: str, address: str) -> Path:
    # Address is fixed-length & filesystem-safe; partition by chain then address.
    return cache_dir / chain_key.lower() / f"{address.lower()}.json"


def fetch_sourcecode(
    chain_key: str,
    address: str,
    *,
    api_key: str | None = None,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    online: bool = False,
    force: bool = False,
) -> dict:
    """Return the explorer's ``getsourcecode`` result dict for an address.

    Reads cache first. Only contacts the network when ``online`` is True and the
    entry is missing (or ``force``). Raises :class:`ExplorerError` when offline
    with nothing cached.
    """
    chain = get_chain(chain_key)
    if chain is None:
        raise ExplorerError(f"unknown chain '{chain_key}'")
    address = address.lower()
    cache_dir = Path(cache_dir)
    cpath = _cache_path(cache_dir, chain.key, address)

    if cpath.exists() and not force:
        return json.loads(cpath.read_text(encoding="utf-8"))

    if not online:
        raise ExplorerError(
            f"{chain.key}:{address} not cached and --online not set "
            f"(offline-first; pass online=True to fetch)"
        )

    result = _http_get_sourcecode(chain.chain_id, address, api_key)
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cpath.write_text(json.dumps(result), encoding="utf-8")
    return result


def _http_get_sourcecode(chain_id: int, address: str, api_key: str | None) -> dict:
    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key or "YourApiKeyToken",
    }
    url = f"{_API_V2}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "seshat/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (https only)
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # network/JSON errors → uniform error type
        raise ExplorerError(f"explorer request failed: {exc}") from exc

    if str(payload.get("status")) != "1" or not payload.get("result"):
        raise ExplorerError(
            f"explorer returned no source: {payload.get('message') or payload}"
        )
    result = payload["result"]
    return result[0] if isinstance(result, list) else result


def extract_source_payload(result: dict) -> tuple[str, str | None]:
    """From a ``getsourcecode`` result, return ``(source_text, contract_name)``.

    ``source_text`` is whatever the explorer stored (flat Solidity, Standard-JSON,
    or the ``{{…}}`` wrapper) — the normalizer handles every form.
    """
    source = result.get("SourceCode") or result.get("sourceCode") or ""
    name = result.get("ContractName") or result.get("contractName") or None
    return source, name


def is_verified(result: dict) -> bool:
    return bool(result.get("SourceCode") or result.get("sourceCode"))
