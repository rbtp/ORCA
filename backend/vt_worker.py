"""
vt_worker.py

Background worker that looks up file hashes (surfaced by the AMCACHE and
SUSPICIOUS_LOCATIONS_HASH collection techniques) against the VirusTotal API,
respecting the free-tier rate limit. Runs continuously once started from
main.py's startup hook; disabled entirely (logs once, returns) if VT_API_KEY
isn't set.

Keyed globally by hash in vt_lookups (see migrations/add_vt_lookups.sql) --
no separate queue table: "not yet looked up" is just "missing from
vt_lookups", discovered by scanning evidence directly each cycle.
"""
import os
import asyncio
import logging

import httpx
from sqlalchemy import text

from core.database_manager import db

logger = logging.getLogger(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
VT_RATE_LIMIT_SECONDS = float(os.environ.get("VT_RATE_LIMIT_SECONDS", "16"))  # free tier is 4/min; 16s leaves margin
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
_IDLE_POLL_SECONDS = 30       # nothing to look up right now -- check again soon
_BACKOFF_SECONDS = 60         # rate-limited / transient error / bad key -- don't hammer


def _next_unlooked_hash():
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT h.hash FROM (
                SELECT LOWER(raw_data->>'SHA256') AS hash FROM evidence
                WHERE t_code = 'SUSPICIOUS_LOCATIONS_HASH' AND raw_data->>'SHA256' IS NOT NULL
                UNION
                SELECT LOWER(raw_data->>'SHA1') AS hash FROM evidence
                WHERE t_code = 'AMCACHE' AND raw_data->>'SHA1' IS NOT NULL
            ) h
            WHERE h.hash IS NOT NULL AND h.hash != ''
              AND NOT EXISTS (SELECT 1 FROM vt_lookups vl WHERE vl.hash = h.hash)
            LIMIT 1
        """)).fetchone()
    return row[0] if row else None


def _store_result(hash_value, status, malicious=None, suspicious=None, total=None):
    with db.engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO vt_lookups (hash, status, malicious_count, suspicious_count, total_engines, checked_at)
            VALUES (:h, :s, :m, :sp, :t, NOW())
            ON CONFLICT (hash) DO UPDATE SET
                status = EXCLUDED.status, malicious_count = EXCLUDED.malicious_count,
                suspicious_count = EXCLUDED.suspicious_count, total_engines = EXCLUDED.total_engines,
                checked_at = NOW()
        """), {"h": hash_value, "s": status, "m": malicious, "sp": suspicious, "t": total})


async def _lookup_one(client: httpx.AsyncClient, hash_value: str) -> bool:
    """Returns True if this hash was resolved (write a permanent vt_lookups row --
    found or genuinely not_found) and should never be retried; False if this
    attempt didn't resolve anything (rate-limited, bad key, network hiccup) and
    the hash should be picked up again on a later cycle instead."""
    try:
        resp = await client.get(
            f"{VT_BASE_URL}/{hash_value}", headers={"x-apikey": VT_API_KEY}, timeout=30.0
        )
    except (httpx.TimeoutException, httpx.NetworkError) as e:
        logger.warning("[VT] network error for %s...: %s (will retry)", hash_value[:12], e)
        return False

    if resp.status_code == 200:
        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        _store_result(hash_value, "found", malicious, suspicious, total)
        logger.info("[VT] %s... -> %d/%d engines flagged malicious", hash_value[:12], malicious, total)
        return True

    if resp.status_code == 404:
        # A real, useful answer -- VT has never seen this hash -- not a failure.
        _store_result(hash_value, "not_found")
        return True

    if resp.status_code == 429:
        logger.warning("[VT] rate limit hit -- backing off")
        return False

    if resp.status_code in (401, 403):
        logger.error("[VT] API key rejected (HTTP %d) -- check VT_API_KEY; worker will keep retrying", resp.status_code)
        return False

    logger.warning("[VT] unexpected status %d for %s... (will retry)", resp.status_code, hash_value[:12])
    return False


async def run_forever():
    if not VT_API_KEY:
        logger.info("[VT] VT_API_KEY not set -- background lookup worker disabled")
        return

    logger.info("[VT] Background lookup worker started (1 lookup per %.0fs)", VT_RATE_LIMIT_SECONDS)
    async with httpx.AsyncClient() as client:
        while True:
            try:
                hash_value = await asyncio.get_event_loop().run_in_executor(None, _next_unlooked_hash)
            except Exception as e:
                logger.error("[VT] error querying for next hash: %s", e)
                await asyncio.sleep(_BACKOFF_SECONDS)
                continue

            if not hash_value:
                await asyncio.sleep(_IDLE_POLL_SECONDS)
                continue

            resolved = await _lookup_one(client, hash_value)
            await asyncio.sleep(VT_RATE_LIMIT_SECONDS if resolved else _BACKOFF_SECONDS)
