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

A verdict isn't permanent -- VT's detection coverage grows as more engines
see a given sample, so a hash that came back clean or unseen a month ago
isn't necessarily still accurate. Never-checked hashes always take priority,
but once none remain, the oldest verdict past VT_RECHECK_DAYS (default 30)
gets re-checked instead of the worker sitting idle. A re-check that comes
back worse than before logs at WARNING, not INFO.
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
VT_RECHECK_DAYS = float(os.environ.get("VT_RECHECK_DAYS", "30"))  # re-check an existing verdict after this long
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
_IDLE_POLL_SECONDS = 30       # nothing to look up right now -- check again soon
_BACKOFF_SECONDS = 60         # rate-limited / transient error / bad key -- don't hammer

_EVIDENCE_HASH_UNION = """
    SELECT LOWER(raw_data->>'SHA256') AS hash FROM evidence
    WHERE t_code = 'SUSPICIOUS_LOCATIONS_HASH' AND raw_data->>'SHA256' IS NOT NULL
    UNION
    SELECT LOWER(raw_data->>'SHA1') AS hash FROM evidence
    WHERE t_code = 'AMCACHE' AND raw_data->>'SHA1' IS NOT NULL
"""


def _next_unlooked_hash():
    """Priority 1: a hash with no result at all yet. Always takes priority
    over re-checking an existing verdict -- zero information beats stale
    information."""
    with db.engine.connect() as conn:
        row = conn.execute(text(f"""
            SELECT h.hash FROM ({_EVIDENCE_HASH_UNION}) h
            WHERE h.hash IS NOT NULL AND h.hash != ''
              AND NOT EXISTS (SELECT 1 FROM vt_lookups vl WHERE vl.hash = h.hash)
            LIMIT 1
        """)).fetchone()
    return row[0] if row else None


def _next_stale_hash():
    """Priority 2 (only when nothing is brand-new): the oldest-checked
    verdict past VT_RECHECK_DAYS, among hashes still actually referenced by
    current evidence -- a hash's own detection count is not fixed forever,
    more engines flag a given sample as VT's corpus grows, so a "clean" or
    "not seen" verdict from a month ago isn't necessarily still accurate.
    No point re-checking a hash nothing points to anymore, hence the EXISTS
    against evidence rather than just re-checking everything in vt_lookups."""
    with db.engine.connect() as conn:
        row = conn.execute(text(f"""
            SELECT vl.hash FROM vt_lookups vl
            WHERE vl.checked_at < NOW() - (:days || ' days')::interval
              AND EXISTS (SELECT 1 FROM ({_EVIDENCE_HASH_UNION}) h WHERE h.hash = vl.hash)
            ORDER BY vl.checked_at ASC
            LIMIT 1
        """), {"days": VT_RECHECK_DAYS}).fetchone()
    return row[0] if row else None


def _prior_result(hash_value):
    with db.engine.connect() as conn:
        row = conn.execute(text("""
            SELECT status, malicious_count FROM vt_lookups WHERE hash = :h
        """), {"h": hash_value}).fetchone()
    return (row.status, row.malicious_count) if row else (None, None)


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

        prior_status, prior_malicious = _prior_result(hash_value)
        _store_result(hash_value, "found", malicious, suspicious, total)

        # A re-check that got *worse* since we last looked is the whole point
        # of re-checking at all -- worth a distinct, louder log line rather
        # than blending in with routine first-time lookups.
        if prior_status is not None and (prior_malicious or 0) == 0 and malicious > 0:
            logger.warning(
                "[VT] RE-CHECK VERDICT WORSENED: %s... was %s (%s/%s malicious) -- now %d/%d engines flag it malicious",
                hash_value[:12], prior_status, prior_malicious or 0, total, malicious, total,
            )
        else:
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

    logger.info(
        "[VT] Background lookup worker started (1 lookup per %.0fs, re-check after %.0f days)",
        VT_RATE_LIMIT_SECONDS, VT_RECHECK_DAYS,
    )
    async with httpx.AsyncClient() as client:
        while True:
            loop = asyncio.get_event_loop()
            try:
                hash_value = await loop.run_in_executor(None, _next_unlooked_hash)
                is_recheck = False
                if not hash_value:
                    hash_value = await loop.run_in_executor(None, _next_stale_hash)
                    is_recheck = hash_value is not None
            except Exception as e:
                logger.error("[VT] error querying for next hash: %s", e)
                await asyncio.sleep(_BACKOFF_SECONDS)
                continue

            if not hash_value:
                await asyncio.sleep(_IDLE_POLL_SECONDS)
                continue

            if is_recheck:
                logger.info("[VT] re-checking stale verdict for %s...", hash_value[:12])
            resolved = await _lookup_one(client, hash_value)
            await asyncio.sleep(VT_RATE_LIMIT_SECONDS if resolved else _BACKOFF_SECONDS)
