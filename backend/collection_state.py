"""Assets deleted while a collection may still be running for them.

Deleting a case/asset marks its ids here; the collection runners in main.py
check it before starting each technique and before saving its results, so a
collection still running for a deleted asset stops instead of writing rows
for an asset that no longer exists. Its own module because main.py runs as
__main__ (python main.py) and routes can't import it without loading a
second copy. Asset ids come from a sequence and are never reused, so ids
are never removed from the set.
"""
import threading

_lock = threading.Lock()
_deleted: set = set()


def mark_deleted(asset_ids):
    with _lock:
        _deleted.update(int(a) for a in asset_ids)


def is_deleted(asset_id) -> bool:
    try:
        a = int(asset_id)
    except (TypeError, ValueError):
        return False
    with _lock:
        return a in _deleted
