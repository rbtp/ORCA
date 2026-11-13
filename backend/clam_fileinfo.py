"""Hashes and file facts of a file ClamAV flagged, for the in-container scan
(the agent does the same in orca_agent.py)."""
import datetime
import hashlib
import os


def threat_file_info(threat_line: str) -> dict:
    body = threat_line[:-len(" FOUND")] if threat_line.endswith(" FOUND") else threat_line
    path, _, sig = body.rpartition(": ")
    info = {"path": path or body, "signature": sig}

    def ts(x):
        return datetime.datetime.fromtimestamp(x, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        st = os.stat(info["path"])
        info.update(size=st.st_size, modified=ts(st.st_mtime), created=ts(st.st_ctime))
        h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
        with open(info["path"], "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                for x in h.values():
                    x.update(chunk)
        info.update({k: x.hexdigest() for k, x in h.items()})
    except OSError as e:
        info["error"] = f"could not read the file to hash it ({e.strerror or e}); it may have been removed or quarantined"
    return info
