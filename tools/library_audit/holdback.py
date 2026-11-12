"""Shared: techniques whose repair is held back (WORK\\floods.json written by floods.py)."""
import json, os

def held_back(work):
    p = os.path.join(work, "floods.json")
    if not os.path.exists(p):
        return {}
    return json.load(open(p, encoding="utf-8")).get("held_back", {})
