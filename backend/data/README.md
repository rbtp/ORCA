# backend/data/

Reference data that is deliberately **not** vendored into this repo, unlike
everything under `backend/bin/` — updated independently of the app itself,
same reasoning as ClamAV's signature definitions.

## mitre-attack.json

Drop the official MITRE ATT&CK STIX 2.1 bundle here as `mitre-attack.json`
(the Enterprise matrix — `enterprise-attack.json` from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data),
renamed) before first boot, or set `ORCA_MITRE_ATTACK_JSON` to point at it
somewhere else.

On startup, the backend automatically imports this file into
`mitre_groups` / `mitre_software` / `mitre_mitigations` / `mitre_techniques`
/ `mitre_tactics` / `mitre_relationships` — but **only if those tables are
currently empty** (see `mitre_import.auto_import_if_empty` in
`backend/mitre_import.py`). It will not silently overwrite existing data on
every restart.

To load an updated bundle later (a new ATT&CK release), run manually from
inside the backend container:

```
python mitre_import.py /app/data/mitre-attack.json
```

This re-imports even if the tables are already populated — it's an upsert,
matched on each object's own STIX ID, and deliberately leaves
`mitre_techniques.detection_notes` / `kape_targets` untouched (those are
ORCA-specific analyst fields with no equivalent in the raw MITRE data, only
ever set once on first import).

No internet access is required for any of this — the JSON file is read
entirely from local disk.
