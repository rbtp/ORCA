import json
import time
import os
from sqlalchemy import text
from core.database_manager import db

import re as _re

_TRIAGE_PATTERNS = [
    (_re.compile(r'Microsoft-Windows-Sysmon', _re.I),          'EVENT_LOGS_SYSMON'),
    (_re.compile(r'Security\.evtx',           _re.I),          'EVENT_LOGS_SECURITY'),
    (_re.compile(r'Application\.evtx',        _re.I),          'EVENT_LOGS_APPLICATION'),
    (_re.compile(r'System\.evtx',             _re.I),          'EVENT_LOGS_SYSTEM'),
    (_re.compile(r'PowerShell',               _re.I),          'EVENT_LOGS_POWERSHELL'),
    (_re.compile(r'TaskScheduler',            _re.I),          'EVENT_LOGS_TASKSCHEDULER'),
    (_re.compile(r'WMI.Activity',             _re.I),          'EVENT_LOGS_WMI'),
    (_re.compile(r'WinRM',                    _re.I),          'EVENT_LOGS_WINRM'),
    (_re.compile(r'Prefetch',                 _re.I),          'PREFETCH'),
    (_re.compile(r'\$MFT|\$J|\$LogFile',      _re.I),          'MFT'),
    (_re.compile(r'\\SAM$|/SAM$',             _re.I),          'REGISTRY_SAM'),
    (_re.compile(r'\\SYSTEM$|/SYSTEM$',       _re.I),          'REGISTRY_SYSTEM'),
    (_re.compile(r'\\SOFTWARE$|/SOFTWARE$',   _re.I),          'REGISTRY_SOFTWARE'),
    (_re.compile(r'\\SECURITY$|/SECURITY$',   _re.I),          'REGISTRY_SECURITY'),
    (_re.compile(r'NTUSER\.DAT',              _re.I),          'REGISTRY_NTUSER'),
    (_re.compile(r'UsrClass\.dat',            _re.I),          'REGISTRY_USRCLASS'),
    (_re.compile(r'Amcache',                  _re.I),          'AMCACHE'),
    (_re.compile(r'Chrome',                   _re.I),          'BROWSER_CHROME'),
    (_re.compile(r'Edge|MicrosoftEdge',       _re.I),          'BROWSER_EDGE'),
    (_re.compile(r'Firefox',                  _re.I),          'BROWSER_FIREFOX'),
    (_re.compile(r'LNK|JumpList|AutomaticDest', _re.I),        'LNK_JUMPLISTS'),
    (_re.compile(r'ScheduledTask',            _re.I),          'SCHEDULED_TASKS'),
    (_re.compile(r'WMI|\.mof\b',             _re.I),          'WMI_PERSISTENCE'),
    (_re.compile(r'SRUM',                     _re.I),          'SRUM'),
    (_re.compile(r'Recycle',                  _re.I),          'RECYCLE_BIN'),
    (_re.compile(r'USB|usbstor|setupapi',     _re.I),          'USB_ARTIFACTS'),
]

# Browser sub-routing by profile path
_BROWSER_PATTERNS = [
    (_re.compile(r'Chrome',        _re.I), 'BROWSER_CHROME'),
    (_re.compile(r'Edge',          _re.I), 'BROWSER_EDGE'),
    (_re.compile(r'Firefox',       _re.I), 'BROWSER_FIREFOX'),
]

# Registry sub-routing by hive path or key
_REGISTRY_PATTERNS = [
    (_re.compile(r'\\SAM$|/SAM$|HKLM.*/SAM',           _re.I), 'REGISTRY_SAM'),
    (_re.compile(r'\\SYSTEM$|/SYSTEM$|HKLM.*/SYSTEM',  _re.I), 'REGISTRY_SYSTEM'),
    (_re.compile(r'\\SOFTWARE$|/SOFTWARE$|HKLM.*/SOFTWARE', _re.I), 'REGISTRY_SOFTWARE'),
    (_re.compile(r'\\SECURITY$|/SECURITY$',             _re.I), 'REGISTRY_SECURITY'),
    (_re.compile(r'NTUSER\.DAT|HKCU|HKU',               _re.I), 'REGISTRY_NTUSER'),
    (_re.compile(r'UsrClass\.dat',                      _re.I), 'REGISTRY_USRCLASS'),
]

# Registry artifact t_codes
_REGISTRY_TCODES = {
    'REGISTRY_SAM', 'REGISTRY_SYSTEM', 'REGISTRY_SOFTWARE', 'REGISTRY_SECURITY',
    'REGISTRY_NTUSER', 'REGISTRY_USRCLASS',
    'REGISTRY_CLASSES_ROOT', 'REGISTRY_CURRENT_CONFIG',
}

# Direct t_code → artifact index category mapping (1:1 parsers)
_TCODE_TO_CATEGORY = {
    'TRIAGE_PREFETCH': 'PREFETCH',
    'TRIAGE_MFT':      'MFT',
    'TRIAGE_LNK':      'LNK_JUMPLISTS',
    'TRIAGE_TASKS':    'SCHEDULED_TASKS',
    'TRIAGE_WMI':      'WMI_PERSISTENCE',
    'TRIAGE_SRUM':     'SRUM',
    'TRIAGE_RECYCLE':  'RECYCLE_BIN',
    'TRIAGE_USB':      'USB_ARTIFACTS',
}


def _parse_reg_values(raw):
    """Convert any serialization of a registry values field to a list of dicts."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        # Velociraptor sometimes serializes Go slices as {"0": {...}, "1": {...}}
        try:
            return [raw[str(i)] for i in range(len(raw)) if str(i) in raw] or list(raw.values())
        except Exception:
            return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            pass
    return []


_REGISTRY_ROW_META_KEYS = {
    'Key', '_Source', 'KeyPath', 'KeyModTime', 'Values', 'FullPath', 'ModTime',
    'ValueName', 'ValueType', 'ValueData',
}


def _values_from_row_columns(item):
    """
    read_reg_key()'s actual output has no Key.Values array — each named registry
    value under a key comes back as its own dynamically-named top-level column on
    the row, alongside Key (path/modtime only). Build a values list from those.
    """
    return [{'Name': k, 'Type': '', 'Data': v}
            for k, v in item.items() if k not in _REGISTRY_ROW_META_KEYS]


def _extract_registry_row(item):
    """
    Normalize a single row into (key_path, mod_time, values).

    Handles VQL output shapes:
    1. Per-value foreach shape: {KeyPath, KeyModTime, ValueName, ValueType, ValueData}
       One row per registry value — produced by the foreach VQL.
    2. Per-key explicit SELECT: {KeyPath, KeyModTime, Values: [{Name, Type, Data}...]}
       One row per key with Values as a JSON array (or ordereddict).
    3. Key-blob with flattened value columns: {Key: {FileInfo: {FullPath, ModTime}},
       <ValueName1>: <data1>, <ValueName2>: <data2>, ...} — this is what
       read_reg_key() actually emits; there is no Key.Values field, so any VQL
       selecting Key.Values AS Values silently gets NULL for every row.
    """
    # Shape 1 — per-value row from foreach VQL
    if 'ValueName' in item or 'ValueType' in item or 'ValueData' in item:
        key_path = item.get('KeyPath') or item.get('FullPath') or ''
        mod_time = item.get('KeyModTime') or item.get('ModTime') or ''
        val_name = item.get('ValueName') or ''
        val_type = item.get('ValueType') or ''
        val_data = item.get('ValueData')
        values = [{'Name': val_name, 'Type': val_type, 'Data': val_data}] \
            if (val_name or val_data is not None) else []
        return key_path, mod_time, values

    # Shape 3 — Key blob present; real values (if any) are sibling top-level
    # columns on the row (see docstring), not nested inside Key.
    key_raw = item.get('Key')
    if key_raw is not None:
        try:
            key_obj = json.loads(key_raw) if isinstance(key_raw, str) else key_raw
            if isinstance(key_obj, dict):
                file_info = key_obj.get('FileInfo', {}) or {}
                key_path = file_info.get('FullPath', '') or item.get('FullPath', '')
                mod_time = file_info.get('ModTime', '') or item.get('ModTime', '')
                values = _parse_reg_values(key_obj.get('Values'))
                if not values:
                    values = _values_from_row_columns(item)
                return key_path, mod_time, values
        except Exception:
            pass

    # Shape 2 — explicit SELECT with KeyPath/KeyModTime/Values at top level, no Key blob
    key_path = item.get('KeyPath') or item.get('FullPath') or ''
    mod_time = item.get('KeyModTime') or item.get('ModTime') or ''
    values = _parse_reg_values(item.get('Values'))
    if not values:
        values = _values_from_row_columns(item)
    return key_path, mod_time, values


def _insert_into_tree(tree, key_path, mod_time, values):
    """
    Insert a single registry key into the nested tree dict.

    key_path looks like: HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control
    Tree nodes are plain dicts; reserved keys:
      _values : list of {name, type, data} — the values at this key
      _meta   : {modtime}
    """
    # Normalise separators and strip leading/trailing slashes
    key_path = key_path.replace('/', '\\').strip('\\')
    parts = key_path.split('\\')

    node = tree
    for part in parts:
        if not part:
            continue
        if part not in node:
            node[part] = {}
        node = node[part]

    node['_meta'] = {'modtime': mod_time}
    if values:
        node['_values'] = values


def _build_registry_tree(rows):
    """
    Convert flat rows into a nested regedit-style tree.

    Works with both per-key rows (one row = one key, Values is a list) and
    per-value rows (one row = one value at a key, from the foreach VQL).
    Multiple rows for the same key_path have their values merged.
    Returns (tree dict, hive_root string).
    """
    tree = {}
    hive_root = ''
    # key_path -> {'mod_time': str, 'values': list}
    key_groups: dict = {}

    for item in rows:
        key_path, mod_time, values = _extract_registry_row(item)
        if not key_path:
            continue
        if not hive_root:
            hive_root = key_path.replace('/', '\\').split('\\')[0]
        if key_path not in key_groups:
            key_groups[key_path] = {'mod_time': mod_time or '', 'values': []}
        elif mod_time and not key_groups[key_path]['mod_time']:
            key_groups[key_path]['mod_time'] = mod_time
        key_groups[key_path]['values'].extend(values)

    for key_path, group in key_groups.items():
        _insert_into_tree(tree, key_path, group['mod_time'], group['values'])

    return tree, hive_root


def _source_to_category(source_file):
    if not source_file:
        return None
    for pattern, category in _TRIAGE_PATTERNS:
        if pattern.search(str(source_file)):
            return category
    return None


def _route_triage_row(t_code, row):
    """Determine the final artifact index category for a triage row."""

    # 1:1 mappings — no sub-routing needed
    if t_code in _TCODE_TO_CATEGORY:
        return _TCODE_TO_CATEGORY[t_code]

    # EVTX — sub-route by Channel field (parsed events have Channel)
    if t_code == 'TRIAGE_EVTX':
        channel = str(row.get('Channel') or row.get('Provider') or row.get('FullPath') or '')
        return _source_to_category(channel)

    # Registry — sub-route by Hive or KeyPath
    if t_code == 'TRIAGE_REG':
        hive = str(row.get('Hive') or row.get('KeyPath') or row.get('FullPath') or '')
        for pattern, category in _REGISTRY_PATTERNS:
            if pattern.search(hive):
                return category
        return None

    # Browser — sub-route by Profile or SourceFile path
    if t_code == 'TRIAGE_BROWSER':
        source = str(row.get('UserName') or row.get('SourceFile') or row.get('FullPath') or '')
        for pattern, category in _BROWSER_PATTERNS:
            if pattern.search(source):
                return category
        return 'BROWSER_CHROME'  # default

    return 'TRIAGE_MISC'


def _normalize_triage(file_path, asset_id, t_code='TRIAGE', is_fallback=False):
    import json, logging
    from sqlalchemy import text
    from core.database_manager import db
    logger = logging.getLogger(__name__)
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        return 0
    rows_by_category = {}
    with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            cat = _route_triage_row(t_code, row)
            if cat is None:
                continue  # unrecognized artifact — drop silently
            rows_by_category.setdefault(cat, []).append(row)
    total = 0
    with db.engine.begin() as conn:
        for category, rows in rows_by_category.items():

            # ── Registry: merge into single REGISTRY row ────────────────────
            if category in _REGISTRY_TCODES:
                new_tree, hive_root = _build_registry_tree(rows)
                row_count = len(rows)

                existing = conn.execute(text("""
                    SELECT id, raw_data FROM evidence
                    WHERE asset_id = :aid AND t_code = 'REGISTRY'
                    LIMIT 1
                """), {"aid": asset_id}).fetchone()

                if existing:
                    try:
                        doc = json.loads(existing.raw_data) if isinstance(existing.raw_data, str) else existing.raw_data
                    except Exception:
                        doc = {"tree": {}, "key_count": 0, "hives": []}
                    def deep_merge(base, incoming):
                        for k, v in incoming.items():
                            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                                deep_merge(base[k], v)
                            else:
                                base[k] = v
                    deep_merge(doc["tree"], new_tree)
                    doc["key_count"] = doc.get("key_count", 0) + row_count
                    if hive_root and hive_root not in doc.get("hives", []):
                        doc.setdefault("hives", []).append(hive_root)
                    conn.execute(text("""
                        UPDATE evidence SET raw_data = :raw WHERE id = :id
                    """), {"raw": json.dumps(doc), "id": existing.id})
                else:
                    doc = {
                        "tree": new_tree,
                        "key_count": row_count,
                        "hives": [hive_root] if hive_root else [],
                    }
                    conn.execute(text("""
                        INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                        VALUES (:aid, 'REGISTRY', 'REGISTRY', 'REGISTRY', :raw)
                    """), {"aid": asset_id, "raw": json.dumps(doc)})

                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, 'REGISTRY', 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET
                        verdict = 'Evidence Found',
                        evidence_summary = EXCLUDED.evidence_summary,
                        evidence_imported = TRUE
                """), {"aid": asset_id, "s": json.dumps({
                    "message": f"Registry: {doc['key_count']} total keys across {len(doc.get('hives', []))} hives",
                })})
                # Mark sub-technique row as processed (merged into REGISTRY rollup)
                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET
                        verdict = 'Evidence Found',
                        evidence_summary = EXCLUDED.evidence_summary,
                        evidence_imported = TRUE
                """), {"aid": asset_id, "t": category, "s": json.dumps({"message": f"{category}: {row_count} keys merged into REGISTRY rollup"})})
                total += 1
                continue

            # ── All other triage artifacts: standard flat ingest ─────────────
            for row in rows:
                flat = {}
                for k, v in row.items():
                    if isinstance(v, dict):
                        for sk, sv in v.items():
                            flat[f"{k}.{sk}"] = sv
                    else:
                        flat[k] = v
                for drop in ('_Source', 'VQLSource', '_orca_fallback', '_orca_fallback_note'):
                    flat.pop(drop, None)

                display_name = (
                    flat.get('FileName') or flat.get('Name') or
                    flat.get('EventID') or flat.get('Channel') or category
                )
                display_path = (
                    flat.get('FullPath') or flat.get('OSPath') or
                    flat.get('Hive') or 'Triage'
                )
                conn.execute(text("""
                    INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                    VALUES (:asset_id, :t_code, :fname, :fpath, :raw)
                """), {
                    "asset_id": asset_id,
                    "t_code": category,
                    "fname": str(display_name)[:255],
                    "fpath": str(display_path)[:512],
                    "raw": json.dumps(flat),
                })
                total += 1
            conn.execute(text("""
                INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                ON CONFLICT (asset_id, t_code)
                DO UPDATE SET
                    verdict = 'Evidence Found',
                    evidence_summary = EXCLUDED.evidence_summary,
                    evidence_imported = TRUE
            """), {
                "aid": asset_id,
                "t": category,
                "s": json.dumps({"message": f"Triage: {len(rows)} records collected"}),
            })
    logger.info("_normalize_triage: asset=%s t_code=%s total=%d categories=%s",
                asset_id, t_code, total, list(rows_by_category.keys()))
    return total


def normalize_and_ingest(file_path, asset_id, t_code, target_name_hint=None, is_fallback=False):
    """
    Standardizes evidence from Velociraptor JSONL output.
    Ensures nested objects are flattened to avoid React [object Object] rendering.
    """
    if t_code == 'TRIAGE' or t_code.startswith('TRIAGE_'):
        return _normalize_triage(file_path, asset_id, t_code, is_fallback)

    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"[-] SKIPPING: {file_path} is empty or missing.")
        return 0

    try:
        # Prevent race conditions with Velociraptor file write
        time.sleep(0.5)

        raw_rows = []
        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    raw_item = json.loads(line)
                    if "_Source" in raw_item and len(raw_item) == 1:
                        continue
                    raw_rows.append(raw_item)
                except Exception as json_err:
                    print(f"[!] JSON PARSE ERROR in {file_path}: {json_err}")

        if not raw_rows:
            return 0

        # ── Registry: merge all hives into one REGISTRY row ─────────────────
        if t_code in _REGISTRY_TCODES:
            new_tree, hive_root = _build_registry_tree(raw_rows)
            row_count = len(raw_rows)
            with db.engine.begin() as conn:
                # Load existing merged tree if present
                existing = conn.execute(text("""
                    SELECT id, raw_data FROM evidence
                    WHERE asset_id = :aid AND t_code = 'REGISTRY'
                    LIMIT 1
                """), {"aid": asset_id}).fetchone()

                if existing:
                    try:
                        doc = json.loads(existing.raw_data) if isinstance(existing.raw_data, str) else existing.raw_data
                    except Exception:
                        doc = {"tree": {}, "key_count": 0, "hives": []}
                    # Deep-merge new hive tree into existing
                    def deep_merge(base, incoming):
                        for k, v in incoming.items():
                            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                                deep_merge(base[k], v)
                            else:
                                base[k] = v
                    deep_merge(doc["tree"], new_tree)
                    doc["key_count"] = doc.get("key_count", 0) + row_count
                    if hive_root and hive_root not in doc.get("hives", []):
                        doc.setdefault("hives", []).append(hive_root)
                    conn.execute(text("""
                        UPDATE evidence SET raw_data = :raw WHERE id = :id
                    """), {"raw": json.dumps(doc), "id": existing.id})
                else:
                    doc = {
                        "tree": new_tree,
                        "key_count": row_count,
                        "hives": [hive_root] if hive_root else [],
                    }
                    conn.execute(text("""
                        INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                        VALUES (:aid, 'REGISTRY', 'REGISTRY', 'REGISTRY', :raw)
                    """), {"aid": asset_id, "raw": json.dumps(doc)})

                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, 'REGISTRY', 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET
                        verdict = 'Evidence Found',
                        evidence_summary = EXCLUDED.evidence_summary,
                        evidence_imported = TRUE
                """), {"aid": asset_id, "s": json.dumps({
                    "message": f"Registry: {doc['key_count']} total keys across {len(doc.get('hives', []))} hives",
                })})
                # Mark sub-technique row as processed (merged into REGISTRY rollup)
                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET
                        verdict = 'Evidence Found',
                        evidence_summary = EXCLUDED.evidence_summary,
                        evidence_imported = TRUE
                """), {"aid": asset_id, "t": t_code, "s": json.dumps({"message": f"{t_code}: {row_count} keys merged into REGISTRY rollup"})})
            print(f"[+] SUCCESS: {t_code} merged into REGISTRY ({row_count} keys, hive={hive_root}).")
            return 1

        # ── MFT: one row per entry in mft_entries table ─────────────────────
        if t_code == 'MFT':
            def _ts(v):
                """Return ISO string or None — strip Velociraptor's trailing precision noise."""
                if not v:
                    return None
                s = str(v).strip()
                # Velociraptor emits e.g. "2023-01-15T10:22:31.123456789Z" — truncate to µs
                if 'T' in s and s.endswith('Z'):
                    s = s[:26] + 'Z' if len(s) > 27 else s
                return s or None

            records = []
            file_count = 0
            meta_count = 0
            for row in raw_rows:
                path = row.get('OSPath') or row.get('FullPath') or ''
                name = row.get('FileName') or ''
                is_meta = name.startswith('$') or (path.startswith('$') and '\\' not in path)
                if is_meta:
                    meta_count += 1
                    continue  # skip $MFT system entries — not useful for analysis
                file_count += 1
                alt_names = row.get('FileNames') or []
                records.append({
                    'asset_id':   asset_id,
                    'entry_num':  row.get('EntryNumber'),
                    'parent_num': row.get('ParentEntryNumber'),
                    'file_name':  name[:512] if name else None,
                    'full_path':  path[:1024] if path else None,
                    'is_dir':     bool(row.get('IsDir')),
                    'in_use':     bool(row.get('InUse')),
                    'has_ads':    bool(row.get('HasADS')),
                    'si_lt_fn':   bool(row.get('SI_Lt_FN')),
                    'copied':     bool(row.get('Copied')),
                    'file_size':  row.get('FileSize') or 0,
                    'alt_names':  json.dumps(alt_names) if alt_names else None,
                    'si_created':  _ts(row.get('Created0x10')),
                    'si_modified': _ts(row.get('LastModified0x10')),
                    'si_accessed': _ts(row.get('LastAccess0x10')),
                    'si_rc':       _ts(row.get('LastRecordChange0x10')),
                    'fn_created':  _ts(row.get('Created0x30')),
                    'fn_modified': _ts(row.get('LastModified0x30')),
                    'fn_accessed': _ts(row.get('LastAccess0x30')),
                })

            BATCH = 5000
            with db.engine.begin() as conn:
                # Clear previous MFT data for this asset
                conn.execute(text("DELETE FROM mft_entries WHERE asset_id = :aid"), {"aid": asset_id})
                conn.execute(text("DELETE FROM evidence WHERE asset_id = :aid AND t_code = 'MFT'"), {"aid": asset_id})

                # Bulk insert in batches
                for i in range(0, max(len(records), 1), BATCH):
                    batch = records[i:i+BATCH]
                    if batch:
                        conn.execute(text("""
                            INSERT INTO mft_entries (
                                asset_id, entry_num, parent_num, file_name, full_path,
                                is_dir, in_use, has_ads, si_lt_fn, copied, file_size, alt_names,
                                si_created, si_modified, si_accessed, si_rc,
                                fn_created, fn_modified, fn_accessed
                            ) VALUES (
                                :asset_id, :entry_num, :parent_num, :file_name, :full_path,
                                :is_dir, :in_use, :has_ads, :si_lt_fn, :copied, :file_size, :alt_names,
                                :si_created, :si_modified, :si_accessed, :si_rc,
                                :fn_created, :fn_modified, :fn_accessed
                            )
                        """), batch)

                # Single sentinel row in evidence so triage_categories picks it up
                conn.execute(text("""
                    INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                    VALUES (:aid, 'MFT', 'MFT', 'MFT', :raw)
                """), {"aid": asset_id, "raw": json.dumps({"file_count": file_count, "meta_count": meta_count})})

                conn.execute(text("""
                    INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                    VALUES (:aid, 'MFT', 'Evidence Found', :s, TRUE)
                    ON CONFLICT (asset_id, t_code)
                    DO UPDATE SET
                        verdict = 'Evidence Found',
                        evidence_summary = EXCLUDED.evidence_summary,
                        evidence_imported = TRUE
                """), {"aid": asset_id, "s": json.dumps({
                    "message": f"MFT: {file_count} files, {meta_count} metadata entries"
                })})

            print(f"[+] SUCCESS: MFT ingested ({file_count} files → mft_entries table).")
            return file_count

        # ── All other artifacts: standard flat ingest ────────────────────────
        evidence_list = []
        for raw_item in raw_rows:
            clean_item = {}
            for k, v in raw_item.items():
                if isinstance(v, (dict, list)):
                    clean_item[k] = json.dumps(v)
                else:
                    clean_item[k] = v

            if is_fallback:
                clean_item["_orca_fallback"] = True
                clean_item["_orca_fallback_note"] = "Primary query returned 0 hits - broad EventID collection for analyst review"

                data_fields = {
                    k: v for k, v in clean_item.items()
                    if not k.startswith("_orca_")
                    and k not in ("System.Computer", "Computer", "COMPUTER")
                }
                if data_fields:
                    empty = sum(
                        1 for v in data_fields.values()
                        if v is None or str(v).strip() in ("", "-", "---", "{}", "[]", "null")
                    )
                    if empty / len(data_fields) > 0.5:
                        continue

            evidence_list.append(clean_item)

        if not evidence_list:
            return 0

        with db.engine.begin() as conn:
            summary_data = {
                "message": (
                    f"Broad Collection (Fallback): {len(evidence_list)} entries - primary query returned 0 hits. Review for relevance."
                    if is_fallback else
                    f"Forensic Hit: {len(evidence_list)} system entries found via {target_name_hint or 'Surgical Logic'}"
                )
            }
            conn.execute(text("""
                INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_summary, evidence_imported)
                VALUES (:aid, :t, 'Evidence Found', :s, TRUE)
                ON CONFLICT (asset_id, t_code)
                DO UPDATE SET
                    verdict = 'Evidence Found',
                    evidence_summary = EXCLUDED.evidence_summary,
                    evidence_imported = TRUE
            """), {"aid": asset_id, "t": t_code, "s": json.dumps(summary_data)})

            for item in evidence_list:
                display_name = (
                    item.get("Name") or item.get("EventID") or item.get("ID") or
                    target_name_hint or "Surgical_Hit"
                )
                display_path = (
                    item.get("KeyPath") or item.get("OSPath") or
                    item.get("FullPath") or "System"
                )
                conn.execute(text("""
                    INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                    VALUES (:aid, :t, :fname, :fpath, :raw)
                """), {
                    "aid": asset_id,
                    "t": t_code,
                    "fname": display_name,
                    "fpath": display_path,
                    "raw": json.dumps(item)
                })

        print(f"[+] SUCCESS: {t_code} ingested correctly ({len(evidence_list)} rows).")
        return len(evidence_list)

    except Exception as e:
        print(f"[!] INGESTION_ERROR for {t_code}: {e}")
        return 0