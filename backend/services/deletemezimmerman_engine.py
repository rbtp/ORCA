import pandas as pd
import os
import json
from sqlalchemy import text
from core.database_manager import db

class ZimmermanEngine:
    @staticmethod
    def ingest_kape_collection(asset_id, kape_folder, target_list=None, country_code='bel'):
        if not os.path.exists(kape_folder): return
            
        copylog_path = None
        for root, _, files in os.walk(kape_folder):
            for f in files:
                if f.lower().endswith("copylog.csv"):
                    copylog_path = os.path.join(root, f)
                    break
            if copylog_path: break
        
        active_targets = target_list if target_list else []

        if copylog_path:
            try:
                df_log = pd.read_csv(copylog_path, engine='python', on_bad_lines='skip', sep=None)
                df_log.columns = df_log.columns.str.replace('^\ufeff', '', regex=True)
                
                target_col = next((c for c in ['TargetName', 'Target'] if c in df_log.columns), None)
                if target_col:
                    log_hits = df_log[df_log[target_col].notna()][target_col].unique().tolist()
                    active_targets = list(set(active_targets + log_hits))
            except Exception:
                pass 

        if active_targets:
            # 1. Sync the high-level T-Code results
            ZimmermanEngine.sync_fan_out(asset_id, active_targets, copylog_path or kape_folder, country_code)
            
            # 2. Ingest the actual granular data from the 'out' folder
            ZimmermanEngine.ingest_granular_evidence(asset_id, kape_folder)
        else:
            print(f"[!] No targets to sync for Asset {asset_id}")

    @staticmethod
    def ingest_granular_evidence(asset_id, kape_folder):
        """
        Scans KAPE output for CSVs, maps them to T-Codes, 
        and dumps raw rows into the evidence table as JSONB.
        """
        print(f"[*] Starting Granular Ingestion for Asset {asset_id}...")
        
        for root, _, files in os.walk(kape_folder):
            for f in files:
                # We want result CSVs, ignoring the logs themselves
                if f.lower().endswith('.csv') and "copylog" not in f.lower():
                    file_path = os.path.join(root, f)
                    
                    # Determine T-Code based on the filename (e.g., 'Registry_SAM.csv')
                    target_name = f.replace('.csv', '')
                    t_code = ZimmermanEngine.get_tcode_for_target(target_name)
                    
                    if not t_code:
                        continue # Skip artifacts that don't map to a MITRE technique

                    try:
                        df = pd.read_csv(file_path, on_bad_lines='skip', low_memory=False)
                        # Replace NaN with None so JSON conversion is clean
                        df = df.where(pd.notnull(df), None)

                        with db.engine.begin() as conn:
                            for _, row in df.iterrows():
                                # This is the "Grand Plan": row -> JSON string -> JSONB column
                                row_json = row.to_json()
                                
                                conn.execute(text("""
                                    INSERT INTO evidence (asset_id, t_code, file_name, file_path, raw_data)
                                    VALUES (:aid, :t, :name, :path, :data)
                                """), {
                                    "aid": asset_id,
                                    "t": t_code,
                                    "name": f,
                                    "path": file_path,
                                    "data": row_json
                                })
                    except Exception as e:
                        print(f"[-] Error parsing {f}: {e}")

    @staticmethod
    def get_tcode_for_target(target_name):
        """
        Reverse lookup to find which T-Code a specific KAPE artifact belongs to.
        Checks the mapping table dynamically.
        """
        query = text("""
            SELECT t_code FROM kape_mitre_mapping 
            WHERE :target = ANY(kape_targets) LIMIT 1
        """)
        try:
            with db.engine.connect() as conn:
                res = conn.execute(query, {"target": target_name}).mappings().first()
                return res['t_code'] if res else None
        except:
            return None

    @staticmethod
    def sync_fan_out(asset_id, found_targets, log_path, country_code):
        query = text("""
            INSERT INTO artifact_results (asset_id, t_code, verdict, evidence_imported, evidence_path)
            SELECT :aid, t_code, 
                   CASE WHEN priority = 1 THEN 'Validated Threat' ELSE 'Evidence Found' END,
                   TRUE, :path
            FROM (
                SELECT DISTINCT ON (t_code) t_code, priority
                FROM (
                    SELECT t_code, 1 as priority 
                    FROM investigation_intelligence_map 
                    WHERE kape_targets && :targets AND focus_country = :country
                    
                    UNION ALL
                    
                    SELECT t_code, 2 as priority 
                    FROM kape_mitre_mapping 
                    WHERE kape_targets && :targets
                ) sub
                ORDER BY t_code, priority ASC
            ) as prioritized_matches
            ON CONFLICT (asset_id, t_code) 
            DO UPDATE SET 
                verdict = EXCLUDED.verdict,
                evidence_imported = TRUE,
                evidence_path = EXCLUDED.evidence_path;
        """)

        try:
            with db.engine.begin() as conn:
                result = conn.execute(query, {
                    "path": log_path, 
                    "aid": asset_id, 
                    "targets": found_targets,
                    "country": country_code
                })
                print(f"[DATABASE] Intelligence Sync: {result.rowcount} T-Codes mapped.")
        except Exception as e:
            print(f"[-] SYNC_ERROR: {e}")