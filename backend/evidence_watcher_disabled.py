import os
import time
import pandas as pd
from sqlalchemy import text
from core.database_manager import db

def start_ingestion_watcher(parsed_root_folder, case_id):
    """
    Monitors the parsed folder for new CSVs and pushes them to the DB.
    """
    processed_files = set()
    
    print(f"[*] Watcher started for Case {case_id} at {parsed_root_folder}")

    while True:
        # 1. Look for new CSV files
        try:
            current_files = [
                os.path.join(root, f) 
                for root, dirs, files in os.walk(parsed_root_folder) 
                for f in files if f.endswith('.csv')
            ]
        except Exception:
            time.sleep(5)
            continue

        for file_path in current_files:
            if file_path not in processed_files:
                # 2. Process the new evidence
                ingest_csv_to_db(file_path, case_id)
                processed_files.add(file_path)
        
        # Poll every 5 seconds to keep it snappy without hogging CPU
        time.sleep(5)

def ingest_csv_to_db(file_path, case_id):
    filename = os.path.basename(file_path)
    df = pd.read_csv(file_path)
    
    # Simple logic to determine T-Code based on Zimmerman filename
    t_code = "T1000" # Default
    if "PECmd" in filename: t_code = "T1027.001"
    if "EvtxECmd" in filename: t_code = "T1078"
    if "RECmd" in filename: t_code = "T1012"

    # Push to your existing evidence table
    # This ensures the React UI 'sees' the data on the next refresh
    with db.engine.connect() as conn:
        for _, row in df.iterrows():
            conn.execute(text("""
                INSERT INTO asset_evidence (case_id, t_code, source_file, evidence_data)
                VALUES (:case_id, :t_code, :src, :data)
            """), {
                "case_id": case_id,
                "t_code": t_code,
                "src": filename,
                "data": row.to_json()
            })
        conn.commit()
    print(f"[+] Successfully ingested {len(df)} rows from {filename}")