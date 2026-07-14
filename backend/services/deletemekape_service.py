import os
import csv
from sqlalchemy.orm import Session
from core.models import Asset, ArtifactResult, RefArtifact

class KapeIngestService:
    @staticmethod
    def should_ingest(source_path: str) -> bool:
        """
        FILTER LOGIC: Returns False if the file path contains high-volume noise.
        """
        noise_patterns = [
            'node_modules', 
            '$recycle.bin', 
            'appdata\\local\\temp', 
            '\\.map', 
            '\\.json', 
            '\\cache\\'
        ]
        path_lower = source_path.lower()
        
        # If any noise pattern is in the path, skip it
        if any(pattern in path_lower for pattern in noise_patterns):
            return False
        return True

    @staticmethod
    def process_copylog(session: Session, asset_id: int, kape_output_dir: str):
        """
        Processes KAPE CopyLog.csv and matches against RefArtifact library with noise filtering.
        """
        try:
            # 1. Locate the CopyLog.csv within the provided directory
            copylog_path = None
            for root, _, files in os.walk(kape_output_dir):
                for file in files:
                    if "CopyLog.csv" in file:
                        copylog_path = os.path.join(root, file)
                        break
            
            if not copylog_path:
                print(f"[-] Error: CopyLog.csv not found in {kape_output_dir}")
                return 0

            # 2. Map the Artifact Library (T-Code -> Kape Modules)
            library = session.query(RefArtifact).filter(RefArtifact.kape_modules != None).all()
            lib_map = {}
            for entry in library:
                modules = [m.strip().lower() for m in entry.kape_modules.split('|') if m.strip()]
                lib_map[entry.t_code] = modules

            hits = 0
            # 3. Parse CopyLog and check for matches
            with open(copylog_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    source_file = row.get('SourceFile', '').lower()
                    dest_file = row.get('DestinationFile', '')

                    # --- NOISE FILTER START ---
                    if not KapeIngestService.should_ingest(source_file):
                        continue
                    # --- NOISE FILTER END ---

                    # Ensure the file actually exists on disk before logging it
                    if not dest_file or not os.path.exists(dest_file):
                        continue

                    for t_code, modules in lib_map.items():
                        if any(mod in source_file for mod in modules):
                            # Check if we already logged this result for this asset
                            existing = session.query(ArtifactResult).filter_by(
                                asset_id=asset_id, 
                                t_code=t_code
                            ).first()

                            if not existing:
                                new_hit = ArtifactResult(
                                    asset_id=asset_id,
                                    t_code=t_code,
                                    verdict="Evidence Found",
                                    evidence_path=dest_file,
                                    evidence_summary=f"Matched module pattern in {source_file}"
                                )
                                session.add(new_hit)
                            else:
                                # Update path if it's a new file for the same T-Code
                                current_paths = existing.evidence_path or ""
                                if dest_file not in current_paths:
                                    existing.evidence_path = f"{current_paths}|{dest_file}"
                            
                            hits += 1
            
            session.commit()
            print(f"[+] Ingest Complete for Asset {asset_id}: {hits} artifacts identified (Noise Filtered).")
            return hits

        except Exception as e:
            session.rollback()
            print(f"[-] Ingest Failed: {str(e)}")
            return 0
        finally:
            session.close()