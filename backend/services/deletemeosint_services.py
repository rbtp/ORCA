import re

class OSINTService:
    @staticmethod
    def scan_artifacts(session, case_name, ioc_list):
        """
        Scans all ArtifactResults in a case for a list of user-provided IOCs.
        """
        results = []
        # Fetch all forensic hits for this case
        forensic_hits = session.query(ArtifactResult).join(Asset).filter(Asset.case_name == case_name).all()

        for ioc in ioc_list:
            ioc = ioc.strip()
            for hit in forensic_hits:
                # Landmark: Check evidence_path and summary for the IOC
                if ioc.lower() in (hit.evidence_path or "").lower() or ioc.lower() in (hit.evidence_summary or "").lower():
                    # Generate External Links
                    vt_link = f"https://www.virustotal.com/gui/search/{ioc}"
                    otx_link = f"https://otx.alienvault.com/indicator/file/{ioc}"
                    
                    results.append({
                        "ioc": ioc,
                        "matched_asset": hit.asset.hostname,
                        "t_code": hit.t_code,
                        "path": hit.evidence_path,
                        "vt_link": vt_link,
                        "otx_link": otx_link
                    })
        return results