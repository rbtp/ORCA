/**
 * RemotePackagePanel.jsx
 * 
 * Renders inside the asset card in CaseDetail.jsx (ASSETS tab).
 * Shows: Generate Package button → download link + token expiry + live progress.
 * 
 * Props:
 *   assetId     {number}
 *   hostname    {string}
 *   caseName    {string}
 */

import { useState, useEffect, useRef } from "react";

const API = (path) => `/api${path}`;
const authHdr = () => ({ 'Content-Type': 'application/json' });

const STATUS_COLORS = {
  COMPLETE:          "#00ff41",
  FALLBACK_COMPLETE: "#ffaa00",
  NO_ARTIFACTS:      "#555",
  RUNNING:           "#00bfff",
  FALLBACK_RUNNING:  "#ffaa00",
  QUEUED:            "#333",
  ERROR:             "#ff4141",
};

export default function RemotePackagePanel({ assetId, hostname, caseName }) {
  const [generating, setGenerating]   = useState(false);
  const [pkg, setPkg]                 = useState(null);   // { download_url, token, technique_count, expires_at }
  const [copied, setCopied]           = useState(false);
  const [progress, setProgress]       = useState(null);   // from /api/ingest/remote/{id}/progress
  const [revoking, setRevoking]       = useState(false);
  const pollRef                       = useRef(null);

  // On mount, check if there's an active package token for this asset
  useEffect(() => {
    fetchProgress();
    return () => stopPoll();
  }, [assetId]);

  const fetchProgress = async () => {
    try {
      const resp = await fetch(API(`/ingest/remote/${assetId}/progress`), { credentials: 'include', headers: authHdr() });
      if (resp.status === 401) { stopPoll(); return; }
      if (!resp.ok) return;
      const data = await resp.json();
      setProgress(data);
      // No active token left means nothing more can ever check in — stop polling
      // instead of spinning forever on techniques that lost the race and got shut out.
      if (!data.package_active || data.pending === 0) stopPoll();
    } catch (_) {}
  };

  const startPoll = () => {
    if (pollRef.current) return;
    pollRef.current = setInterval(fetchProgress, 5000);
  };

  const stopPoll = () => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const resp = await fetch(API(`/assets/${assetId}/package`), {
        method: "POST",
        credentials: 'include',
        headers: authHdr(),
      });
      if (!resp.ok) {
        const err = await resp.json();
        alert(`Package generation failed: ${err.detail || resp.statusText}`);
        return;
      }
      const data = await resp.json();
      setPkg(data);
      startPoll();
    } catch (e) {
      alert(`Error: ${e.message}`);
    } finally {
      setGenerating(false);
    }
  };

  const handleCopy = () => {
    if (!pkg) return;
    navigator.clipboard.writeText(pkg.download_url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const handleRevoke = async () => {
    if (!pkg?.token) return;
    if (!window.confirm("Revoke this package token? The agent will be unable to submit further results.")) return;
    setRevoking(true);
    try {
      await fetch(API(`/packages/${pkg.token}`), {
        method: "DELETE",
        credentials: 'include',
        headers: authHdr(),
      });
      setPkg(null);
      stopPoll();
    } catch (e) {
      alert(`Revoke failed: ${e.message}`);
    } finally {
      setRevoking(false);
    }
  };

  const expiresIn = (isoStr) => {
    if (!isoStr) return "";
    const diff = new Date(isoStr + "Z") - new Date();
    if (diff <= 0) return "EXPIRED";
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    return `${h}h ${m}m`;
  };

  const progressBar = () => {
    if (!progress || !progress.total) return null;
    const { total, with_evidence, no_artifacts, pending } = progress;
    const evidencePct   = (with_evidence / total) * 100;
    const noArtPct      = (no_artifacts  / total) * 100;
    const pendingPct    = (pending       / total) * 100;

    return (
      <div style={{ marginTop: 8 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#888", marginBottom: 3 }}>
          <span>REMOTE COLLECTION PROGRESS</span>
          <span>{with_evidence + no_artifacts}/{total} PROCESSED</span>
        </div>
        <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", background: "#111" }}>
          <div style={{ width: `${evidencePct}%`, background: "#00ff41", transition: "width 0.4s" }} />
          <div style={{ width: `${noArtPct}%`,   background: "#333",    transition: "width 0.4s" }} />
          <div style={{ width: `${pendingPct}%`, background: "#1a1a1a", transition: "width 0.4s" }} />
        </div>
        <div style={{ display: "flex", gap: 12, fontSize: 9, color: "#555", marginTop: 3 }}>
          <span style={{ color: "#00ff41" }}>■ EVIDENCE {with_evidence}</span>
          <span style={{ color: "#444" }}>■ NO_ARTIFACTS {no_artifacts}</span>
          <span style={{ color: "#333" }}>■ PENDING {pending}</span>
        </div>
      </div>
    );
  };

  return (
    <div style={{
      background: "#0a0a0a",
      border: "1px solid #1a1a1a",
      padding: "10px 12px",
      marginTop: 8,
      fontFamily: "monospace",
      fontSize: 11,
    }}>
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <span style={{ color: "#555", letterSpacing: 1, fontSize: 10 }}>REMOTE PACKAGE</span>
        {!pkg && (
          <button
            onClick={handleGenerate}
            disabled={generating}
            style={{
              background: "transparent",
              border: "1px solid #00ff41",
              color: "#00ff41",
              padding: "3px 10px",
              fontFamily: "monospace",
              fontSize: 11,
              cursor: generating ? "not-allowed" : "pointer",
              opacity: generating ? 0.5 : 1,
              letterSpacing: 1,
            }}
          >
            {generating ? "BUILDING..." : "GENERATE PACKAGE"}
          </button>
        )}
        {pkg && (
          <button
            onClick={handleRevoke}
            disabled={revoking}
            style={{
              background: "transparent",
              border: "1px solid #ff4141",
              color: "#ff4141",
              padding: "3px 10px",
              fontFamily: "monospace",
              fontSize: 10,
              cursor: revoking ? "not-allowed" : "pointer",
              letterSpacing: 1,
            }}
          >
            {revoking ? "REVOKING..." : "REVOKE"}
          </button>
        )}
      </div>

      {/* Package download row */}
      {pkg && (
        <div style={{ marginBottom: 4 }}>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
            <span style={{ color: "#00ff41", fontSize: 10 }}>
              ✓ {pkg.technique_count} TECHNIQUES PACKAGED
            </span>
            <span style={{ color: "#444", fontSize: 10 }}>
              EXPIRES {expiresIn(pkg.expires_at)}
            </span>
          </div>

          {/* Download URL box */}
          <div style={{
            background: "#050505",
            border: "1px solid #222",
            padding: "5px 8px",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}>
            <span style={{
              color: "#00bfff",
              flex: 1,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              fontSize: 10,
            }}>
              {pkg.download_url}
            </span>
            <button
              onClick={handleCopy}
              style={{
                background: "transparent",
                border: "1px solid #333",
                color: copied ? "#00ff41" : "#888",
                padding: "2px 8px",
                fontFamily: "monospace",
                fontSize: 10,
                cursor: "pointer",
                flexShrink: 0,
              }}
            >
              {copied ? "COPIED" : "COPY"}
            </button>
          </div>

          {/* Usage hint */}
          <div style={{ color: "#333", fontSize: 9, marginTop: 4 }}>
            On target: powershell -ExecutionPolicy Bypass -File run_orca_collection.ps1
          </div>
        </div>
      )}

      {/* Live progress (show if there's any activity even without a fresh pkg object) */}
      {progress?.package_active && progressBar()}

      {/* Completed state */}
      {progress?.package_info?.completed_at && (
        <div style={{ color: "#00ff41", fontSize: 10, marginTop: 6, letterSpacing: 1 }}>
          ✓ COLLECTION COMPLETE —{" "}
          {new Date(progress.package_info.completed_at + "Z").toLocaleString()}
        </div>
      )}
    </div>
  );
}
