import React, { useState, useEffect, useRef, useMemo } from 'react';
import InvestigationGallery from './InvestigationGallery';
import CaseDetail from './CaseDetail';

export default function InvestigationWorkspace({ activeNodes, activeLinks, updateNodeData, pendingCase, onPendingCaseHandled }) {
  const [mitreData, setMitreData] = useState([]);
  const [profiles, setProfiles] = useState([]);
  const [cases, setCases] = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const lastCaseRef = React.useRef(null); // keeps CaseDetail mounted when going back to gallery
  const [status, setStatus] = useState("INITIALIZING_UPLINK...");

  // ── Persistent pkg/deploy state — survives CaseDetail unmount ──────────────
  const [pkgData, setPkgData]         = useState({});   // { [assetId]: pkgResult }
  const [pkgProgress, setPkgProgress] = useState({});   // { [assetId]: progressData }
  const [pkgExpanded, setPkgExpanded] = useState({});   // { [assetId]: bool }
  const [pkgGenerating, setPkgGenerating] = useState({});
  const [pkgCopied, setPkgCopied]     = useState({});
  const [deployStatus, setDeployStatus] = useState({}); // { [assetId]: { phase, message, error } }
  const [deployRunning, setDeployRunning] = useState(false);
  const pollIntervalsRef = useRef({});                   // { [assetId]: intervalId }

  // ── Persistent analysis results — keyed by assetId, survive EvidenceWindow unmount ──
  const [memSummaries, setMemSummaries]   = useState({});  // { [assetId]: memSummary }
  const [avSummaries, setAvSummaries]     = useState({});  // { [assetId]: avSummary }
  const [vulnSummaries, setVulnSummaries] = useState({});  // { [assetId]: vulnSummary }
  const [dirToast, setDirToast]           = useState(null); // host path shown after local dir creation

  const isConnected = status === "CONNECTED_STABLE";
  const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

  const getAuthHeaders = () => ({ "Content-Type": "application/json" });

  useEffect(() => {
    const loadData = async () => {
      try {
        const fetchOpts = { credentials: 'include', headers: getAuthHeaders() };
        const profilesUrl = `${import.meta.env.VITE_API_URL}/api/profiles`;
        const [mitreRes, casesRes, profilesRes] = await Promise.all([
          fetch(`${API_BASE}/geopolitical/groups`, fetchOpts),
          fetch(`${API_BASE}/cases`, fetchOpts),
          fetch(profilesUrl, fetchOpts),
        ]);
        if (!mitreRes.ok || !casesRes.ok) throw new Error("DATA_SYNC_FAILED");
        setMitreData(await mitreRes.json());
        setCases(await casesRes.json());
        if (profilesRes.ok) setProfiles(await profilesRes.json());
        setStatus("CONNECTED_STABLE");
      } catch (err) {
        setStatus(`OFFLINE: ${err.message}`);
      }
    };
    loadData();

    // Cleanup all polling intervals on unmount
    return () => {
      Object.values(pollIntervalsRef.current).forEach(clearInterval);
    };
  }, []);

  // ── Polling helpers — managed here so they outlive CaseDetail ─────────────

  const fetchPkgProgress = async (assetId) => {
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/ingest/remote/${assetId}/progress`, {
        credentials: 'include',
        headers: getAuthHeaders(),
      });
      if (r.status === 401) return;
      if (r.ok) {
        const data = await r.json();
        setPkgProgress(prev => ({ ...prev, [String(assetId)]: data }));
        // No active token left means nothing more can ever check in — stop polling
        // instead of spinning forever on techniques that lost the race and got shut out.
        if (!data.package_active || data.pending === 0) stopProgressPolling(assetId);
      }
    } catch {}
  };

  const startProgressPolling = (assetId) => {
    const key = String(assetId);
    if (pollIntervalsRef.current[key]) return; // already polling
    fetchPkgProgress(assetId);
    pollIntervalsRef.current[key] = setInterval(() => fetchPkgProgress(assetId), 5000);
    // Stop after 24h
    setTimeout(() => {
      clearInterval(pollIntervalsRef.current[key]);
      delete pollIntervalsRef.current[key];
    }, 24 * 60 * 60 * 1000);
  };

  const stopProgressPolling = (assetId) => {
    const key = String(assetId);
    if (pollIntervalsRef.current[key]) {
      clearInterval(pollIntervalsRef.current[key]);
      delete pollIntervalsRef.current[key];
    }
  };

  // ── Purple status logic ────────────────────────────────────────────────────

  const enrichedNodes = useMemo(() => {
    if (!selectedCase || !selectedCase.assets) return activeNodes;
    const detectedTCodes = new Set(
      selectedCase.assets
        .filter(a => a.found_t_codes)
        .flatMap(a => a.found_t_codes.split(',').map(code => code.trim()))
    );
    return activeNodes.map(node => {
      const nodeCode = node.t_code || node.hostname || node.id;
      const isHit = detectedTCodes.has(nodeCode);
      return { ...node, isDetected: isHit, status: isHit ? 'DETECTED' : (node.status || 'READY') };
    });
  }, [activeNodes, selectedCase]);

  // ── Case handlers ──────────────────────────────────────────────────────────

  const handleSelectCase = async (caseObj) => {
    const caseName = caseObj.case_name || caseObj.name;
    setStatus(`FETCHING_ASSETS: ${caseName}`);
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assets`, {
        credentials: 'include',
        headers: getAuthHeaders(),
      });
      const assetData = res.ok ? await res.json() : [];
      setSelectedCase({ ...caseObj, assets: assetData });
      setStatus("CONNECTED_STABLE");
      // Resume polling for any assets that have active packages
      assetData.forEach(a => {
        if (pkgData[String(a.id)]) startProgressPolling(a.id);
      });
    } catch (err) {
      setSelectedCase({ ...caseObj, assets: [] });
      setStatus("CONNECTED_STABLE");
    }
  };

  // Jumping in from the dashboard's ACTIVE_INVESTIGATIONS list — open that case directly
  // instead of landing on the gallery.
  useEffect(() => {
    if (!pendingCase) return;
    handleSelectCase(pendingCase);
    onPendingCaseHandled && onPendingCaseHandled();
  }, [pendingCase]);

  const handleAddCase = async (newCase) => {
    setCases(prev => [...prev, newCase]);
    try {
      const res = await fetch(`${API_BASE}/cases`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(), body: JSON.stringify(newCase),
      });
      if (res.ok && newCase.create_local_dir) {
        const data = await res.json().catch(() => ({}));
        if (data.host_path) {
          setDirToast(data.host_path);
          setTimeout(() => setDirToast(null), 6000);
        }
      }
    } catch (err) { console.error("DB_COMMIT_ERROR:", err); }
  };

  const handleDeleteCase = async (caseName) => {
    // Confirmation is handled by InvestigationGallery's 4-step modal
    setCases(prev => prev.filter(c => (c.case_name || c.name) !== caseName));
    try {
      await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}`, {
        method: 'DELETE', credentials: 'include', headers: getAuthHeaders()
      });
    } catch (err) { console.error("DB_DELETE_ERROR:", err); }
  };

  return (
    <div style={{ width: '100%', height: '100%', minHeight: '100vh', background: '#000' }}>
      {dirToast && (
        <div style={{ position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
          background: '#0a1a0a', border: '1px solid #00ff41', padding: '12px 18px',
          fontFamily: 'monospace', fontSize: 11, color: '#00ff41', maxWidth: 420,
          boxShadow: '0 0 20px rgba(0,255,65,0.15)' }}>
          <div style={{ fontWeight: 'bold', marginBottom: 4, letterSpacing: 1 }}>✓ WORKING DIRECTORY CREATED</div>
          <div style={{ color: '#aaa', wordBreak: 'break-all' }}>{dirToast}</div>
          <div style={{ color: '#555', fontSize: 9, marginTop: 6 }}>Drop evidence files here — asset subfolders created automatically</div>
        </div>
      )}
      <div style={{
        background: isConnected ? 'rgba(0, 255, 65, 0.05)' : 'rgba(255, 68, 68, 0.05)',
        color: isConnected ? '#00ff41' : '#ff4444',
        padding: '12px 40px', fontSize: '11px', fontFamily: 'monospace',
        borderBottom: `1px solid ${isConnected ? '#00ff41' : '#ff4444'}`,
        display: 'flex', justifyContent: 'space-between',
        position: 'sticky', top: 0, zIndex: 100
      }}>
        <span>[SYSTEM_LINK]: {status}</span>
        <span>{selectedCase ? `LOCATION: /${selectedCase.case_name || selectedCase.name}` : `ACTIVE_CASES: ${cases.length}`}</span>
      </div>

      <div>
        {/* Always render CaseDetail when a case has been selected — display:none keeps scans alive */}
        {(selectedCase || lastCaseRef.current) && (
        <div style={{ display: selectedCase ? 'block' : 'none' }}>
          <CaseDetail
            caseData={selectedCase || lastCaseRef.current}
            onBack={() => { lastCaseRef.current = selectedCase; setSelectedCase(null); }}
            onRefresh={() => handleSelectCase(selectedCase || lastCaseRef.current)}
            activeNodes={enrichedNodes}
            activeLinks={activeLinks}
            updateNodeData={updateNodeData}
            // ── Persistent state passed down ──
            pkgData={pkgData}
            setPkgData={setPkgData}
            pkgProgress={pkgProgress}
            setPkgProgress={setPkgProgress}
            pkgExpanded={pkgExpanded}
            setPkgExpanded={setPkgExpanded}
            pkgGenerating={pkgGenerating}
            setPkgGenerating={setPkgGenerating}
            pkgCopied={pkgCopied}
            setPkgCopied={setPkgCopied}
            deployStatus={deployStatus}
            setDeployStatus={setDeployStatus}
            deployRunning={deployRunning}
            setDeployRunning={setDeployRunning}
            startProgressPolling={startProgressPolling}
            stopProgressPolling={stopProgressPolling}
            fetchPkgProgress={fetchPkgProgress}
            memSummaries={memSummaries}
            setMemSummaries={setMemSummaries}
            avSummaries={avSummaries}
            setAvSummaries={setAvSummaries}
            vulnSummaries={vulnSummaries}
            setVulnSummaries={setVulnSummaries}
          />
        </div>
        )}
        {!selectedCase && (
          <InvestigationGallery
            cases={cases}
            mitreData={mitreData}
            profiles={profiles}
            onSelectCase={handleSelectCase}
            onAddCase={handleAddCase}
            onDeleteCase={handleDeleteCase}
          />
        )}
      </div>
    </div>
  );
}
