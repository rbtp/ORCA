import React, { useState, useEffect, useImperativeHandle, forwardRef } from 'react';
import EvidenceWindow from './EvidenceWindow';

const AssetInvestigation = forwardRef(({ asset }, ref) => {
  const [tacticList, setTacticList] = useState([]); 
  const [selectedTactic, setSelectedTactic] = useState(null);
  const [protocolData, setProtocolData] = useState(null);
  const [history, setHistory] = useState([]);
  const [currentNote, setCurrentNote] = useState("");
  const [currentBlufInput, setCurrentBlufInput] = useState(""); 
  const [isLoading, setIsLoading] = useState(true);
  const [isEvidenceModalOpen, setIsEvidenceModalOpen] = useState(false);
  const [evidenceTCode, setEvidenceTCode] = useState(null);

  const searchIdentifier = asset?.case_name || asset?.focus_country || asset?.country_focus;

  // AUTH HEADER HELPER
  const getAuthHeaders = () => ({ "Content-Type": "application/json" });

  // FORCED DOWNLOAD TRIGGER & REFRESH HANDLES
  useImperativeHandle(ref, () => ({
    refreshData: () => fetchTechniques(),
    runGenKapeMods: async () => {
      console.log("[SYSTEM] Requesting KAPE Gen from Backend...");
      try {
        const response = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/execute`, {
          method: "POST",
          credentials: 'include',
          headers: getAuthHeaders(),
          body: JSON.stringify({
            action: 'Generate KAPE Modules',
            asset_id: asset?.id || 48,
            asset: asset
          })
        });
        if (!response.ok) throw new Error("BACKEND_SERVICE_FAILURE");
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `ORCA_ASSET_${asset?.id || 48}.tkape`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } catch (err) {
        console.error("[CRITICAL] Download Handshake Failed:", err);
      }
    }
  }));

  const fetchTechniques = async () => {
    if (!searchIdentifier) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/threat-profile/${searchIdentifier}?asset_id=${asset?.id}`, {
        credentials: 'include',
        headers: getAuthHeaders(),
      });
      const data = await res.json();
      setTacticList(data);
      if (data.length > 0 && !selectedTactic) setSelectedTactic(data[0].t_code);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => { fetchTechniques(); }, [searchIdentifier, asset?.id]);

  useEffect(() => {
    if (selectedTactic) {
      fetch(`${import.meta.env.VITE_API_URL}/api/mitre/library/${selectedTactic}`, {
        credentials: 'include',
        headers: getAuthHeaders(),
      })
        .then(res => res.json())
        .then(data => setProtocolData(data))
        .catch(() => setProtocolData(null));
    }
  }, [selectedTactic]);

  const handleOpenEvidence = (tCode) => {
    setEvidenceTCode(tCode);
    setIsEvidenceModalOpen(true);
  };

  const updateVerdict = async (verdict) => {
    if (!selectedTactic || !asset) return;
    try {
      await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${asset.id}/${selectedTactic}/verdict`, {
        method: 'POST',
        credentials: 'include',
        headers: getAuthHeaders(),
        body: JSON.stringify({ verdict })
      });
      fetchTechniques(); 
    } catch (err) { console.error("VERDICT_UPDATE_FAILED"); }
  };

  const handleCommit = (type) => {
    const ts = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
    if (type === 'BLUF' && currentBlufInput.trim()) {
      setHistory([{ time: ts, text: currentBlufInput, isBluf: true }, ...history]);
      setCurrentBlufInput("");
    } else if (type === 'NOTE' && currentNote.trim()) {
      setHistory([{ time: ts, text: currentNote, isBluf: false }, ...history]);
      setCurrentNote("");
    }
  };

  if (isLoading) return <div style={TerminalStyle}>[SYSTEM]: SYNCING...</div>;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '0', height: '100vh', background: '#000', fontFamily: 'monospace', overflow: 'hidden' }}>
      
      <aside style={{ borderRight: '1px solid #222', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={SidebarHeader}>
          <div style={LabelStyle}>TECHNIQUE_INDEX / {searchIdentifier}</div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {tacticList.map(t => (
            <div 
              key={t.t_code} 
              onClick={() => setSelectedTactic(t.t_code)}
              style={{ 
                ...TacticItem, 
                backgroundColor: t.verdict === 'Malicious' ? 'rgba(255,0,0,0.1)' : t.evidence_imported ? 'rgba(123,44,191,0.1)' : selectedTactic === t.t_code ? '#00ff4110' : 'transparent',
                color: t.verdict === 'Malicious' ? '#ff4444' : t.evidence_imported ? '#7b2cbf' : selectedTactic === t.t_code ? '#00ff41' : '#aaa',
                borderLeftColor: t.verdict === 'Malicious' ? '#ff4444' : t.evidence_imported ? '#7b2cbf' : selectedTactic === t.t_code ? '#00ff41' : 'transparent'
              }}
            >
              <div style={{ fontSize: '12px', fontWeight: 'bold' }}>{t.t_code}</div>
              <div style={{ fontSize: '11px' }}>{t.technique_name || t.name}</div>
              {t.evidence_imported && (
                <button 
                  onClick={(e) => { e.stopPropagation(); handleOpenEvidence(t.t_code); }}
                  style={{ background: '#7b2cbf', color: '#fff', border: 'none', padding: '2px 5px', fontSize: '9px', cursor: 'pointer', marginTop: '5px' }}
                >
                  OPEN EVIDENCE
                </button>
              )}
            </div>
          ))}
        </div>
      </aside>

      <main style={{ display: 'flex', flexDirection: 'column', padding: '20px', gap: '15px', background: '#050505', overflow: 'hidden' }}>
        
        <section style={StatusHeader}>
          <div style={{ color: '#00ff41', fontSize: '14px', fontWeight: 'bold' }}>[ STATUS ]: {selectedTactic || "IDLE"}</div>
          <div style={{ display: 'flex', gap: '15px', alignItems: 'center' }}>
            <span style={LabelStyle}>VERDICT:</span>
            <select 
              style={InputStyle} 
              value={tacticList.find(t => t.t_code === selectedTactic)?.verdict || "UNDETERMINED"}
              onChange={(e) => updateVerdict(e.target.value)}
            >
              <option value="UNDETERMINED">UNDETERMINED</option>
              <option value="MALICIOUS">MALICIOUS</option>
              <option value="NON-MALICIOUS">NON-MALICIOUS</option>
            </select>
          </div>
        </section>

        <section style={AnalysisBox}>
            <div style={BoxHeader}>DETECTION_STRATEGY_PROTOCOL</div>
            <div style={{ padding: '15px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '15px' }}>
              <div>
                  <div style={GuideLabel}>&gt; LIVE_ANALYSIS</div>
                  <div style={GuideText}>{protocolData?.live_analysis || "---"}</div>
              </div>
              <div>
                  <div style={GuideLabel}>&gt; DEAD_DISK_ANALYSIS</div>
                  <div style={GuideText}>{protocolData?.dead_disk_analysis || "---"}</div>
              </div>
              <div>
                  <div style={GuideLabel}>&gt; COLLECTION_STRATEGY</div>
                  <div style={GuideText}>{protocolData?.bluf_text || protocolData?.collection_strategy || "---"}</div>
              </div>
            </div>
        </section>

        <section style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div>
               <div style={InputTitleGreen}>&gt; BLUF_PRIORITY_INPUT</div>
               <div style={{ display: 'flex', gap: '5px' }}>
                  <input style={{ ...SingleLineInput, borderLeft: '4px solid #00ff41' }} value={currentBlufInput} onChange={(e) => setCurrentBlufInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleCommit('BLUF')} />
                  <button onClick={() => handleCommit('BLUF')} style={{ ...CommitBtn, background: '#00ff41', color: '#000' }}>COMMIT</button>
               </div>
            </div>
            <div>
               <div style={InputTitleGrey}>&gt; ANALYST_OBSERVATION</div>
               <div style={{ display: 'flex', gap: '5px' }}>
                  <input style={SingleLineInput} value={currentNote} onChange={(e) => setCurrentNote(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleCommit('NOTE')} />
                  <button onClick={() => handleCommit('NOTE')} style={{ ...CommitBtn, background: '#333', color: '#00ff41' }}>COMMIT</button>
               </div>
            </div>
        </section>

        <section style={TimelineContainer}>
          <div style={BoxHeader}>INVESTIGATION_TIMELINE_LOG</div>
          <div style={TimelineBody}>
            {history.map((h, i) => (
              <div key={i} style={{ color: h.isBluf ? '#00ff41' : '#ccc', padding: '4px 10px', borderLeft: h.isBluf ? '2px solid #00ff41' : '2px solid #333', fontSize: '12px' }}>
                <span style={{ opacity: 0.5, marginRight: '10px' }}>[{h.time}]</span> {h.text}
              </div>
            ))}
          </div>
        </section>
      </main>

      <EvidenceWindow
        assetId={asset?.id}
        assetType={asset?.asset_type || asset?.type || ''}
        tCode={evidenceTCode}
        isOpen={isEvidenceModalOpen}
        onClose={() => setIsEvidenceModalOpen(false)}
      />
    </div>
  );
});

export default AssetInvestigation;

const TerminalStyle = { background: '#000', color: '#00ff41', padding: '40px', fontFamily: 'monospace', height: '100vh' };
const SidebarHeader = { padding: '20px', borderBottom: '1px solid #222' };
const LabelStyle = { color: '#888', fontSize: '10px', textTransform: 'uppercase' };
const TacticItem = { padding: '12px 15px', borderLeft: '3px solid', cursor: 'pointer', borderBottom: '1px solid #111' };
const StatusHeader = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px', border: '1px solid #222', background: '#000' };
const InputStyle = { background: '#000', border: '1px solid #333', color: '#00ff41', padding: '5px', fontSize: '11px', fontFamily: 'monospace' };
const AnalysisBox = { border: '1px solid #222', background: '#000', height: '320px', display: 'flex', flexDirection: 'column' };
const BoxHeader = { padding: '6px 12px', background: '#111', borderBottom: '1px solid #222', fontSize: '10px', color: '#888' };
const GuideLabel = { color: '#00ff41', fontSize: '10px', fontWeight: 'bold', marginBottom: '4px' };
const GuideText = { color: '#aaa', fontSize: '12px', lineHeight: '1.4' };
const InputTitleGreen = { color: '#00ff41', fontSize: '10px', fontWeight: 'bold', marginBottom: '6px' };
const InputTitleGrey = { color: '#888', fontSize: '10px', fontWeight: 'bold', marginBottom: '6px' };
const SingleLineInput = { background: '#000', border: '1px solid #222', color: '#fff', padding: '10px', fontSize: '12px', fontFamily: 'monospace', flex: 1, outline: 'none' };
const CommitBtn = { border: 'none', fontWeight: 'bold', cursor: 'pointer', fontSize: '10px', width: '80px', fontFamily: 'monospace' };
const TimelineContainer = { flex: 1, border: '1px solid #222', background: '#020202', display: 'flex', flexDirection: 'column', minHeight: 0 };
const TimelineBody = { flex: 1, overflowY: 'auto', padding: '10px' };