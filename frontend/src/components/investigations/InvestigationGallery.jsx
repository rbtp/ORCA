import React, { useState, useEffect, useMemo } from 'react';

export default function InvestigationGallery({ cases = [], onSelectCase, onAddCase, onDeleteCase, mitreData = [], profiles = [] }) {
  const [showModal, setShowModal] = useState(false);

  // --- FORM STATE ---
  const [caseName, setCaseName]           = useState("");
  const [teamName, setTeamName]           = useState("");
  const [missionLead, setMissionLead]     = useState("");
  const [staffInput, setStaffInput]       = useState("");
  const [personnelList, setPersonnelList] = useState([]);
  const [focusCountry, setFocusCountry]   = useState("");
  const [selectedGroups, setSelectedGroups] = useState([]);
  const [caseType, setCaseType]           = useState("INVESTIGATION");
  const [activeProfile, setActiveProfile] = useState(null); // set when a profile is selected
  const [createLocalDir, setCreateLocalDir] = useState(false);

  // ── Delete case confirmation state ────────────────────────────────────────
  const [deleteTarget, setDeleteTarget]   = useState(null);  // case name
  const [deleteStep, setDeleteStep]       = useState(0);
  const [deleteMath, setDeleteMath]       = useState({ a: 0, b: 0, op: '+' });
  const [deleteMathAnswer, setDeleteMathAnswer] = useState('');
  const [deleteConfirmText, setDeleteConfirmText] = useState('');

  const openDeleteCase = (caseName, e) => {
    e.stopPropagation();
    const ops = ['+', '-', '*'];
    const op  = ops[Math.floor(Math.random() * ops.length)];
    const a   = Math.floor(Math.random() * 20) + 5;
    const b   = Math.floor(Math.random() * 10) + 2;
    setDeleteMath({ a, b, op });
    setDeleteMathAnswer('');
    setDeleteConfirmText('');
    setDeleteTarget(caseName);
    setDeleteStep(1);
  };

  const closeDeleteCase = () => { setDeleteStep(0); setDeleteTarget(null); setDeleteMathAnswer(''); setDeleteConfirmText(''); };

  const confirmDeleteCase = () => {
    onDeleteCase(deleteTarget);
    closeDeleteCase();
  };

  const mathAnswer = () => {
    const { a, b, op } = deleteMath;
    return op === '+' ? a + b : op === '-' ? a - b : a * b;
  };

  // --- DATA EXTRACTION ---
  const allGroups = useMemo(() => {
    if (Array.isArray(mitreData)) return mitreData;
    if (mitreData && mitreData.objects) return mitreData.objects;
    return [];
  }, [mitreData]);

  const attributedCountries = useMemo(() => {
    const countries = allGroups
      .map(g => g.country || g.x_mitre_origins || g.origin) 
      .filter(Boolean);
    return [...new Set(countries)].sort();
  }, [allGroups]);

  // --- AUTOMAGIC SELECTION LOGIC ---
  useEffect(() => {
    if (activeProfile) return; // profile mode: selectedGroups managed by handleFocusChange
    if (focusCountry) {
      const groupsInCountry = allGroups
        .filter(g => (g.country === focusCountry || g.x_mitre_origins === focusCountry || g.origin === focusCountry))
        .map(g => g.name || g.group_name);
      setSelectedGroups(groupsInCountry);
    } else {
      setSelectedGroups([]);
    }
  }, [focusCountry, allGroups, activeProfile]);

  const handleFocusChange = (e) => {
    const val = e.target.value;
    if (val.startsWith('profile::')) {
      const profileId = parseInt(val.split('::')[1], 10);
      const profile = profiles.find(p => p.id === profileId);
      if (profile) {
        setFocusCountry(val);
        setActiveProfile(profile);
        setSelectedGroups(profile.tcodes || []);
      }
    } else {
      setFocusCountry(val);
      setActiveProfile(null);
      // useEffect will populate selectedGroups based on country
    }
  };

  const handleStaffCommit = (e) => {
    if (e.key === 'Enter' && staffInput.trim()) {
      e.preventDefault();
      if (!personnelList.includes(staffInput.trim())) {
        setPersonnelList([...personnelList, staffInput.trim()]);
      }
      setStaffInput("");
    }
  };

  const resetForm = () => {
    setCaseName(""); setTeamName(""); setMissionLead("");
    setPersonnelList([]); setFocusCountry(""); setSelectedGroups([]);
    setCaseType("INVESTIGATION"); setActiveProfile(null); setCreateLocalDir(false);
  };

  const handleCommitInvestigation = () => {
    if (!caseName.trim()) {
      alert("CRITICAL_ERROR: CASE_IDENTIFIER_REQUIRED");
      return;
    }
    onAddCase({
      name: caseName,
      case_name: caseName,
      teamName,
      missionLead,
      personnel: personnelList,
      country: activeProfile ? `[PROFILE] ${activeProfile.name}` : focusCountry,
      groups: selectedGroups,
      case_type: caseType,
      create_local_dir: createLocalDir,
    });
    setShowModal(false);
    resetForm();
  };

  const isIR = (c) => (c.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE';

  return (
    <div style={{ padding: '40px', background: '#000', minHeight: '100vh', color: '#fff', fontFamily: 'monospace' }}>
      
      <div style={headerFlex}>
        <h2 style={titleGlow}>INVESTIGATION_ORCHESTRATOR</h2>
        <button onClick={() => setShowModal(true)} style={btnDeploy}>NEW_INVESTIGATION +</button>
      </div>

      {showModal && (
        <div style={modalOverlay}>
          <div style={modalContent}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
              <div style={modalHeader}>INIT_CASE_FILE</div>
              <div style={{ color: '#888', fontSize: '10px' }}>ORCA_PROTOCOL_v4.2</div>
            </div>

            {/* ── CASE TYPE TOGGLE ── */}
            <div style={{ marginBottom: '40px' }}>
              <label style={labelStyle}>OPERATION_TYPE</label>
              <div style={{ display: 'flex', gap: 12 }}>
                {[
                  { val: 'INVESTIGATION', label: 'INVESTIGATION', sub: 'Threat-intel driven, no confirmed incident' },
                  { val: 'INCIDENT_RESPONSE', label: 'INCIDENT_RESPONSE', sub: 'Active incident — triage-first workflow' },
                ].map(({ val, label, sub }) => (
                  <div key={val} onClick={() => setCaseType(val)}
                    style={{ flex: 1, padding: '16px 20px', border: `1px solid ${caseType === val ? (val === 'INCIDENT_RESPONSE' ? '#ff4141' : '#00ff41') : '#1a1a1a'}`, cursor: 'pointer', background: caseType === val ? (val === 'INCIDENT_RESPONSE' ? 'rgba(255,65,65,0.05)' : 'rgba(0,255,65,0.04)') : '#050505', transition: 'all 0.15s' }}>
                    <div style={{ color: caseType === val ? (val === 'INCIDENT_RESPONSE' ? '#ff4141' : '#00ff41') : '#444', fontSize: 11, fontWeight: 'bold', letterSpacing: 2, marginBottom: 6 }}>
                      {caseType === val ? '◉' : '○'} {label}
                    </div>
                    <div style={{ color: '#bbb', fontSize: 9 }}>{sub}</div>
                  </div>
                ))}
              </div>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '40px' }}>
              <div>
                <label style={labelStyle}>CASE_IDENTIFIER</label>
                <input value={caseName} onChange={(e) => setCaseName(e.target.value)} style={inputStyle} placeholder="e.g. OPERATION_SILENT_WHALE" />

                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginBottom: 16 }}>
                  <input type="checkbox" checked={createLocalDir} onChange={e => setCreateLocalDir(e.target.checked)}
                    style={{ accentColor: '#00ff41', width: 13, height: 13, cursor: 'pointer' }} />
                  <span style={{ color: '#777', fontSize: 9, letterSpacing: 1, fontFamily: 'monospace' }}>
                    CREATE_LOCAL_WORKING_DIRECTORY
                  </span>
                  <span style={{ color: '#999', fontSize: 8, fontFamily: 'monospace' }}>
                    ({caseName.trim() ? caseName.trim().replace(/[^A-Za-z0-9_\-.]/g, '_') : 'CASE_NAME'}\)
                  </span>
                </label>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
                  <div>
                    <label style={labelStyle}>TEAM_NAME</label>
                    <input value={teamName} onChange={(e) => setTeamName(e.target.value)} style={inputStyle} />
                  </div>
                  <div>
                    <label style={labelStyle}>MISSION_LEAD</label>
                    <input value={missionLead} onChange={(e) => setMissionLead(e.target.value)} style={inputStyle} />
                  </div>
                </div>

                <label style={labelStyle}>SUPPORT_PERSONNEL (PRESS_ENTER_TO_ADD)</label>
                <input value={staffInput} onChange={(e) => setStaffInput(e.target.value)} onKeyDown={handleStaffCommit} style={inputStyle} />
                
                <div style={staffStorageBox}>
                  {personnelList.length === 0 && <div style={{ color: '#777', fontSize: '10px' }}>NO_PERSONNEL_ASSIGNED</div>}
                  {personnelList.map(p => (
                    <div key={p} style={staffChip}>
                      {p} <span onClick={() => setPersonnelList(personnelList.filter(x => x !== p))} style={removeX}>×</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <label style={labelStyle}>GEOPOLITICAL_FOCUS / CUSTOM_PROFILE (POSTGRES_FILTER)</label>
                <select value={focusCountry} onChange={handleFocusChange} style={inputStyle}>
                  <option value="">SELECT_COUNTRY_OR_PROFILE...</option>
                  <optgroup label="── COUNTRIES ──">
                    {attributedCountries.map(c => <option key={c} value={c}>{c}</option>)}
                  </optgroup>
                  {profiles.length > 0 && (
                    <optgroup label="── CUSTOM PROFILES ──">
                      {profiles.map(p => (
                        <option key={`profile::${p.id}`} value={`profile::${p.id}`}>
                          ⬡ {p.name}
                        </option>
                      ))}
                    </optgroup>
                  )}
                </select>

                <label style={labelStyle}>
                  {activeProfile ? `PROFILE_TCODES: ${activeProfile.name}` : 'THREAT_GROUP_MATRIX (AUTO_SELECTED)'}
                </label>
                <div style={scrollBox}>
                  {activeProfile ? (
                    selectedGroups.length > 0 ? selectedGroups.map(tc => (
                      <div
                        key={tc}
                        onClick={() => setSelectedGroups(prev => prev.filter(x => x !== tc))}
                        style={{ ...itemStyle, color: '#00b8ff', borderColor: '#0a1a2a', background: 'rgba(0,184,255,0.02)' }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span>{tc}</span>
                          <span style={{ fontSize: '9px', color: '#0a3a5a' }}>⬡ PROFILE_TCODE</span>
                        </div>
                      </div>
                    )) : (
                      <div style={{ color: '#999', fontSize: '10px', padding: '20px', textAlign: 'center', border: '1px dashed #111' }}>
                        PROFILE_EMPTY: NO_TCODES_DEFINED
                      </div>
                    )
                  ) : allGroups.length > 0 ? allGroups.map(g => {
                    const isSelected = selectedGroups.includes(g.name || g.group_name);
                    return (
                      <div
                        key={g.id || g.name}
                        onClick={() => setSelectedGroups(prev => isSelected ? prev.filter(x => x !== (g.name || g.group_name)) : [...prev, (g.name || g.group_name)])}
                        style={{ ...itemStyle, color: isSelected ? '#00ff41' : '#333', borderColor: isSelected ? '#00ff41' : '#111', background: isSelected ? 'rgba(0,255,65,0.02)' : 'transparent' }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span>{g.name || g.group_name}</span>
                          {(g.country === focusCountry || g.origin === focusCountry) && <span style={{ fontSize: '9px' }}>📍 ORIGIN_MATCH</span>}
                        </div>
                      </div>
                    );
                  }) : <div style={{ color: '#ff4444', fontSize: '10px', padding: '20px', textAlign: 'center', border: '1px dashed #222' }}>CRITICAL: NO_DATA_STREAM_DETECTED</div>}
                </div>
              </div>
            </div>

            <div style={footerRow}>
              <button onClick={() => { setShowModal(false); resetForm(); }} style={btnAbort}>ABORT_SESSION</button>
              <button onClick={handleCommitInvestigation}
                style={{ ...btnDeploy, background: caseType === 'INCIDENT_RESPONSE' ? '#ff4141' : '#00ff41', color: '#000' }}>
                COMMIT_{caseType === 'INCIDENT_RESPONSE' ? 'IR_CASE' : 'INVESTIGATION'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* GALLERY VIEW */}
      <div style={gridStyle}>
        {cases.length === 0 && <div style={{ color: '#777', gridColumn: '1/-1', textAlign: 'center', marginTop: '100px', fontSize: '20px', letterSpacing: '10px' }}>NO_ACTIVE_INVESTIGATIONS</div>}
        {cases.map((c, i) => (
          <div key={i} style={{ position: 'relative' }}>
            <button 
              onClick={(e) => openDeleteCase(c.name || c.case_name, e)}
              style={btnTerminate}
              title="TERMINATE_CASE"
            >×</button>
            <div onClick={() => onSelectCase && onSelectCase(c)}
              style={{ ...caseCardStyle, borderColor: isIR(c) ? '#2a0a0a' : '#111', background: isIR(c) ? '#060000' : '#050505' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <div style={cardTop}>{(c.country || "GLOBAL").toUpperCase()} // {c.teamName || "UNASSIGNED"}</div>
                <span style={{ fontSize: 8, letterSpacing: 1, padding: '2px 6px', border: `1px solid ${isIR(c) ? '#ff4141' : '#222'}`, color: isIR(c) ? '#ff4141' : '#333', fontWeight: 'bold' }}>
                  {isIR(c) ? '⚡ IR' : 'INV'}
                </span>
              </div>
              <div style={cardTitle}>{c.name || c.case_name || "UNTITLED_CASE"}</div>
              <div style={{ marginTop: '20px', display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                {c.groups?.slice(0, 3).map(g => <span key={g} style={{ fontSize: '8px', color: '#aaa', border: '1px solid #111', padding: '2px 5px' }}>{g}</span>)}
                {c.groups?.length > 3 && <span style={{ fontSize: '8px', color: '#aaa' }}>+{c.groups.length - 3} MORE</span>}
              </div>
            </div>
          </div>
        ))}
      </div>
      {/* ── Delete Case Modal ──────────────────────────────────────────────── */}
      {deleteStep > 0 && deleteTarget && (
        <div style={modalOverlay}>
          <div style={{ ...modalContent, maxWidth: 480, padding: 48, border: '1px solid #ff4141' }}>

            {deleteStep === 1 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>⚠ TERMINATE INVESTIGATION</h2>
              <p style={{ color: '#ccc', fontSize: 11, marginBottom: 8 }}>You are about to permanently delete investigation:</p>
              <p style={{ color: '#ff4141', fontSize: 14, fontWeight: 'bold', marginBottom: 16 }}>{deleteTarget}</p>
              <p style={{ color: '#888', fontSize: 10, marginBottom: 20 }}>
                This will permanently destroy all assets, collected evidence, MFT entries, event logs, registry data, notes, and analysis results for this entire investigation. This cannot be undone.
              </p>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDeleteCase} style={btnAbort}>CANCEL</button>
                <button onClick={() => setDeleteStep(2)} style={{ ...btnDeploy, background: '#ff4141', color: '#000' }}>YES, CONTINUE</button>
              </div>
            </>)}

            {deleteStep === 2 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>⚠ ARE YOU SURE?</h2>
              <p style={{ color: '#ff8888', fontSize: 11, marginBottom: 20 }}>
                All forensic evidence for investigation <strong>{deleteTarget}</strong> will be permanently destroyed across all assets. This action is irreversible.
              </p>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDeleteCase} style={btnAbort}>CANCEL</button>
                <button onClick={() => setDeleteStep(3)} style={{ ...btnDeploy, background: '#ff4141', color: '#000' }}>YES, I AM SURE</button>
              </div>
            </>)}

            {deleteStep === 3 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>VERIFY YOU ARE HUMAN</h2>
              <p style={{ color: '#ccc', fontSize: 11, marginBottom: 12 }}>Solve this to continue:</p>
              <p style={{ color: '#ffaa00', fontSize: 20, fontWeight: 'bold', marginBottom: 16, textAlign: 'center', letterSpacing: 2 }}>
                {deleteMath.a} {deleteMath.op} {deleteMath.b} = ?
              </p>
              <input value={deleteMathAnswer} onChange={e => setDeleteMathAnswer(e.target.value)}
                placeholder="ENTER ANSWER" autoFocus
                style={{ ...inputStyle, textAlign: 'center', fontSize: 14, marginBottom: 16 }} />
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDeleteCase} style={btnAbort}>CANCEL</button>
                <button onClick={() => {
                  if (parseInt(deleteMathAnswer) === mathAnswer()) setDeleteStep(4);
                  else { setDeleteMathAnswer(''); alert('INCORRECT. Try again.'); }
                }} style={{ ...btnDeploy, background: '#ff4141', color: '#000' }}>VERIFY</button>
              </div>
            </>)}

            {deleteStep === 4 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>FINAL WARNING</h2>
              <p style={{ color: '#ff8888', fontSize: 11, marginBottom: 8 }}>Type the investigation name to confirm permanent deletion:</p>
              <p style={{ color: '#ffaa00', fontSize: 12, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>{deleteTarget}</p>
              <input value={deleteConfirmText} onChange={e => setDeleteConfirmText(e.target.value)}
                placeholder={`TYPE: ${deleteTarget}`} autoFocus
                style={{ ...inputStyle, marginBottom: 16 }} />
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDeleteCase} style={btnAbort}>CANCEL</button>
                <button disabled={deleteConfirmText !== deleteTarget} onClick={confirmDeleteCase}
                  style={{ ...btnDeploy,
                    background: deleteConfirmText === deleteTarget ? '#ff4141' : '#1a0000',
                    color: deleteConfirmText === deleteTarget ? '#000' : '#ff4141',
                    cursor: deleteConfirmText === deleteTarget ? 'pointer' : 'not-allowed',
                    opacity: deleteConfirmText === deleteTarget ? 1 : 0.4 }}>
                  PERMANENTLY DELETE
                </button>
              </div>
            </>)}

          </div>
        </div>
      )}

    </div>
  );
}

// STYLES
const modalOverlay   = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.99)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 };
const modalContent   = { background: '#000', border: '1px solid #111', padding: '60px', width: '1100px', maxHeight: '95vh', overflowY: 'auto' };
const inputStyle     = { width: '100%', background: '#050505', border: '1px solid #1a1a1a', color: '#eee', padding: '15px', marginBottom: '25px', fontSize: '13px', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' };
const staffStorageBox= { background: '#050505', border: '1px solid #111', minHeight: '140px', padding: '15px', display: 'flex', flexWrap: 'wrap', gap: '10px' };
const scrollBox      = { height: '380px', overflowY: 'auto', background: '#050505', border: '1px solid #111', padding: '15px' };
const itemStyle      = { padding: '12px', border: '1px solid #111', fontSize: '11px', cursor: 'pointer', marginBottom: '8px', transition: 'all 0.2s' };
const labelStyle     = { color: '#888', fontSize: '10px', fontWeight: 'bold', display: 'block', marginBottom: '10px', letterSpacing: '1px' };
const headerFlex     = { display: 'flex', justifyContent: 'space-between', marginBottom: '80px', alignItems: 'center' };
const titleGlow      = { color: '#00ff41', letterSpacing: '8px', fontSize: '24px', margin: 0 };
const btnDeploy      = { background: '#00ff41', color: '#000', border: 'none', padding: '18px 40px', fontWeight: 900, cursor: 'pointer', letterSpacing: '1px', fontFamily: 'monospace' };
const btnAbort       = { background: 'none', color: '#999', border: '1px solid #222', padding: '18px 40px', cursor: 'pointer', fontFamily: 'monospace' };
const btnTerminate   = { position: 'absolute', top: '20px', right: '20px', background: 'none', border: 'none', color: '#ff4444', fontSize: '24px', cursor: 'pointer', zIndex: 10, fontWeight: 'bold' };
const footerRow      = { display: 'flex', gap: '20px', marginTop: '50px' };
const gridStyle      = { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '30px' };
const caseCardStyle  = { background: '#050505', border: '1px solid #111', padding: '40px', cursor: 'pointer', transition: 'border 0.3s' };
const cardTop        = { color: '#00ff41', fontSize: '10px', letterSpacing: '2px' };
const cardTitle      = { color: '#fff', fontSize: '24px', fontWeight: 900 };
const staffChip      = { background: '#0a0a0a', border: '1px solid #222', padding: '8px 15px', fontSize: '11px', color: '#eee' };
const removeX        = { marginLeft: '12px', color: '#ff4444', cursor: 'pointer', fontWeight: 'bold' };
const modalHeader    = { color: '#00ff41', marginBottom: '40px', fontSize: '18px', fontWeight: 900, letterSpacing: '2px' };
