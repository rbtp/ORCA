import React, { useState, useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import MitreInspector from './components/MitreInspector';
import InvestigationWorkspace from './components/investigations/InvestigationWorkspace';
import ArtifactLibraryEditor from "./components/Tools/ArtifactLibraryEditor";
import InvestigationProfileManager from "./components/Tools/InvestigationProfileManager";
import DetectionCoverage from "./components/Tools/DetectionCoverage";
import IOCManager from "./components/IOCManager.jsx";
import ReportsView from "./components/investigations/ReportsView";
import UserManagement from "./components/management/UserManagement";
import NetworkSettings from "./components/Options/NetworkSettings";
import GeneralSettings from "./components/Options/GeneralSettings";
import VelociraptorModal from "./components/VelociraptorModal";
import AgentDeployModal from "./components/AgentDeployModal";

import { useAuth } from './context/AuthContext';
import LoginScreen from './components/LoginScreen';

export default function App() {
  const { user, logout, loading, sessionExpired } = useAuth();
  const [activeNav, setActiveNav] = useState('Dashboard');
  const [activeSubNav, setActiveSubNav] = useState('MITRE ATT&CK');
  const [activeOptionNav, setActiveOptionNav] = useState('General');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [veloOpen, setVeloOpen] = useState(false);
  const [agentFleetOpen, setAgentFleetOpen] = useState(false);
  const [agentFleet, setAgentFleet] = useState([]);
  const [selectedIntel, setSelectedIntel] = useState(null);

  const [cases, setCases] = useState([]);
  const [dbStatus, setDbStatus] = useState("INITIALIZING...");
  const videoRef = useRef(null);

  const savedSession = JSON.parse(localStorage.getItem('NEO_WORKSPACE_SESSION'));
  const [activeNodes, setActiveNodes] = useState(savedSession?.nodes || []);
  const [activeLinks, setActiveLinks] = useState(savedSession?.links || []);

  const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

  useEffect(() => {
    if (user && activeNav === 'Dashboard') {
      fetch(`${API_BASE}/cases`, {
        credentials: 'include',
      })
        .then(res => {
          if (res.ok) { setDbStatus("CONNECTED_STABLE"); return res.json(); }
          if (res.status === 401) { logout(true); }
          throw new Error();
        })
        .then(data => setCases(data))
        .catch(() => setDbStatus("OFFLINE_ERR_500"));

      fetch(`${import.meta.env.VITE_API_URL}/api/agent/list`, {
        credentials: 'include',
      })
        .then(r => r.ok ? r.json() : [])
        .then(setAgentFleet)
        .catch(() => {});
    }
  }, [activeNav, user, logout]);


  useEffect(() => {
    if (user && activeNav === 'Dashboard' && videoRef.current) {
      videoRef.current.muted = true;
      videoRef.current.defaultMuted = true;
      videoRef.current.play().catch(err => console.warn("VIDEO_PLAY_ERR:", err));
    }
  }, [activeNav, user]);

  useEffect(() => {
    const handleIntelSelect = (event) => {
      const incomingData = event.detail.data;
      if (!incomingData) return;
      setActiveNav('Tools');
      setActiveSubNav('MITRE ATT&CK');
      setSelectedIntel(incomingData);
    };
    window.addEventListener('orca-intel-select', handleIntelSelect);
    return () => window.removeEventListener('orca-intel-select', handleIntelSelect);
  }, []);

  const updateNodeData = (node, type, payload) => {
    let updatedNodes = [...activeNodes];
    if (type === 'COORD_UPDATE') {
      updatedNodes = activeNodes.map(n =>
        n.hostname === node.hostname ? { ...n, ...payload } : n
      );
    }
    setActiveNodes(updatedNodes);
    localStorage.setItem('NEO_WORKSPACE_SESSION', JSON.stringify({
      nodes: updatedNodes,
      links: activeLinks
    }));
  };

  const getMatrixHierarchy = (techs) => {
    if (!techs || !Array.isArray(techs)) return {};
    const hierarchy = {};
    techs.forEach(tech => {
      const techId = tech.t_code || tech.id || "";
      const tactics = Array.isArray(tech.tactic) ? tech.tactic : [tech.tactic || "unassigned"];
      const mitreUrl = `https://attack.mitre.org/techniques/${techId.replace('.', '/')}`;
      tactics.forEach(tactic => {
        const tacKey = tactic.toLowerCase().trim();
        if (!hierarchy[tacKey]) hierarchy[tacKey] = {};
        const isSub = techId.includes('.');
        if (!isSub) {
          if (!hierarchy[tacKey][techId]) {
            hierarchy[tacKey][techId] = { name: tech.name, url: mitreUrl, subs: [] };
          }
        } else {
          const parentId = techId.split('.')[0];
          if (!hierarchy[tacKey][parentId]) {
            hierarchy[tacKey][parentId] = { name: "Parent Technique", url: `https://attack.mitre.org/techniques/${parentId}`, subs: [] };
          }
          hierarchy[tacKey][parentId].subs.push({ id: techId, name: tech.name, url: mitreUrl });
        }
      });
    });
    return hierarchy;
  };

  if (loading) return null;
  if (!user) return <LoginScreen sessionExpired={sessionExpired} />;

  const renderDashboard = () => (
    <div style={{ animation: 'fadeIn 0.5s ease' }}>
      <div style={{ marginBottom: '40px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 style={{ fontSize: '32px', fontWeight: '900', margin: '0', color: '#00ff41' }}>COMMAND_CENTER</h1>
          <div style={{ color: '#444', fontSize: '10px', fontFamily: 'monospace' }}>ORCA_WEB_v1.0.6 // OPERATOR: {user.username.toUpperCase()}</div>
        </div>
        <button onClick={logout} style={{ background: 'none', border: '1px solid #ff4141', color: '#ff4141', padding: '5px 15px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px' }}>
          TERMINATE_SESSION
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 400px', gap: '40px' }}>
        <div>
          <div style={{ border: '1px solid #111', background: '#000', padding: '15px', marginBottom: '30px' }}>
            <div style={{ color: '#00ff41', fontSize: '10px', marginBottom: '15px', fontFamily: 'monospace', display: 'flex', justifyContent: 'space-between' }}>
              <span>[ SITUATION_ROOM_UPLINK ]</span>
              <span style={{ color: dbStatus.includes('STABLE') ? '#00ff41' : '#ff4141' }}>● LIVE_FEED</span>
            </div>
            <div style={{
              position: 'relative', width: '100%', aspectRatio: '16 / 9', overflow: 'hidden',
              clipPath: 'inset(15% 0 15% 0)', backgroundColor: '#050505'
            }}>
              <video
                ref={videoRef} autoPlay muted loop playsInline
                style={{
                  width: '100%', height: '100%', objectFit: 'cover', display: 'block',
                  filter: 'contrast(1.2) brightness(0.8) sepia(0.2) hue-rotate(80deg)'
                }}
              >
                <source src="/briefing.mp4" type="video/mp4" />
              </video>
              <div style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', background: 'linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%)', backgroundSize: '100% 4px', pointerEvents: 'none', zIndex: 1 }} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
            <div style={{ border: '1px solid #111', padding: '20px' }}>
              <div style={{ fontSize: '10px', color: '#444', marginBottom: '10px' }}>DATABASE_STATUS</div>
              <div style={{ fontSize: '18px', color: dbStatus.includes('STABLE') ? '#00ff41' : '#ff4141' }}>{dbStatus}</div>
            </div>
            <div style={{ border: '1px solid #111', padding: '20px', background: 'rgba(255,255,255,0.01)' }}>
              <div style={{ fontSize: '10px', color: '#444', marginBottom: '10px' }}>SYSTEM_INFO</div>
              <div style={{ fontSize: '12px', color: '#555' }}>AUTH_ROLE: {user.role?.toUpperCase() || "USER"}</div>
            </div>
          </div>

          {/* Agent Fleet Widget */}
          <div style={{ border: '1px solid #111', padding: '16px 20px', background: 'rgba(0,255,65,0.01)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div style={{ fontSize: '10px', color: '#444', fontFamily: 'monospace', letterSpacing: 1 }}>AGENT_FLEET</div>
              <button
                onClick={() => setAgentFleetOpen(true)}
                style={{ background: '#00ff41', color: '#000', border: 'none', padding: '5px 14px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px', fontWeight: 'bold' }}>
                ▶ MANAGE / DEPLOY
              </button>
            </div>
            {agentFleet.length === 0 ? (
              <div style={{ fontSize: '11px', color: '#333', fontFamily: 'monospace' }}>NO AGENTS REGISTERED</div>
            ) : (
              <div style={{ display: 'flex', gap: 24 }}>
                <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  <span style={{ color: '#00ff41' }}>● </span>
                  <span style={{ color: '#555' }}>ONLINE: </span>
                  <span style={{ color: '#00ff41', fontWeight: 'bold' }}>{agentFleet.filter(a => a.status === 'ONLINE').length}</span>
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
                  <span style={{ color: '#444' }}>○ </span>
                  <span style={{ color: '#555' }}>OFFLINE: </span>
                  <span style={{ color: '#555', fontWeight: 'bold' }}>{agentFleet.filter(a => a.status === 'OFFLINE').length}</span>
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#333' }}>
                  {agentFleet.filter(a => a.status === 'ONLINE').map(a => a.hostname).join(' · ') || ''}
                </div>
              </div>
            )}
          </div>
        </div>

        <div style={{ borderLeft: '1px solid #111', paddingLeft: '40px' }}>
          <div style={{ color: '#00ff41', fontSize: '10px', marginBottom: '20px', letterSpacing: '2px' }}>[ ACTIVE_INVESTIGATIONS ]</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
            {cases.length > 0 ? cases.map((c, i) => (
              <div key={i} onClick={() => setActiveNav('Investigations')} style={{ border: '1px solid #111', padding: '15px', cursor: 'pointer', background: 'rgba(255,255,255,0.02)' }}>
                <div style={{ fontSize: '13px', color: '#eee', marginBottom: '5px' }}>{c.name}</div>
                <div style={{ fontSize: '9px', color: '#444' }}>LEAD: {c.missionLead}</div>
              </div>
            )) : (
              <div style={{ color: '#222', fontSize: '10px' }}>NO_DATA_RECORDS</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderMitreDossier = () => {
    if (!selectedIntel) return <div style={{ color: '#444', fontFamily: 'monospace' }}>SELECT_INTEL_OBJECT_TO_DECODE...</div>;
    const techs = selectedIntel.linkedTechniques || selectedIntel.techniques || [];
    const hierarchy = getMatrixHierarchy(techs);

    return (
      <div style={{ animation: 'fadeIn 0.5s ease', maxWidth: '1100px' }}>
        <div style={{ marginBottom: '40px', borderBottom: '1px solid #111', paddingBottom: '20px' }}>
          <h1 style={{ fontSize: '36px', fontWeight: '900', margin: '0 0 10px 0', color: '#00ff41', letterSpacing: '-1px' }}>
            {(selectedIntel?.name || selectedIntel?.id || "UNKNOWN_THREAT").toUpperCase()}
          </h1>
          <div style={{ color: '#444', fontSize: '10px', fontFamily: 'monospace', letterSpacing: '2px' }}>
            ID: {selectedIntel.id} // STIX: {selectedIntel.stix_id}
          </div>
        </div>

        <div style={{ marginBottom: '80px' }}>
          <div style={{ color: '#aaa', lineHeight: '1.9', fontSize: '16px' }}>
            {selectedIntel.formattedBody ? (
              <div style={{ whiteSpace: 'pre-wrap' }}>{selectedIntel.formattedBody}</div>
            ) : (
              <ReactMarkdown>{selectedIntel?.description || "NO_DESCRIPTION_AVAILABLE"}</ReactMarkdown>
            )}
          </div>
        </div>

        <div style={{ borderTop: '1px solid #111', paddingTop: '50px' }}>
          <div style={{ fontSize: '13px', color: '#00ff41', marginBottom: '40px', letterSpacing: '4px', fontWeight: 'bold', textAlign: 'center' }}>
            —— SYSTEM_ATT&CK_HIERARCHY ——
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '40px' }}>
            {Object.entries(hierarchy).map(([tactic, techniques]) => (
              <div key={tactic} style={{ border: '1px solid #111', padding: '30px', background: 'rgba(0,0,0,0.3)' }}>
                <div style={{ fontSize: '11px', color: '#444', marginBottom: '25px', borderBottom: '1px solid #222', paddingBottom: '10px', fontWeight: '900' }}>
                  TACTIC // {tactic.toUpperCase()}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(450px, 1fr))', gap: '20px' }}>
                  {Object.entries(techniques).map(([id, data]) => (
                    <div key={id} className="ttp-parent-box" style={{ border: '1px solid #1a1a1a', borderLeft: '3px solid #00ff41', padding: '20px', background: '#080808' }}>
                      <a href={data.url} target="_blank" rel="noreferrer" style={{ color: '#eee', textDecoration: 'none', fontSize: '14px', fontWeight: 'bold' }}>
                        {id} | {data.name}
                      </a>
                      {data.subs?.length > 0 && (
                        <div style={{ marginTop: '15px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                          {data.subs.map(sub => (
                            <div key={sub.id} className="ttp-sub-box" style={{ marginLeft: '15px', padding: '8px', border: '1px solid #111', borderLeft: '2px solid #444' }}>
                              <a href={sub.url} target="_blank" rel="noreferrer" style={{ color: '#888', textDecoration: 'none', fontSize: '11px' }}>
                                <span style={{ color: '#00ff41' }}>↳</span> {sub.id}: {sub.name}
                              </a>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  const renderStaging = (name) => (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '60px', border: '1px dashed #111', color: '#222', fontSize: '10px', fontFamily: 'monospace' }}>
      SYSTEM_STAGING: {name}_MODULE_OFFLINE
    </div>
  );

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#020202', color: '#eee', overflow: 'hidden', filter: 'brightness(var(--text-brightness))' }}>
      <aside style={{ width: isCollapsed ? '80px' : '240px', borderRight: '1px solid #111', display: 'flex', flexDirection: 'column', transition: 'width 0.2s ease' }}>
        <div style={{ padding: '30px', borderBottom: '1px solid #111', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          {!isCollapsed && <span style={{ color: '#00ff41', fontWeight: 'bold', letterSpacing: '4px' }}>ORCA_WEB</span>}
          <button onClick={() => setIsCollapsed(!isCollapsed)} style={{ background: 'none', border: 'none', color: '#333', cursor: 'pointer' }}>{isCollapsed ? '>' : '<'}</button>
        </div>
        <nav style={{ flex: 1, padding: '20px 0' }}>
          {['Dashboard', 'Investigations', 'Tools', 'IOCs', 'Reports', 'Options'].map(item => (
            <div key={item} onClick={() => { setActiveNav(item); if (item === 'Options') setActiveOptionNav('General'); }} style={{ width: '100%', padding: '15px 0', textAlign: 'center', cursor: 'pointer', color: activeNav === item ? '#00ff41' : '#555', fontSize: '12px', background: activeNav === item ? 'rgba(0, 255, 65, 0.05)' : 'transparent', borderLeft: activeNav === item ? '2px solid #00ff41' : '2px solid transparent' }}>
              {isCollapsed ? item[0] : item.toUpperCase()}
            </div>
          ))}
        </nav>
      </aside>

      {activeNav === 'Tools' && (
        <section style={{ width: '220px', borderRight: '1px solid #111', background: '#030303' }}>
          <div style={{ padding: '30px', color: '#333', fontSize: '9px', letterSpacing: '2px' }}>SUB_MODULES</div>
          <nav>
            {['MITRE ATT&CK', 'Detection Coverage', 'Artifact Library Editor', 'Investigation Profiles'].map(item => (
              <div key={item} onClick={() => setActiveSubNav(item)} style={{ padding: '12px 30px', cursor: 'pointer', fontSize: '11px', color: activeSubNav === item ? '#eee' : '#333', background: activeSubNav === item ? 'rgba(0, 255, 65, 0.03)' : 'transparent', borderLeft: activeSubNav === item ? '2px solid #00ff41' : '2px solid transparent' }}>{item}</div>
            ))}
          </nav>
        </section>
      )}

      {activeNav === 'Options' && (
        <section style={{ width: '220px', borderRight: '1px solid #111', background: '#030303' }}>
          <div style={{ padding: '30px', color: '#333', fontSize: '9px', letterSpacing: '2px' }}>SYSTEM_PREFERENCES</div>
          <nav>
            {['General', 'Network'].map(item => (
              <div key={item} onClick={() => setActiveOptionNav(item)} style={{ padding: '12px 30px', cursor: 'pointer', fontSize: '11px', color: activeOptionNav === item ? '#eee' : '#333', background: activeOptionNav === item ? 'rgba(0, 255, 65, 0.03)' : 'transparent', borderLeft: activeOptionNav === item ? '2px solid #00ff41' : '2px solid transparent' }}>{item.toUpperCase()}</div>
            ))}
            {user?.role === 'admin' && (
              <div onClick={() => setActiveOptionNav('User Management')} style={{ padding: '12px 30px', cursor: 'pointer', fontSize: '11px', color: activeOptionNav === 'User Management' ? '#00ff41' : '#ffb400', background: activeOptionNav === 'User Management' ? 'rgba(0, 255, 65, 0.03)' : 'transparent', borderLeft: activeOptionNav === 'User Management' ? '2px solid #00ff41' : '2px solid transparent' }}>
                USER_REGISTRY
              </div>
            )}
            <div
              onClick={() => setVeloOpen(true)}
              style={{ padding: '12px 30px', cursor: 'pointer', fontSize: '11px', color: veloOpen ? '#00ff41' : '#333', background: veloOpen ? 'rgba(0, 255, 65, 0.03)' : 'transparent', borderLeft: veloOpen ? '2px solid #00ff41' : '2px solid transparent' }}
            >
              VELOCIRAPTOR
            </div>
          </nav>
        </section>
      )}

      {activeNav === 'Tools' && activeSubNav === 'MITRE ATT&CK' && <MitreInspector />}

      <main style={{ flex: 1, background: '#050505', overflowY: 'auto' }}>
        {activeNav === 'Reports' ? (
          <ReportsView />
        ) : activeNav === 'Investigations' ? (
          <InvestigationWorkspace activeNodes={activeNodes} activeLinks={activeLinks} updateNodeData={updateNodeData} />
        ) : (
          <div style={{ padding: '60px' }}>
            {activeNav === 'Dashboard' ? renderDashboard() :
              activeNav === 'IOCs' ? <IOCManager cases={cases} /> :
              activeNav === 'Options' ? (
                activeOptionNav === 'User Management' ? <UserManagement /> :
              activeOptionNav === 'Network' ? <NetworkSettings /> :
              activeOptionNav === 'General' ? <GeneralSettings /> :
              renderStaging(activeOptionNav.toUpperCase())
              ) :
              activeNav !== 'Tools' ? renderStaging(activeNav.toUpperCase()) :
              activeSubNav === 'MITRE ATT&CK' ? renderMitreDossier() :
              activeSubNav === 'Artifact Library Editor' ? <ArtifactLibraryEditor /> :
              activeSubNav === 'Investigation Profiles' ? <InvestigationProfileManager /> :
              activeSubNav === 'Detection Coverage' ? <DetectionCoverage /> :
              renderStaging(activeSubNav)}
          </div>
        )}
      </main>

      <VelociraptorModal isOpen={veloOpen} onClose={() => setVeloOpen(false)} />
      <AgentDeployModal isOpen={agentFleetOpen} onClose={() => setAgentFleetOpen(false)} />

      <style>{`
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .ttp-parent-box:hover { border-color: #222 !important; background: #0b0b0b !important; transform: translateX(4px); }
        .ttp-sub-box:hover { border-color: #333 !important; border-left-color: #00ff41 !important; background: rgba(0, 255, 65, 0.05) !important; transform: translateX(6px); }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #050505; }
        ::-webkit-scrollbar-thumb { background: #1a1a1a; }
        ::-webkit-scrollbar-thumb:hover { background: #00ff41; }
      `}</style>
    </div>
  );
}
