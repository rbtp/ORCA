import React, { useState, useEffect, useRef } from 'react';
import NetworkMap from './NetworkMap';
import AssetActionTab from './AssetActionTab';
import EvidenceWindow from './EvidenceWindow';
import { TimelineViewer } from './EvidenceWindow';
import CollabNotificationTray from './CollabNotificationTray';
import { useCollaboration } from './useCollaboration';

// FORM_FACTOR is never read by /threat-profile's technique filtering (only
// a.os is -- see mitre_routes.py) so it isn't filtered by ASSET_TYPE or
// OPERATING_SYSTEM at all: a cascade here wouldn't change which MITRE
// techniques get applied, so per the standing rule it's not worth having.
// One flat list, always available.
const ALL_FORM_FACTORS = ['Laptop', 'Desktop', 'Server Rack', 'Virtual Machine', 'Container', 'Embedded', 'Switch', 'Router', 'Firewall', 'Load Balancer', 'Access Point', 'IDS/IPS', 'Proxy', 'Other'];

export default function CaseDetail({
  caseData, onBack, onRefresh,
  memSummaries = {}, setMemSummaries,
  avSummaries = {}, setAvSummaries,
  vulnSummaries = {}, setVulnSummaries,
  pkgData, setPkgData,
  pkgProgress, setPkgProgress,
  pkgExpanded, setPkgExpanded,
  pkgGenerating, setPkgGenerating,
  pkgCopied, setPkgCopied,
  deployStatus, setDeployStatus,
  deployRunning, setDeployRunning,
  startProgressPolling, fetchPkgProgress,
}) {
  const [activeTab, setActiveTab] = useState(
  'OVERVIEW'
  );
  const [notes, setNotes]                   = useState([]);
  const [newNote, setNewNote]               = useState('');
  const [noteType, setNoteType]             = useState('NOTE');
  const [showAssetModal, setShowAssetModal] = useState(false);
  const [editingConfig, setEditingConfig]   = useState(null);
  const [configBuffer, setConfigBuffer]     = useState('');
  const [completion, setCompletion]         = useState(null);

  const [investigatingAssetId, setInvestigatingAssetId] = useState(null);
  const [isEvidenceOpen, setIsEvidenceOpen]             = useState(false);
  const [evidenceTacticList, setEvidenceTacticList]     = useState([]);
  const [isFetchingTactics, setIsFetchingTactics]       = useState(false);

  const [timelineAssetId, setTimelineAssetId]           = useState(null);
  const [isTimelineOpen, setIsTimelineOpen]             = useState(false);
  const [deleteTarget, setDeleteTarget]                 = useState(null);
  const [deleteStep, setDeleteStep]                     = useState(0);
  const [deleteMathAnswer, setDeleteMathAnswer]         = useState('');
  const [deleteConfirmText, setDeleteConfirmText]       = useState('');
  const [deleteMath, setDeleteMath]                     = useState({ a: 0, b: 0, op: '+' });

  const [activeNodes, setActiveNodes]     = useState([]);
  const [activeLinks, setActiveLinks]     = useState([]);
  const [isMaximized, setIsMaximized]     = useState(false);
  const [saveStatus, setSaveStatus]       = useState('READY');
  const [linkForm, setLinkForm]           = useState(null);
  const [editDetailsForm, setEditDetailsForm] = useState(null);
  const [assignableUsers, setAssignableUsers] = useState([]);
  const [assignedUsers, setAssignedUsers]     = useState([]);
  const [assetModes, setAssetModes]       = useState({});
  const [mountSessions, setMountSessions] = useState({});
  const [mountExpanded, setMountExpanded] = useState({});
  const [mountForms, setMountForms]       = useState({});
  const [mountLoading, setMountLoading]   = useState({});
  const [mountAgents, setMountAgents]     = useState([]);

  // Deploy state
  const getDefaultTransport = () => {
    const v = localStorage.getItem('orca_default_transport');
    return (v === 'WINRM' || v === 'SMB_TASK') ? v : 'SMB_TASK';
  };
  const [deployOpen, setDeployOpen]           = useState(false);
  const [deploySelected, setDeploySelected]   = useState(new Set());
  const [deployCreds, setDeployCreds]         = useState({ username: '', password: '', remoteDir: '', transport: getDefaultTransport() });
  const [deployShowPass, setDeployShowPass]   = useState(false);
  const deployAbortRef                        = useRef(false);
  const autoSaveTimerRef                      = useRef(null);

  // Triage state
  const [triageCategories, setTriageCategories] = useState([]);
  const [triageSelected, setTriageSelected]     = useState(new Set());
  const [triageCreds, setTriageCreds]           = useState({ username: '', password: '', transport: getDefaultTransport(), domain: '' });
  const [triageRunning, setTriageRunning]       = useState(false);
  const [triageStatus, setTriageStatus]         = useState({});
  const triageAbortRef                          = useRef(false);

  const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

  const getAuthHeaders = () => ({ 'Content-Type': 'application/json' });

  const getCurrentUserRole = () => {
    try {
      const userStr = localStorage.getItem('orca_user');
      if (!userStr) return 'analyst';
      return JSON.parse(userStr).role || 'analyst';
    } catch { return 'analyst'; }
  };
  const userRole = getCurrentUserRole();

  const collab       = useCollaboration();
  const currentAsset = caseData.assets?.find(a => String(a.id) === String(investigatingAssetId));
  const caseName     = caseData.name || caseData.case_name;

  // ── Map background image ─────────────────────────────────────────────────
  // Bumped after every upload/clear so the <image> tag's URL changes and the
  // browser can't serve a stale cached copy of the old background under the
  // same path -- auth is cookie-based (see getAuthHeaders' lack of an
  // Authorization header), so a plain image URL works without a manual
  // fetch+blob dance; same-origin <img>/<image> requests send cookies
  // automatically.
  const [mapBackgroundVersion, setMapBackgroundVersion] = useState(0);
  const mapBackgroundUrl = `${API_BASE}/cases/${encodeURIComponent(caseName)}/map-background?v=${mapBackgroundVersion}`;

  const handleUploadMapBackground = async (file) => {
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/map-background`, {
        method: 'PUT', credentials: 'include', body: fd,
      });
      if (res.ok) setMapBackgroundVersion(v => v + 1);
      else alert('Could not upload map background.');
    } catch { alert('Could not upload map background.'); }
  };

  const handleClearMapBackground = async () => {
    if (!window.confirm('Remove the map background image?')) return;
    try {
      await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/map-background`, {
        method: 'DELETE', credentials: 'include',
      });
      setMapBackgroundVersion(v => v + 1);
    } catch { alert('Could not remove map background.'); }
  };

  // ── Edit investigation details (lead/team/unit/ops/country) ────────────────
  // Assignment picker options + this case's current assignments load
  // whenever the case changes, not just when the modal opens, so the
  // ASSIGNED_TO badge on the case header (visible without opening anything)
  // stays current -- that's the actual "know what you're assigned to"
  // ask, the modal is just where it gets edited.
  useEffect(() => {
    fetch(`${API_BASE}/users/assignable`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.ok ? r.json() : [])
      .then(setAssignableUsers)
      .catch(() => setAssignableUsers([]));
  }, []);

  useEffect(() => {
    if (!caseName) return;
    fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assignments`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.ok ? r.json() : [])
      .then(setAssignedUsers)
      .catch(() => setAssignedUsers([]));
  }, [caseName]);

  const openEditDetails = () => setEditDetailsForm({
    missionLead: caseData.missionLead || '',
    teamName:    caseData.teamName || '',
    support:     caseData.support || '',
    personnel:   caseData.personnel || '',
    country:     caseData.country || '',
    assignedIds: assignedUsers.map(u => u.id),
  });

  const toggleAssignedUser = (userId) => {
    setEditDetailsForm(prev => ({
      ...prev,
      assignedIds: prev.assignedIds.includes(userId)
        ? prev.assignedIds.filter(id => id !== userId)
        : [...prev.assignedIds, userId],
    }));
  };

  const handleSaveDetails = async () => {
    try {
      const res = await fetch(`${API_BASE}/cases`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({
          name: caseName,
          missionLead: editDetailsForm.missionLead,
          teamName: editDetailsForm.teamName,
          support: editDetailsForm.support,
          personnel: editDetailsForm.personnel,
          country: editDetailsForm.country,
          // POST /cases is an upsert keyed on name and overwrites every one
          // of these columns unconditionally -- groups/case_type must be
          // carried through unchanged here or this save would silently wipe
          // the case's MITRE actor-group selection / revert an
          // INCIDENT_RESPONSE case back to a plain INVESTIGATION.
          groups: caseData.groups || [],
          case_type: caseData.case_type || 'INVESTIGATION',
        }),
      });
      await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assignments`, {
        method: 'PUT', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ user_ids: editDetailsForm.assignedIds }),
      });
      setAssignedUsers(assignableUsers.filter(u => editDetailsForm.assignedIds.includes(u.id)));
      if (res.ok) {
        setEditDetailsForm(null);
        if (onRefresh) onRefresh();
      } else {
        alert('Could not save investigation details.');
      }
    } catch { alert('Could not save investigation details.'); }
  };

  useEffect(() => {
    if (caseData.assets) {
      setAssetModes(prev => {
        const next = { ...prev };
        caseData.assets.forEach(a => {
          if (!next[String(a.id)]) next[String(a.id)] = a.analysis_mode || 'UNKNOWN';
        });
        return next;
      });
    }
  }, [caseData.assets]);

  // collab.techniqueStatuses otherwise only gets populated for an asset once
  // its Evidence Window has been opened this session -- the network map's
  // status coloring needs it for every asset up front, so load it here too.
  useEffect(() => {
    (caseData.assets || []).forEach(a => collab.loadTechniqueStatuses(a.id));
  }, [caseData.assets]);

  const loadCompletion = async () => {
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/completion`, { credentials: 'include', headers: getAuthHeaders() });
      if (res.ok) setCompletion(await res.json());
    } catch {}
  };

  useEffect(() => { loadCompletion(); }, [caseName]);

  // The counts above are otherwise a one-time snapshot from initial case
  // load -- collab.techniqueStatuses changes on every claim/submit/
  // kickback/close anywhere in the case (live SSE, not just this analyst's
  // own actions), so re-pull the aggregate whenever it does instead of
  // requiring a manual page reload to see the overview catch up.
  useEffect(() => { loadCompletion(); }, [collab.techniqueStatuses]);

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL}/api/agent/list`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.ok ? r.json() : [])
      .then(data => setMountAgents((data || []).filter(a => a.status === 'ONLINE' && (a.capabilities || []).includes('aim'))))
      .catch(() => setMountAgents([]));
  }, []);

  const handleInvestigateAsset = (id) => {
    setIsEvidenceOpen(false);
    setInvestigatingAssetId(null);
    setTimeout(() => setInvestigatingAssetId(id), 0);
  };

  useEffect(() => {
    if (!investigatingAssetId) return;
    const identifier = caseName || caseData.country;
    if (!identifier) { setEvidenceTacticList([]); setIsEvidenceOpen(true); return; }
    setIsFetchingTactics(true);
    fetch(`${API_BASE}/threat-profile/${encodeURIComponent(identifier)}?asset_id=${investigatingAssetId}`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.json())
      .then(data => { setEvidenceTacticList(Array.isArray(data) ? data : []); setIsEvidenceOpen(true); })
      .catch(() => { setEvidenceTacticList([]); setIsEvidenceOpen(true); })
      .finally(() => setIsFetchingTactics(false));
  }, [investigatingAssetId]);

  const handleCloseEvidence = () => {
    if (investigatingAssetId) collab.releaseTechnique(investigatingAssetId, '__ALL__').catch(() => {});
    setIsEvidenceOpen(false);
    setInvestigatingAssetId(null);
    setEvidenceTacticList([]);
    loadCompletion();
  };

  const handleOpenTimeline = (id) => {
    setTimelineAssetId(id);
    setIsTimelineOpen(true);
  };

  const openDeleteAsset = (asset) => {
    const ops = ['+', '-', '*'];
    const op  = ops[Math.floor(Math.random() * ops.length)];
    const a   = Math.floor(Math.random() * 20) + 5;
    const b   = Math.floor(Math.random() * 10) + 2;
    setDeleteMath({ a, b, op });
    setDeleteMathAnswer('');
    setDeleteConfirmText('');
    setDeleteTarget(asset);
    setDeleteStep(1);
  };

  const closeDelete = () => { setDeleteStep(0); setDeleteTarget(null); setDeleteMathAnswer(''); setDeleteConfirmText(''); };

  const confirmDeleteAsset = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/assets/${deleteTarget.id}`,
        { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || `HTTP ${res.status}`);
      }
      closeDelete();
      if (onRefresh) onRefresh();
    } catch(e) { alert('DELETE FAILED: ' + e.message); }
  };

  const mathAnswer = () => {
    const { a, b, op } = deleteMath;
    return op === '+' ? a + b : op === '-' ? a - b : a * b;
  };

  useEffect(() => {
    const rawMap = caseData.mapData || caseData.map_data;
    if (rawMap) {
      try {
        const parsed = typeof rawMap === 'string' ? JSON.parse(rawMap) : rawMap;
        if (parsed?.nodes) { setActiveNodes(parsed.nodes || []); setActiveLinks(parsed.links || []); }
        else if (Array.isArray(parsed)) { setActiveNodes(parsed); setActiveLinks([]); }
      } catch (e) { console.error('MAP_REHYDRATION_ERROR:', e); }
    }
  }, [caseData]);

  useEffect(() => {
    if (activeNodes.length === 0 && activeLinks.length === 0) return;
    if (autoSaveTimerRef.current) clearTimeout(autoSaveTimerRef.current);
    autoSaveTimerRef.current = setTimeout(() => {
      fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/map-sync`, {
        method: 'POST',
        credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ nodes: activeNodes, links: activeLinks }),
      }).catch(() => {});
    }, 2000);
    return () => { if (autoSaveTimerRef.current) clearTimeout(autoSaveTimerRef.current); };
  }, [activeNodes, activeLinks]);

  const saveMapLayout = async () => {
    setSaveStatus('SAVING...');
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/map-sync`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ nodes: activeNodes || [], links: activeLinks || [] }),
      });
      if (res.ok) { setSaveStatus('SAVED_SUCCESSFULLY'); setTimeout(() => setSaveStatus('READY'), 2000); }
      else setSaveStatus('ERROR');
    } catch { setSaveStatus('ERROR'); }
  };

  useEffect(() => {
    fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/notes/v2`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.json()).then(setNotes).catch(() => setNotes([]));
  }, [caseName]);

  const handleAddNote = async () => {
    if (!newNote.trim()) return;
    const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/notes/v2`, {
      method: 'POST', credentials: 'include', headers: getAuthHeaders(),
      body: JSON.stringify({ text: newNote, note_type: noteType }),
    });
    if (res.ok) {
      const d = await res.json();
      setNotes(prev => [...prev, { text: newNote, time: d.time, type: noteType, author_initials: d.author_initials }]);
      setNewNote('');
    }
  };

  const [assetForm, setAssetForm] = useState({
    hostname: '', ip: '', subnet: '255.255.255.0', gateway: '', mac: '',
    type: 'Workstation', os: 'Windows', version: '10', formFactor: 'Laptop',
    assetNotes: '', analysisMode: 'UNKNOWN',
  });

  const handleRegisterAsset = async () => {
    try {
      const res = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assets`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(), body: JSON.stringify(assetForm),
      });
      if (res.ok) {
        if (assetForm.analysisMode !== 'UNKNOWN') {
          const assetsRes = await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assets`, { credentials: 'include', headers: getAuthHeaders() });
          const assets = await assetsRes.json();
          const newAsset = assets.find(a => a.hostname === assetForm.hostname);
          if (newAsset) {
            await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assets/${newAsset.id}/mode`, {
              method: 'PATCH', credentials: 'include', headers: getAuthHeaders(),
              body: JSON.stringify({ analysis_mode: assetForm.analysisMode }),
            });
            setAssetModes(prev => ({ ...prev, [String(newAsset.id)]: assetForm.analysisMode }));
          }
        }
        setShowAssetModal(false);
        if (onRefresh) onRefresh();
      }
    } catch (err) { console.error(err); }
  };

  const loadMountSessions = async (assetId) => {
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/${assetId}/mounts`, { credentials: 'include', headers: getAuthHeaders() });
      if (r.ok) { const data = await r.json(); setMountSessions(prev => ({ ...prev, [String(assetId)]: data })); }
    } catch {}
  };

  const handleMount = async (assetId) => {
    const form = mountForms[String(assetId)] || {};
    if (!form.imagePath || !form.agentId) return;
    setMountLoading(prev => ({ ...prev, [String(assetId)]: true }));
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/mount`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ asset_id: assetId, agent_id: form.agentId, image_path: form.imagePath, drive_letter: form.driveLetter || null, provider: form.provider || 'auto', readonly: true }),
      });
      const d = await r.json();
      if (r.ok) {
        setAssetModes(prev => ({ ...prev, [String(assetId)]: 'DEAD_DISK_LOCAL' }));
        if (d.drive_letter) setMountForms(prev => ({ ...prev, [String(assetId)]: { ...form, driveLetter: d.drive_letter } }));
        await loadMountSessions(assetId);
        if (onRefresh) onRefresh();
      } else { alert('MOUNT_ERROR: ' + (d.detail || 'Unknown error')); }
    } catch (e) { alert('MOUNT_ERROR: ' + e.message); }
    finally { setMountLoading(prev => ({ ...prev, [String(assetId)]: false })); }
  };

  const handleDismount = async (assetId, mountId) => {
    setMountLoading(prev => ({ ...prev, [String(assetId)]: true }));
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/dismount?asset_id=${assetId}&mount_id=${mountId}`, { method: 'POST', credentials: 'include', headers: getAuthHeaders() });
      const d = await r.json();
      if (r.ok) { await loadMountSessions(assetId); }
      else { alert('DISMOUNT_ERROR: ' + (d.detail || 'Unknown error')); }
    } catch (e) { alert('DISMOUNT_ERROR: ' + e.message); }
    finally { setMountLoading(prev => ({ ...prev, [String(assetId)]: false })); }
  };

  // ── Package handlers ───────────────────────────────────────────────────────

  const handleGeneratePackage = async (assetId) => {
    setPkgGenerating(prev => ({ ...prev, [String(assetId)]: true }));
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/${assetId}/package`, { method: 'POST', credentials: 'include', headers: getAuthHeaders() });
      if (!r.ok) { const e = await r.json(); alert(`PACKAGE_ERROR: ${e.detail || r.statusText}`); return; }
      const data = await r.json();
      setPkgData(prev => ({ ...prev, [String(assetId)]: data }));
      startProgressPolling(assetId);
    } catch (e) { alert(`PACKAGE_ERROR: ${e.message}`); }
    finally { setPkgGenerating(prev => ({ ...prev, [String(assetId)]: false })); }
  };

  const handleRevokePackage = async (assetId) => {
    const pkg = pkgData[String(assetId)];
    if (!pkg?.token) return;
    if (!window.confirm('Revoke this package token? The agent cannot submit further results.')) return;
    try {
      await fetch(`${import.meta.env.VITE_API_URL}/api/packages/${pkg.token}`, { method: 'DELETE', credentials: 'include', headers: getAuthHeaders() });
      setPkgData(prev => { const n = { ...prev }; delete n[String(assetId)]; return n; });
    } catch (e) { alert(`REVOKE_ERROR: ${e.message}`); }
  };

  const handleCopyOneliner = (assetId) => {
    const pkg = pkgData[String(assetId)];
    if (!pkg?.oneliner) return;
    navigator.clipboard.writeText(pkg.oneliner).then(() => {
      setPkgCopied(prev => ({ ...prev, [String(assetId)]: true }));
      setTimeout(() => setPkgCopied(prev => ({ ...prev, [String(assetId)]: false })), 2000);
    });
  };

  const pkgExpiresIn = (isoStr) => {
    if (!isoStr) return '';
    const diff = new Date(isoStr + 'Z') - new Date();
    if (diff <= 0) return 'EXPIRED';
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    return `${h}h ${m}m`;
  };

  // ── Deploy handlers ────────────────────────────────────────────────────────

  const DEPLOY_PHASES = ['STAGING', 'CONNECTING', 'AUTHENTICATING', 'DEPLOYING', 'EXECUTING', 'COLLECTING'];

  const phaseColor = (phase) => ({
    STAGING: '#00bfff', CONNECTING: '#ffaa00', AUTHENTICATING: '#ffaa00', DEPLOYING: '#00bfff',
    EXECUTING: '#00bfff', COLLECTING: '#00ff41', COMPLETE: '#00ff41', ERROR: '#ff4444'
  }[phase] || '#777');

  const phaseIndex = (phase) => DEPLOY_PHASES.indexOf(phase);

  const toggleDeploySelect = (assetId) => {
    setDeploySelected(prev => {
      const next = new Set(prev);
      next.has(assetId) ? next.delete(assetId) : next.add(assetId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    const all = caseData.assets?.map(a => a.id) || [];
    setDeploySelected(deploySelected.size === all.length ? new Set() : new Set(all));
  };

  const handleDeploy = async () => {
    if (!deployCreds.username || !deployCreds.password) { alert('CREDENTIALS_REQUIRED'); return; }
    if (deploySelected.size === 0) { alert('NO_TARGETS: Select at least one asset.'); return; }

    setDeployRunning(true);
    deployAbortRef.current = false;

    const initial = {};
    deploySelected.forEach(id => { initial[String(id)] = { phase: 'CONNECTING', message: 'Queued...', error: null }; });
    setDeployStatus(initial);

    const expanded = {};
    deploySelected.forEach(id => { expanded[String(id)] = true; });
    setPkgExpanded(prev => ({ ...prev, ...expanded }));

    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/deploy/bulk`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ asset_ids: Array.from(deploySelected), username: deployCreds.username, password: deployCreds.password, remote_dir: deployCreds.remoteDir || null, transport: deployCreds.transport }),
      });

      if (!r.ok) { const e = await r.json(); alert(`DEPLOY_ERROR: ${e.detail || r.statusText}`); setDeployRunning(false); return; }

      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        if (deployAbortRef.current) break;
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const update = JSON.parse(line);
            setDeployStatus(prev => ({ ...prev, [String(update.asset_id)]: { phase: update.phase, message: update.message, error: update.error || null } }));
            if (update.phase === 'COLLECTING') {
              setPkgData(prev => ({
                ...prev,
                [String(update.asset_id)]: prev[String(update.asset_id)] || { technique_count: '?', oneliner: null, expires_at: null, token: null }
              }));
              startProgressPolling(update.asset_id);
            }
          } catch {}
        }
      }
    } catch (e) { console.error('DEPLOY_STREAM_ERROR:', e); }

    setDeployRunning(false);
  };

  const deployComplete = deploySelected.size > 0 && Array.from(deploySelected).every(id => {
    const s = deployStatus[String(id)];
    return s && (s.phase === 'COLLECTING' || s.phase === 'COMPLETE' || s.phase === 'ERROR');
  });

  // ── Triage handlers ────────────────────────────────────────────────────────

  useEffect(() => {
    if ((caseData.case_type || 'INVESTIGATION') !== 'INCIDENT_RESPONSE') return;
    fetch(`${import.meta.env.VITE_API_URL}/api/deploy/triage-categories`, { credentials: 'include', headers: getAuthHeaders() })
      .then(r => r.json())
      .then(d => { setTriageCategories(d.categories || []); setTriageSelected(new Set(d.categories || [])); })
      .catch(() => {});
  }, []);

  const toggleTriageCategory = (cat) => {
    setTriageSelected(prev => { const n = new Set(prev); n.has(cat) ? n.delete(cat) : n.add(cat); return n; });
  };

  const handleTriage = async () => {
    if (!deployCreds.username || !deployCreds.password) { alert('CREDENTIALS_REQUIRED'); return; }
    if (deploySelected.size === 0) { alert('NO_TARGETS: Select at least one asset.'); return; }
    if (triageSelected.size === 0) { alert('NO_CATEGORIES: Select at least one triage category.'); return; }
    setTriageRunning(true);
    triageAbortRef.current = false;
    const initial = {};
    deploySelected.forEach(id => { initial[String(id)] = { phase: 'STAGING', message: 'Queued...' }; });
    setTriageStatus(initial);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/deploy/triage`, {
        method: 'POST', credentials: 'include', headers: getAuthHeaders(),
        body: JSON.stringify({ asset_ids: Array.from(deploySelected), username: deployCreds.username, password: deployCreds.password, categories: Array.from(triageSelected), trigger_transport: triageCreds.transport, domain: triageCreds.domain || null, remote_dir: deployCreds.remoteDir || null }),
      });
      if (!r.ok) { const e = await r.json(); alert(`TRIAGE_ERROR: ${e.detail || r.statusText}`); setTriageRunning(false); return; }
      const reader = r.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      while (true) {
        if (triageAbortRef.current) break;
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n'); buffer = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const u = JSON.parse(line);
            if (u.asset_id) {
              setTriageStatus(prev => ({ ...prev, [String(u.asset_id)]: { phase: u.phase, message: u.message, error: u.error || null } }));
            }
          } catch {}
        }
      }
    } catch (e) { console.error('TRIAGE_STREAM_ERROR:', e); }
    setTriageRunning(false);
  };

  // ── Map helpers ────────────────────────────────────────────────────────────

  const deployToMap = (asset) => {
    if (!activeNodes.find(n => n.hostname === asset.hostname)) {
      // No x/y here on purpose -- NetworkMap.jsx pins fx/fy to whatever x/y
      // a node has (that's what makes a dragged node stay put), so a
      // hardcoded x/y meant every newly deployed asset landed pinned on the
      // exact same spot, on top of each other, immune to the collision
      // force that would otherwise spread them out. Leaving position unset
      // lets the force simulation place and separate it like any other
      // fresh node.
      setActiveNodes([...activeNodes, { hostname: asset.hostname, ip: asset.ip, mac: asset.mac_address, os: asset.os, version: asset.os_version, type: asset.form_factor, config: '', nodeNote: '' }]);
    }
  };

  const handleInitiateLink = (source, target) => {
    setLinkForm({ id: `link-${Date.now()}`, source: source.hostname, target: target.hostname, link_type: 'WIRED', interface_src: '', interface_dst: '', ip_src: source.ip || '', ip_dst: target.ip || '', vlan: '1' });
  };

  const handleConfirmLink = () => { setActiveLinks(prev => [...prev, linkForm]); setLinkForm(null); };

  const handleDeleteNode = (node) => {
    if (window.confirm(`REMOVE ${node.hostname} FROM WORKSPACE?`)) {
      setActiveNodes(prev => prev.filter(n => n.hostname !== node.hostname));
      setActiveLinks(prev => prev.filter(l => l.source !== node.hostname && l.target !== node.hostname));
    }
  };

  const addInfrastructure = (type) => {
    const id = Math.floor(Math.random() * 999);
    // See deployToMap's comment -- same reason x/y is omitted here.
    setActiveNodes([...activeNodes, { hostname: `${type}_${id}`, ip: '0.0.0.0', mac: 'AUTO_GEN', type, os: 'Firmware_v1.0', config: '', nodeNote: '' }]);
  };

  // A map device dropped from INFRASTRUCTURE_TEMPLATES (addInfrastructure) is
  // purely visual until it's backed by a real row in `assets` -- NetworkMap
  // detects that by hostname match against caseAssets and, if there's no
  // match, offers this instead of "INVESTIGATE_ASSET". Reuses the normal
  // NEW_ASSET_SPECIFICATION modal/pipeline so the user still walks through
  // (and can adjust) every field -- just pre-filled from the device on the
  // map instead of starting blank. Creating with the same hostname is what
  // makes the existing map node pick up the new asset automatically (the
  // merge in NetworkMap.jsx is by hostname), no extra linking step needed.
  const handleCreateAssetFromNode = (node) => {
    if (!window.confirm(`"${node.displayName || node.hostname}" is not in the asset list yet. Create it as an asset now?`)) return;
    const FORM_FACTOR_BY_DEVICE_TYPE = { SWITCH: 'Switch', ROUTER: 'Router', FIREWALL: 'Firewall' };
    setAssetForm({
      ...assetForm,
      hostname: node.hostname,
      ip: node.ip && node.ip !== '0.0.0.0' ? node.ip : '',
      mac: node.mac && node.mac !== 'AUTO_GEN' ? node.mac : '',
      type: 'Network Device',
      os: 'Network',
      formFactor: FORM_FACTOR_BY_DEVICE_TYPE[node.type?.toUpperCase()] || 'Other',
    });
    setShowAssetModal(true);
  };

  const handleUpdateNode = (node, action, data) => {
    if (action === 'COORD_UPDATE') { setActiveNodes(prev => prev.map(n => n.hostname === node.hostname ? { ...n, x: data.x, y: data.y } : n)); return; }
    if (action === 'RENAME') {
      // A cosmetic label override, not a hostname change -- hostname is the
      // D3 link id and the join key against caseAssets (real asset records,
      // artifact_results, etc.), so renaming it in place would silently
      // break both. displayName is map-only, flows through the same
      // map-sync auto-save as everything else here, no backend change needed.
      const v = prompt(`ENTER DISPLAY NAME FOR ${node.hostname} (blank clears it, falls back to hostname):`, node.displayName || '');
      if (v !== null) {
        const trimmed = v.trim();
        setActiveNodes(prev => prev.map(n => n.hostname === node.hostname ? { ...n, displayName: trimmed || undefined } : n));
      }
      return;
    }
    if (action === 'CONFIG') {
      if (['SWITCH', 'ROUTER', 'FIREWALL'].includes(node.type?.toUpperCase())) { setEditingConfig(node); setConfigBuffer(node.config || ''); }
      else { const v = prompt(`ENTER SYSTEM NOTES FOR ${node.hostname}:`, node.nodeNote || ''); if (v !== null) setActiveNodes(prev => prev.map(n => n.hostname === node.hostname ? { ...n, nodeNote: v } : n)); }
      return;
    }
    const field = { 'IP': 'ip', 'NOTE': 'nodeNote' }[action];
    if (field) { const v = prompt(`ENTER ${action} FOR ${node.hostname}:`, node[field] || ''); if (v !== null) setActiveNodes(prev => prev.map(n => n.hostname === node.hostname ? { ...n, [field]: v } : n)); }
  };

  const pct    = completion?.aggregate_completion_pct || 0;
  const pctCol = pct >= 80 ? '#00ff41' : pct >= 40 ? '#ffaa00' : '#ff4444';

  return (
    <div style={{ animation: 'fadeIn 0.3s ease', color: '#fff', fontFamily: 'monospace' }}>
      <CollabNotificationTray notifications={collab.notifications} dismissNotification={collab.dismissNotification} connected={collab.connected} />

      <button onClick={onBack} style={{ background: 'none', border: 'none', color: '#00ff41', cursor: 'pointer', fontSize: '10px', marginBottom: '20px' }}>
        [ BACK_TO_GALLERY ]
      </button>

      <div style={{ marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 16 }}>
          <h1 style={{ fontSize: '42px', fontWeight: 900, margin: '0' }}>{caseName}</h1>
          <button onClick={openEditDetails} style={{ background: 'none', border: '1px solid #333', color: '#999', cursor: 'pointer', fontSize: '10px', fontFamily: 'monospace', padding: '4px 10px', letterSpacing: 1 }}>
            [ EDIT_DETAILS ]
          </button>
        </div>
        <div style={{ color: '#888', fontSize: '10px', marginTop: '5px' }}>CASE_REF: {caseData.country?.toUpperCase()}_INTEL_PRIORITY_1</div>
        <div style={{ color: '#888', fontSize: '10px', marginTop: '5px' }}>
          ASSIGNED_TO: {assignedUsers.length === 0
            ? <span style={{ color: '#555' }}>OPEN — no assignments set, any analyst can act on this case</span>
            : assignedUsers.map(u => `${u.username} [${u.initials}]`).join(', ')}
        </div>
        {completion && (
          <div style={{ marginTop: 12, maxWidth: 480 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>INVESTIGATION_COMPLETION</span>
              <span style={{ color: pctCol, fontSize: 11, fontWeight: 'bold' }}>{pct}%</span>
            </div>
            <div style={{ background: '#1a1a1a', height: 4 }}>
              <div style={{ background: pctCol, height: '100%', width: `${pct}%`, transition: 'width 0.6s ease' }} />
            </div>
            <div style={{ display: 'flex', gap: 16, marginTop: 6 }}>
              {[
                ['TOTAL_TECHNIQUES', completion.total_techniques, '#aaa'],
                ['CLOSED', completion.assets?.reduce((s, a) => s + (a.closed || 0), 0), '#00ff41'],
                ['PENDING_REVIEW', completion.assets?.reduce((s, a) => s + (a.pending_review || 0), 0), '#ffaa00'],
                ['IN_PROGRESS', completion.assets?.reduce((s, a) => s + (a.in_progress || 0), 0), '#9b59ff'],
              ].map(([label, val, col]) => (
                <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <span style={{ color: '#777', fontSize: 8, letterSpacing: 1 }}>{label}</span>
                  <span style={{ color: col, fontSize: 13, fontWeight: 'bold' }}>{val ?? 0}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', gap: '30px', marginBottom: '30px', borderBottom: '1px solid #222' }}>
        {['OVERVIEW', 'ASSETS', 'NETWORK_MAP'].map(tab => (
          <div key={tab} onClick={() => setActiveTab(tab)} style={{ fontSize: '11px', letterSpacing: '2px', cursor: 'pointer', color: activeTab === tab ? '#00ff41' : '#666', borderBottom: activeTab === tab ? '2px solid #00ff41' : '2px solid transparent', paddingBottom: '10px' }}>{tab}</div>
        ))}
        {(caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE' && (
          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', paddingBottom: 10 }}>
            <span style={{ fontSize: 8, letterSpacing: 1, padding: '2px 8px', border: '1px solid #ff4141', color: '#ff4141' }}>⚡ INCIDENT_RESPONSE</span>
          </div>
        )}
      </div>

      <div style={{ minHeight: '500px' }}>

        {/* ── OVERVIEW TAB ── */}
        {activeTab === 'OVERVIEW' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '40px' }}>
            <div style={{ animation: 'fadeIn 0.5s ease' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '10px', marginBottom: '40px' }}>
                <StatTile label="LEAD" val={caseData.missionLead} />
                <StatTile label="TEAM" val={caseData.teamName} />
                <StatTile label="UNIT" val={caseData.support} />
                <StatTile label="OPS"  val={caseData.personnel} />
              </div>
              {completion?.assets?.length > 0 && (
                <div style={{ marginBottom: 30 }}>
                  <div style={{ color: '#888', fontSize: '9px', marginBottom: 10, letterSpacing: 1 }}>ASSET_INVESTIGATION_STATUS</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                    <thead>
                      <tr style={{ color: '#666', borderBottom: '1px solid #222' }}>
                        {['HOSTNAME', 'CLOSED', 'PENDING', 'IN_PROGRESS', 'MALICIOUS', 'CLEAN', 'PCT'].map(h => (
                          <th key={h} style={{ padding: '5px 8px', textAlign: 'left', fontWeight: 'normal' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {completion.assets.map((a, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #111' }}>
                          <td style={{ padding: '6px 8px', color: '#00ff41' }}>{a.hostname}</td>
                          <td style={{ padding: '6px 8px', color: '#00ff41' }}>{a.closed}</td>
                          <td style={{ padding: '6px 8px', color: '#ffaa00' }}>{a.pending_review}</td>
                          <td style={{ padding: '6px 8px', color: '#9b59ff' }}>{a.in_progress}</td>
                          <td style={{ padding: '6px 8px', color: '#ff4444' }}>{a.malicious}</td>
                          <td style={{ padding: '6px 8px', color: '#00ff41' }}>{a.clean}</td>
                          <td style={{ padding: '6px 8px', color: a.completion_pct >= 80 ? '#00ff41' : a.completion_pct >= 40 ? '#ffaa00' : '#ff4444' }}>{a.completion_pct}%</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <div style={{ borderTop: '1px solid #222', paddingTop: '30px' }}>
                <div style={{ color: '#888', fontSize: '10px', marginBottom: '15px' }}>MISSION_TIMELINE_LOG</div>
                <div style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                  <input value={newNote} onChange={e => setNewNote(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleAddNote()} placeholder="APPEND_LOG_DATA..." style={InputStyle} />
                  {(userRole === 'admin' || userRole === 'lead') && (
                    <button onClick={() => setNoteType(t => t === 'NOTE' ? 'BLUF' : 'NOTE')} style={{ ...BtnStyle, background: noteType === 'BLUF' ? '#00ff41' : 'transparent', color: noteType === 'BLUF' ? '#000' : '#777', border: '1px solid #333', padding: '6px 12px', fontSize: 9 }}>
                      {noteType === 'BLUF' ? '★ BLUF' : '☆ BLUF'}
                    </button>
                  )}
                  <button onClick={handleAddNote} style={BtnStyle}>COMMIT</button>
                </div>
                <div style={{ maxHeight: '300px', overflowY: 'auto', background: 'rgba(0,0,0,0.2)', padding: '15px', border: '1px solid #111' }}>
                  {notes.map((n, i) => (
                    <div key={i} style={{ fontSize: '11px', marginBottom: '12px', borderLeft: `2px solid ${n.type === 'BLUF' ? '#00ff41' : '#444'}`, paddingLeft: '15px', background: n.type === 'BLUF' ? 'rgba(0,255,65,0.03)' : 'transparent' }}>
                      <span style={{ color: '#00ff41', marginRight: '8px' }}>[{n.time}]</span>
                      {n.author_initials && <span style={{ color: n.type === 'BLUF' ? '#000' : '#666', background: n.type === 'BLUF' ? '#00ff41' : '#1a1a1a', fontSize: 9, padding: '1px 5px', marginRight: 8 }}>{n.author_initials}</span>}
                      {n.type === 'BLUF' && <span style={{ color: '#00ff41', fontSize: 9, marginRight: 6 }}>★ BLUF</span>}
                      <span style={{ color: n.type === 'BLUF' ? '#00ff41' : '#ccc' }}>{n.text}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <aside style={{ borderLeft: '1px solid #222', paddingLeft: '40px' }}>
              <div style={{ color: '#888', fontSize: '9px', marginBottom: '15px' }}>GEOPOLITICAL_CONTEXT</div>
              <div style={{ fontSize: '12px', color: '#aaa', lineHeight: '1.6' }}>Operational environment confirmed as {caseData.country}. Priority assessment is high.</div>
            </aside>
          </div>
        )}

        {/* ── ASSETS TAB ── */}
        {activeTab === 'ASSETS' && (
          <div style={{ animation: 'fadeIn 0.4s ease' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
              <h3 style={{ fontSize: '11px', color: '#888' }}>SYSTEM_INVENTORY</h3>
              <button onClick={() => setShowAssetModal(true)} style={BtnStyle}>+ REGISTER_NEW_ASSET</button>
            </div>

            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px' }}>
              <thead style={{ color: '#777', textAlign: 'left', borderBottom: '1px solid #222' }}>
                <tr>
                  <th style={{ padding: '10px' }}>HOSTNAME</th>
                  <th>NETWORK_ADDRESSING</th>
                  <th>OS_SPECIFICATION</th>
                  <th>FORM_FACTOR</th>
                  <th>ANALYSIS_MODE</th>
                  <th style={{ width: '240px', textAlign: 'left', paddingLeft: '20px' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {caseData.assets?.map((a, i) => {
                  const aId         = String(a.id);
                  const modeCol     = { LIVE_REMOTE: '#ffaa00', DEAD_DISK_LOCAL: '#9b59ff', DEAD_DISK_REMOTE: '#9b59ff', UNKNOWN: '#555' }[a.analysis_mode] || '#555';
                  const sessions    = mountSessions[aId] || [];
                  const activeMount = sessions.find(s => s.status === 'MOUNTED');
                  const isExpanded  = mountExpanded[aId];
                  const form        = mountForms[aId] || {};
                  const loading     = mountLoading[aId];
                  const wasDeployed = !!deployStatus[aId];

                  return (
                    <React.Fragment key={i}>
                      <tr style={{ borderBottom: isExpanded ? 'none' : '1px solid #111' }}>
                        <td style={{ padding: '15px 10px', color: '#00ff41', fontWeight: 'bold' }}>{a.hostname}</td>
                        <td style={{ color: '#aaa' }}>IP: {a.ip}<br /><span style={{ fontSize: '9px', color: '#bbb' }}>MAC: {a.mac_address}</span></td>
                        <td style={{ color: '#ddd' }}>{a.os} {a.os_version}</td>
                        <td style={{ color: '#ddd' }}>{a.form_factor}</td>
                        <td>
                          <select value={assetModes[aId] || a.analysis_mode || 'UNKNOWN'} onChange={async e => {
                            const mode = e.target.value;
                            setAssetModes(prev => ({ ...prev, [aId]: mode }));
                            await fetch(`${API_BASE}/cases/${encodeURIComponent(caseName)}/assets/${a.id}/mode`, { method: 'PATCH', credentials: 'include', headers: getAuthHeaders(), body: JSON.stringify({ analysis_mode: mode }) });
                            if (onRefresh) onRefresh();
                          }} style={{ background: '#0a0a0a', border: '1px solid #2a2a2a', color: modeCol, fontFamily: 'monospace', fontSize: 9, letterSpacing: 1, padding: '3px 6px', cursor: 'pointer', outline: 'none' }}>
                            {['UNKNOWN', 'LIVE_REMOTE', 'DEAD_DISK_LOCAL', 'DEAD_DISK_REMOTE'].map(m => <option key={m} value={m}>{m}</option>)}
                          </select>
                        </td>
                        <td style={{ width: '420px', padding: '15px 0 15px 20px' }}>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            {isFetchingTactics && String(investigatingAssetId) === String(a.id)
                              ? <span style={{ color: '#666', fontSize: '10px' }}>LOADING...</span>
                              : <AssetActionTab assetId={a.id} assetName={a.hostname} setInvestigatingAsset={setInvestigatingAssetId} setTimelineAsset={handleOpenTimeline} />
                            }
                            <button onClick={() => openDeleteAsset(a)}
                              style={{ background: 'transparent', border: '1px solid #330000', color: '#550000',
                                fontFamily: 'monospace', fontSize: 9, padding: '4px 8px', cursor: 'pointer',
                                letterSpacing: 1, transition: 'all 0.15s' }}
                              onMouseEnter={e => { e.currentTarget.style.borderColor='#ff4141'; e.currentTarget.style.color='#ff4141'; }}
                              onMouseLeave={e => { e.currentTarget.style.borderColor='#330000'; e.currentTarget.style.color='#550000'; }}>
                              ✕ DEL
                            </button>
                            <button onClick={() => { setMountExpanded(prev => ({ ...prev, [aId]: !prev[aId] })); if (!mountSessions[aId]) loadMountSessions(a.id); }}
                              style={{ background: activeMount ? 'rgba(155,89,255,0.15)' : '#0a0a0a', border: `1px solid ${activeMount ? '#9b59ff' : '#2a2a2a'}`, color: activeMount ? '#9b59ff' : '#777', fontFamily: 'monospace', fontSize: 9, padding: '4px 8px', cursor: 'pointer', letterSpacing: 1 }}>
                              {activeMount ? '⏏ MOUNTED' : '⏏ MOUNT'}
                            </button>
                            <button onClick={() => { setPkgExpanded(prev => ({ ...prev, [aId]: !prev[aId] })); fetchPkgProgress(a.id); }}
                              style={{ background: pkgData[aId] ? 'rgba(0,191,255,0.1)' : '#0a0a0a', border: `1px solid ${pkgData[aId] ? '#00bfff' : '#2a2a2a'}`, color: pkgData[aId] ? '#00bfff' : '#777', fontFamily: 'monospace', fontSize: 9, padding: '4px 8px', cursor: 'pointer', letterSpacing: 1 }}>
                              ⬇ PKG
                            </button>
                          </div>
                        </td>
                      </tr>

                      {/* ── Mount panel ── */}
                      {isExpanded && (
                        <tr><td colSpan={6} style={{ padding: '0 0 12px 0', borderBottom: '1px solid #111' }}>
                          <div style={{ background: '#060606', border: '1px solid #1a1a1a', margin: '0 10px', padding: '12px 16px', fontFamily: 'monospace', fontSize: 10 }}>
                            <div style={{ color: '#888', fontSize: 9, letterSpacing: 1, marginBottom: 10 }}>IMAGE_MOUNT_CONTROLLER — {a.hostname.toUpperCase()}</div>
                            {mountAgents.length === 0 && (
                              <div style={{ color: '#ffaa00', fontSize: 9, marginBottom: 8 }}>
                                NO_MOUNT_AGENTS_ONLINE — deploy or install an ORCA agent with Arsenal Image Mounter first (Agent Fleet).
                              </div>
                            )}
                            <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: 10 }}>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 2, minWidth: 250 }}>
                                <span style={{ color: '#666', fontSize: 9 }}>IMAGE_PATH</span>
                                <input value={form.imagePath || ''} onChange={e => setMountForms(prev => ({ ...prev, [aId]: { ...form, imagePath: e.target.value } }))} placeholder="C:\images\suspect.E01 or \\fileserver\evidence\suspect.E01" style={{ background: '#000', border: '1px solid #2a2a2a', color: '#00ff41', fontFamily: 'monospace', fontSize: 10, padding: '5px 8px', outline: 'none' }} />
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 140 }}>
                                <span style={{ color: '#666', fontSize: 9 }}>MOUNT_VIA_AGENT</span>
                                <select value={form.agentId || ''} onChange={e => setMountForms(prev => ({ ...prev, [aId]: { ...form, agentId: e.target.value } }))} style={{ background: '#000', border: '1px solid #2a2a2a', color: '#00ff41', fontFamily: 'monospace', fontSize: 10, padding: '5px 6px', outline: 'none' }}>
                                  <option value="">SELECT_AGENT</option>
                                  {mountAgents.map(ag => <option key={ag.agent_id} value={ag.agent_id}>{ag.hostname}</option>)}
                                </select>
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <span style={{ color: '#666', fontSize: 9 }}>DRIVE_LETTER</span>
                                <select value={form.driveLetter || ''} onChange={e => setMountForms(prev => ({ ...prev, [aId]: { ...form, driveLetter: e.target.value } }))} style={{ background: '#000', border: '1px solid #2a2a2a', color: '#00ff41', fontFamily: 'monospace', fontSize: 10, padding: '5px 6px', outline: 'none' }}>
                                  <option value="">AUTO</option>
                                  {'ABDEFGHIJKLMNOPQRSTUVWXYZ'.split('').map(l => <option key={l} value={l}>{l}:</option>)}
                                </select>
                              </div>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <span style={{ color: '#666', fontSize: 9 }}>PROVIDER</span>
                                <select value={form.provider || 'auto'} onChange={e => setMountForms(prev => ({ ...prev, [aId]: { ...form, provider: e.target.value } }))} style={{ background: '#000', border: '1px solid #2a2a2a', color: '#00ff41', fontFamily: 'monospace', fontSize: 10, padding: '5px 6px', outline: 'none' }}>
                                  {['auto', 'LibEwf', 'DiscUtils', 'LibQcow', 'None'].map(p => <option key={p} value={p}>{p}</option>)}
                                </select>
                              </div>
                              <button onClick={() => handleMount(a.id)} disabled={loading || !form.imagePath || !form.agentId || !!activeMount}
                                style={{ background: activeMount ? '#111' : '#00ff41', color: activeMount ? '#444' : '#000', border: 'none', fontFamily: 'monospace', fontSize: 9, fontWeight: 'bold', padding: '7px 14px', cursor: activeMount ? 'not-allowed' : 'pointer', letterSpacing: 1, opacity: loading ? 0.5 : 1 }}>
                                {loading ? 'MOUNTING...' : activeMount ? 'ALREADY_MOUNTED' : '[ MOUNT_IMAGE ]'}
                              </button>
                            </div>
                            {activeMount && (
                              <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 10px', background: 'rgba(155,89,255,0.06)', border: '1px solid #2a1a4a', marginBottom: 8 }}>
                                <div style={{ display: 'flex', gap: 16 }}>
                                  {[['AGENT', mountAgents.find(ag => ag.agent_id === activeMount.agent_id)?.hostname || activeMount.agent_id], ['DEVICE', activeMount.device_number], ['DRIVE', activeMount.drive_letter ? `${activeMount.drive_letter}:` : '—'], ['PHYSICAL', activeMount.physical_drive], ['PROVIDER', activeMount.provider]].map(([l, v]) => v && (
                                    <div key={l} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                      <span style={{ color: '#bbb', fontSize: 8 }}>{l}</span>
                                      <span style={{ color: '#9b59ff', fontSize: 10 }}>{v}</span>
                                    </div>
                                  ))}
                                </div>
                                <button onClick={() => handleDismount(a.id, activeMount.id)} disabled={loading}
                                  style={{ marginLeft: 'auto', background: 'transparent', border: '1px solid #ff4141', color: '#ff4141', fontFamily: 'monospace', fontSize: 9, padding: '4px 10px', cursor: 'pointer', letterSpacing: 1 }}>
                                  {loading ? 'DISMOUNTING...' : '[ DISMOUNT ]'}
                                </button>
                              </div>
                            )}
                            {sessions.filter(s => s.status === 'DISMOUNTED').length > 0 && (
                              <div style={{ marginTop: 6 }}>
                                <div style={{ color: '#999', fontSize: 8, letterSpacing: 1, marginBottom: 4 }}>MOUNT_HISTORY</div>
                                {sessions.filter(s => s.status === 'DISMOUNTED').map((s, idx) => (
                                  <div key={idx} style={{ display: 'flex', gap: 12, fontSize: 9, color: '#bbb', borderTop: '1px solid #111', padding: '4px 0' }}>
                                    <span>{s.image_path}</span>
                                    <span style={{ color: '#aaa' }}>{s.drive_letter ? `${s.drive_letter}:` : '—'}</span>
                                    <span style={{ color: '#999', marginLeft: 'auto' }}>{new Date(s.mounted_at).toLocaleString()}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </td></tr>
                      )}

                      {/* ── PKG panel ── */}
                      {pkgExpanded[aId] && (
                        <tr><td colSpan={6} style={{ padding: '0 0 12px 0', borderBottom: '1px solid #111' }}>
                          <div style={{ background: '#060606', border: '1px solid #1a1a1a', margin: '0 10px', padding: '12px 16px', fontFamily: 'monospace', fontSize: 10 }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                              <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>REMOTE_COLLECTION — {a.hostname.toUpperCase()}</span>
                              <div style={{ display: 'flex', gap: 8 }}>
                                {!wasDeployed && !pkgData[aId] && (
                                  <button onClick={() => handleGeneratePackage(a.id)} disabled={pkgGenerating[aId]}
                                    style={{ background: 'transparent', border: '1px solid #00bfff', color: '#00bfff', padding: '3px 12px', fontFamily: 'monospace', fontSize: 10, cursor: pkgGenerating[aId] ? 'not-allowed' : 'pointer', opacity: pkgGenerating[aId] ? 0.5 : 1, letterSpacing: 1 }}>
                                    {pkgGenerating[aId] ? 'BUILDING...' : '[ GENERATE_PACKAGE ]'}
                                  </button>
                                )}
                                {pkgData[aId] && (
                                  <button onClick={() => handleRevokePackage(a.id)}
                                    style={{ background: 'transparent', border: '1px solid #ff4141', color: '#ff4141', padding: '3px 12px', fontFamily: 'monospace', fontSize: 9, cursor: 'pointer', letterSpacing: 1 }}>
                                    [ REVOKE ]
                                  </button>
                                )}
                              </div>
                            </div>

                            {wasDeployed && (
                              <div style={{ marginBottom: 12 }}>
                                <div style={{ display: 'flex', gap: 2, marginBottom: 4 }}>
                                  {DEPLOY_PHASES.map((ph, idx) => {
                                    const current = phaseIndex(deployStatus[aId]?.phase);
                                    const isError = deployStatus[aId]?.phase === 'ERROR';
                                    const done    = !isError && idx < current;
                                    const active  = !isError && idx === current;
                                    return <div key={ph} style={{ flex: 1, height: 3, background: (isError && idx === 0) ? '#ff4444' : done ? '#00ff41' : active ? '#ffaa00' : '#222', transition: 'background 0.3s' }} />;
                                  })}
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                  <span style={{ color: phaseColor(deployStatus[aId]?.phase), fontSize: 9, letterSpacing: 1, fontWeight: 'bold' }}>{deployStatus[aId]?.phase}</span>
                                  <span style={{ color: '#888', fontSize: 9 }}>{deployStatus[aId]?.message}</span>
                                </div>
                                {deployStatus[aId]?.error && <div style={{ color: '#ff4444', fontSize: 9, marginTop: 3 }}>{deployStatus[aId].error}</div>}
                              </div>
                            )}

                            {pkgData[aId] && !wasDeployed && (() => {
                              const pkg = pkgData[aId];
                              return (
                                <>
                                  <div style={{ display: 'flex', gap: 16, marginBottom: 10, alignItems: 'center' }}>
                                    <span style={{ color: '#00bfff', fontSize: 10 }}>✓ {pkg.technique_count} TECHNIQUES PACKAGED</span>
                                    <span style={{ color: '#777', fontSize: 9 }}>EXPIRES {pkgExpiresIn(pkg.expires_at)}</span>
                                  </div>
                                  <div style={{ color: '#777', fontSize: 9, marginBottom: 4, letterSpacing: 1 }}>DEPLOY_COMMAND — run as admin on target:</div>
                                  <div style={{ background: '#030303', border: '1px solid #2a2a2a', padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                                    <span style={{ color: '#00ff41', flex: 1, fontSize: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'monospace', display: 'block', paddingBottom: 2 }}>{pkg.oneliner}</span>
                                    <button onClick={() => handleCopyOneliner(a.id)} style={{ background: pkgCopied[aId] ? '#00ff41' : 'transparent', border: `1px solid ${pkgCopied[aId] ? '#00ff41' : '#444'}`, color: pkgCopied[aId] ? '#000' : '#888', fontFamily: 'monospace', fontSize: 9, padding: '3px 10px', cursor: 'pointer', flexShrink: 0, transition: 'all 0.15s' }}>
                                      {pkgCopied[aId] ? '✓ COPIED' : 'COPY'}
                                    </button>
                                  </div>
                                </>
                              );
                            })()}

                            {(() => {
                              const prog = pkgProgress[aId];
                              const total        = prog?.total || 0;
                              const withEvidence = prog?.with_evidence || 0;
                              const noArt        = prog?.no_artifacts || 0;
                              const pending      = prog?.pending || 0;
                              if (total === 0) return null;
                              return (
                                <>
                                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#888', marginBottom: 3 }}>
                                    <span>COLLECTION_PROGRESS</span>
                                    <span style={{ color: '#aaa' }}>{withEvidence + noArt}/{total} PROCESSED</span>
                                  </div>
                                  <div style={{ display: 'flex', height: 5, borderRadius: 2, overflow: 'hidden', background: '#1a1a1a', marginBottom: 4 }}>
                                    <div style={{ width: `${(withEvidence / total) * 100}%`, background: '#00ff41', transition: 'width 0.4s' }} />
                                    <div style={{ width: `${(noArt / total) * 100}%`, background: '#444', transition: 'width 0.4s' }} />
                                    <div style={{ width: `${(pending / total) * 100}%`, background: '#1a1a1a', transition: 'width 0.4s' }} />
                                  </div>
                                  <div style={{ display: 'flex', gap: 12, fontSize: 8, color: '#777' }}>
                                    <span style={{ color: '#00ff41' }}>■ EVIDENCE {withEvidence}</span>
                                    <span style={{ color: '#bbb' }}>■ NO_ARTIFACTS {noArt}</span>
                                    <span>■ PENDING {pending}</span>
                                  </div>
                                  {prog?.package_info?.completed_at && (
                                    <div style={{ color: '#00ff41', fontSize: 9, marginTop: 6 }}>✓ COLLECTION COMPLETE — {new Date(prog.package_info.completed_at + 'Z').toLocaleString()}</div>
                                  )}
                                </>
                              );
                            })()}

                            {(() => {
                              // The aggregate bar above collapses everything to 3 numbers --
                              // this surfaces the per-technique detail the backend already
                              // returns (heartbeat status + timestamp in evidence_summary)
                              // but the UI previously threw away, so a hung technique is
                              // visible as "stalled" instead of indistinguishable from "just
                              // pending, hasn't started yet."
                              const techs = pkgProgress[aId]?.techniques || [];
                              if (techs.length === 0) return null;
                              const now = Date.now();
                              const STALL_MS = 120000;
                              const STATUS_ORDER = { STALLED: 0, RUNNING: 1, PENDING: 2, NO_ARTIFACTS: 3, COMPLETE: 4 };
                              const STATUS_COLOR = { STALLED: '#ff4444', RUNNING: '#ffaa00', PENDING: '#555', NO_ARTIFACTS: '#888', COMPLETE: '#00ff41' };
                              const fmtAge = (ms) => {
                                if (ms === null) return '';
                                const s = Math.floor(ms / 1000);
                                if (s < 60) return `${s}s ago`;
                                const m = Math.floor(s / 60);
                                if (m < 60) return `${m}m ago`;
                                return `${Math.floor(m / 60)}h ago`;
                              };
                              const rows = techs.map(t => {
                                let hb = null;
                                try { hb = t.evidence_summary ? JSON.parse(t.evidence_summary) : null; } catch { /* not JSON yet -- treat as no heartbeat */ }
                                const tsMs = hb?.ts ? new Date(hb.ts + 'Z').getTime() : null;
                                const ageMs = tsMs !== null ? now - tsMs : null;
                                let status;
                                if (t.evidence_imported) status = 'COMPLETE';
                                else if (t.verdict === 'NO_ARTIFACTS') status = 'NO_ARTIFACTS';
                                else if (hb?.status && hb.status.includes('RUNNING')) status = 'RUNNING';
                                else status = 'PENDING';
                                if (status === 'RUNNING' && ageMs !== null && ageMs > STALL_MS) status = 'STALLED';
                                return { t_code: t.t_code, status, ageMs, detail: hb?.detail || '' };
                              }).sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);

                              return (
                                <div style={{ marginTop: 10, maxHeight: 220, overflowY: 'auto', border: '1px solid #161616' }}>
                                  {rows.map(r => (
                                    <div key={r.t_code} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', borderBottom: '1px solid #101010', fontSize: 9 }}>
                                      <span style={{ color: STATUS_COLOR[r.status], fontWeight: 'bold', minWidth: 68 }}>{r.status}</span>
                                      <span style={{ color: '#ccc', minWidth: 90 }}>{r.t_code}</span>
                                      <span style={{ color: '#777', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.detail}</span>
                                      <span style={{ color: r.status === 'STALLED' ? '#ff4444' : '#666', flexShrink: 0 }}>{fmtAge(r.ageMs)}</span>
                                    </div>
                                  ))}
                                </div>
                              );
                            })()}

                            {!pkgData[aId] && !pkgGenerating[aId] && !wasDeployed && (
                              <div style={{ color: '#777', fontSize: 9, lineHeight: 1.8 }}>
                                Generates a self-contained collection package.<br />
                                Copy the one-line deploy command and run it as admin on the target.<br />
                                The agent collects artifacts, ships results back, and self-deletes.<br />
                                Token is scoped to this asset, auto-revokes on completion, and expires in 24 hours.
                              </div>
                            )}
                          </div>
                        </td></tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>

            {/* ── BULK DEPLOYMENT PANEL ── */}
            <div style={{ marginTop: 24, border: '1px solid #1a1a1a' }}>
              <div onClick={() => setDeployOpen(p => !p)} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', cursor: 'pointer', background: '#060606', borderBottom: deployOpen ? '1px solid #1a1a1a' : 'none', userSelect: 'none' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <span style={{ color: '#aaa', fontSize: 9, letterSpacing: 2 }}>⚡ BULK_REMOTE_DEPLOYMENT</span>
                  {deployRunning && <span style={{ color: '#ffaa00', fontSize: 9, letterSpacing: 1 }}>● DEPLOYING {deploySelected.size} HOST{deploySelected.size !== 1 ? 'S' : ''}...</span>}
                  {!deployRunning && deployComplete && deploySelected.size > 0 && <span style={{ color: '#00ff41', fontSize: 9 }}>✓ DISPATCH COMPLETE</span>}
                </div>
                <span style={{ color: '#666', fontSize: 11 }}>{deployOpen ? '▲' : '▼'}</span>
              </div>

              {deployOpen && (
  <div style={{ background: '#040404', padding: '16px', fontFamily: 'monospace', fontSize: 10 }}>
    <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', marginBottom: 16, flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 180 }}>
        <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>USERNAME</span>
        <input value={deployCreds.username} onChange={e => setDeployCreds(p => ({ ...p, username: e.target.value }))} placeholder="DOMAIN\svcaccount  or  .\localadmin" disabled={deployRunning || triageRunning} style={{ ...InputStyle, fontSize: 10, padding: '6px 8px', opacity: (deployRunning || triageRunning) ? 0.5 : 1 }} />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 160 }}>
        <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>PASSWORD</span>
        <div style={{ display: 'flex', gap: 0 }}>
          <input type={deployShowPass ? 'text' : 'password'} value={deployCreds.password} onChange={e => setDeployCreds(p => ({ ...p, password: e.target.value }))} placeholder="••••••••" disabled={deployRunning || triageRunning} style={{ ...InputStyle, fontSize: 10, padding: '6px 8px', flex: 1, opacity: (deployRunning || triageRunning) ? 0.5 : 1 }} />
          <button onClick={() => setDeployShowPass(p => !p)} style={{ background: '#0a0a0a', border: '1px solid #2a2a2a', borderLeft: 'none', color: '#777', fontSize: 9, padding: '0 8px', cursor: 'pointer', fontFamily: 'monospace' }}>
            {deployShowPass ? 'HIDE' : 'SHOW'}
          </button>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 200 }}>
        <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>REMOTE_DIR (optional)</span>
        <input value={deployCreds.remoteDir} onChange={e => setDeployCreds(p => ({ ...p, remoteDir: e.target.value }))}
          placeholder="Default: %TEMP% (C:\Windows\Temp)" disabled={deployRunning || triageRunning}
          title="Staging directory on the target for the collection package. Leave blank to use the default (C:\Windows\Temp) — set this if that path is blocked by AppLocker/SRP/EDR policy in your environment."
          style={{ ...InputStyle, fontSize: 10, padding: '6px 8px', opacity: (deployRunning || triageRunning) ? 0.5 : 1 }} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 140 }}>
        <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>TRANSPORT</span>
        <select
          value={(caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE' ? triageCreds.transport : deployCreds.transport}
          onChange={e => {
            const v = e.target.value;
            if ((caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE') setTriageCreds(p => ({ ...p, transport: v }));
            else setDeployCreds(p => ({ ...p, transport: v }));
          }}
          disabled={deployRunning || triageRunning} style={{ ...InputStyle, fontSize: 10, padding: '6px 8px' }}
          title="How the collection is triggered on the target. Both push the package over SMB (port 445) first. SMB/SCHTASK then triggers via a throwaway Windows service; WinRM instead needs port 5985 enabled on the target but avoids creating that service, which is the pattern some AV/EDR flags.">
          <option value="SMB_TASK">SMB / SCHTASK</option>
          <option value="WINRM">WINRM</option>
        </select>
      </div>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center', paddingBottom: 1 }}>
        {(caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE' ? (
          <>
            <button onClick={() => handleTriage(deployCreds.username, deployCreds.password)}
              disabled={triageRunning || deploySelected.size === 0 || !deployCreds.username || !deployCreds.password || triageSelected.size === 0}
              style={{ background: triageRunning ? 'transparent' : '#ff4141', border: triageRunning ? '1px solid #333' : 'none', color: triageRunning ? '#555' : '#000', fontFamily: 'monospace', fontSize: 10, fontWeight: 'bold', padding: '7px 18px', cursor: (triageRunning || deploySelected.size === 0) ? 'not-allowed' : 'pointer', letterSpacing: 1, opacity: (deploySelected.size === 0 || !deployCreds.username || !deployCreds.password || triageSelected.size === 0) ? 0.4 : 1, transition: 'all 0.2s' }}>
              {triageRunning ? `TRIAGING (${deploySelected.size})...` : `[ TRIAGE ${deploySelected.size} HOST${deploySelected.size !== 1 ? 'S' : ''} ]`}
            </button>
            {triageRunning && (
              <button onClick={() => { triageAbortRef.current = true; setTriageRunning(false); }} style={{ background: 'transparent', border: '1px solid #ff4141', color: '#ff4141', fontFamily: 'monospace', fontSize: 9, padding: '6px 12px', cursor: 'pointer', letterSpacing: 1 }}>
                ABORT
              </button>
            )}
          </>
        ) : (
          <>
            <button onClick={handleDeploy}
              disabled={deployRunning || deploySelected.size === 0 || !deployCreds.username || !deployCreds.password}
              style={{ background: deployRunning ? 'transparent' : '#00ff41', border: deployRunning ? '1px solid #333' : 'none', color: deployRunning ? '#555' : '#000', fontFamily: 'monospace', fontSize: 10, fontWeight: 'bold', padding: '7px 18px', cursor: (deployRunning || deploySelected.size === 0) ? 'not-allowed' : 'pointer', letterSpacing: 1, opacity: (deploySelected.size === 0 || !deployCreds.username || !deployCreds.password) ? 0.4 : 1, transition: 'all 0.2s' }}>
              {deployRunning ? `DEPLOYING (${deploySelected.size})...` : `[ DEPLOY TO ${deploySelected.size} HOST${deploySelected.size !== 1 ? 'S' : ''} ]`}
            </button>
            {deployRunning && (
              <button onClick={() => { deployAbortRef.current = true; setDeployRunning(false); }} style={{ background: 'transparent', border: '1px solid #ff4141', color: '#ff4141', fontFamily: 'monospace', fontSize: 9, padding: '6px 12px', cursor: 'pointer', letterSpacing: 1 }}>
                ABORT
              </button>
            )}
          </>
        )}
      </div>
    </div>

    {/* Triage category selector — IR only */}
    {(caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE' && (
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ color: '#ff4141', fontSize: 9, letterSpacing: 2 }}>TRIAGE_CATEGORIES</span>
          <button onClick={() => setTriageSelected(triageSelected.size === triageCategories.length ? new Set() : new Set(triageCategories))}
            style={{ background: 'transparent', border: '1px solid #2a2a2a', color: '#bbb', fontSize: 9, padding: '2px 8px', cursor: 'pointer', fontFamily: 'monospace', letterSpacing: 1 }}>
            {triageSelected.size === triageCategories.length ? 'DESELECT ALL' : 'SELECT ALL'}
          </button>
        </div>
        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
          {triageCategories.map(cat => (
            <div key={cat} onClick={() => toggleTriageCategory(cat)}
              style={{ fontSize: 9, padding: '3px 10px', cursor: 'pointer', fontFamily: 'monospace', letterSpacing: 1,
                border: `1px solid ${triageSelected.has(cat) ? '#ff4141' : '#2a2a2a'}`,
                color: triageSelected.has(cat) ? '#ff4141' : '#555',
                background: triageSelected.has(cat) ? 'rgba(255,65,65,0.06)' : 'transparent' }}>
              {cat}
            </div>
          ))}
        </div>
      </div>
    )}

                  <div style={{ border: '1px solid #111' }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '32px 1fr 140px 160px 1fr', padding: '6px 10px', borderBottom: '1px solid #111', color: '#bbb', fontSize: 9, letterSpacing: 1 }}>
                      <div onClick={toggleSelectAll} style={{ cursor: 'pointer', color: deploySelected.size === (caseData.assets?.length || 0) ? '#00ff41' : '#555', fontSize: 11, lineHeight: 1 }} title="Select all">
                        {deploySelected.size === (caseData.assets?.length || 0) ? '☑' : '☐'}
                      </div>
                      <div>HOSTNAME</div><div>IP_ADDRESS</div><div>STATUS</div><div>MESSAGE</div>
                    </div>
                    {(caseData.assets || []).map((a) => {
                      const aId       = String(a.id);
                      const isChecked = deploySelected.has(a.id);
                      const status = (caseData.case_type || 'INVESTIGATION') === 'INCIDENT_RESPONSE' ? triageStatus[aId] : deployStatus[aId];
                      const phase     = status?.phase;
                      return (
                        <div key={a.id} onClick={() => !deployRunning && toggleDeploySelect(a.id)} style={{ display: 'grid', gridTemplateColumns: '32px 1fr 140px 160px 1fr', padding: '8px 10px', borderBottom: '1px solid #080808', cursor: deployRunning ? 'default' : 'pointer', background: isChecked ? 'rgba(0,255,65,0.03)' : 'transparent', transition: 'background 0.15s' }}>
                          <div style={{ color: isChecked ? '#00ff41' : '#333', fontSize: 13, lineHeight: 1, paddingTop: 1 }}>{isChecked ? '☑' : '☐'}</div>
                          <div style={{ color: isChecked ? '#00ff41' : '#aaa', fontWeight: isChecked ? 'bold' : 'normal' }}>{a.hostname}</div>
                          <div style={{ color: '#888' }}>{a.ip || '—'}</div>
                          <div>{phase
                            ? <span style={{ color: phaseColor(phase), fontSize: 9, letterSpacing: 1, fontWeight: 'bold' }}>{phase === 'ERROR' ? '✗' : phase === 'COLLECTING' ? '●' : '◎'} {phase}</span>
                            : <span style={{ color: '#999', fontSize: 9 }}>IDLE</span>}
                          </div>
                          <div style={{ color: '#777', fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{status?.message || ''}</div>
                        </div>
                      );
                    })}
                  </div>
                  <div style={{ marginTop: 8, color: '#bbb', fontSize: 9, lineHeight: 1.8 }}>
                    Requires SMB (port 445) reachable · Local admin credentials · Runs via impacket SCM (no psexec required)
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── NETWORK MAP TAB ── */}
        {activeTab === 'NETWORK_MAP' && (
          <div style={{ position: isMaximized ? 'fixed' : 'relative', top: isMaximized ? 0 : 'auto', left: isMaximized ? 0 : 'auto', width: isMaximized ? '100vw' : '100%', height: isMaximized ? '100vh' : '650px', zIndex: isMaximized ? 2000 : 1, display: 'grid', gridTemplateColumns: isMaximized ? '1fr 350px' : '1fr 300px', background: '#111', border: '1px solid #1a1a1a' }}>
            <div style={{ background: '#000', overflow: 'hidden', position: 'relative' }}>
              <NetworkMap activeNodes={activeNodes} activeLinks={activeLinks} updateNodeData={handleUpdateNode} onInitiateLink={handleInitiateLink} onDeleteNode={handleDeleteNode} onInvestigateAsset={handleInvestigateAsset} onCreateAssetFromNode={handleCreateAssetFromNode} investigatingAssetId={investigatingAssetId} isFetchingTactics={isFetchingTactics} techniqueStatuses={collab.techniqueStatuses} caseAssets={caseData.assets || []} onToggleMaximize={() => setIsMaximized(p => !p)} isMaximized={isMaximized} mapBackgroundUrl={mapBackgroundUrl} onUploadMapBackground={handleUploadMapBackground} onClearMapBackground={handleClearMapBackground} />
            </div>
            <div style={{ background: '#080808', padding: '20px', borderLeft: '1px solid #1a1a1a', overflowY: 'auto' }}>
              <button onClick={saveMapLayout} style={{ ...BtnStyle, width: '100%', marginBottom: '20px' }}>{saveStatus === 'READY' ? '[ COMMIT_MAP_TO_DATABASE ]' : `[ ${saveStatus} ]`}</button>
              <div style={{ color: '#777', fontSize: '9px', marginBottom: '15px' }}>INFRASTRUCTURE_TEMPLATES</div>
              {['SWITCH', 'ROUTER', 'FIREWALL'].map(type => <button key={type} onClick={() => addInfrastructure(type)} style={TempBtnStyle}>+ ADD_{type}</button>)}
              <div style={{ color: '#777', fontSize: '9px', margin: '20px 0 15px' }}>AVAILABLE_ASSETS</div>
              {caseData.assets?.map((asset, i) => (
                <div key={i} onDoubleClick={() => deployToMap(asset)} style={AssetCardStyle}>
                  <div style={{ color: '#00ff41' }}>{asset.hostname}</div>
                  <div style={{ color: '#666', fontSize: '10px' }}>{asset.ip}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <EvidenceWindow caseType={caseData?.case_type || 'INVESTIGATION'} assetId={investigatingAssetId} assetName={currentAsset?.hostname} tCode={null} isOpen={isEvidenceOpen} onClose={handleCloseEvidence} tacticList={evidenceTacticList} caseName={caseName} collab={collab} analysisMode={assetModes[String(investigatingAssetId)] || currentAsset?.analysis_mode || 'UNKNOWN'} assetIp={currentAsset?.ip || ''} assetType={currentAsset?.asset_type || currentAsset?.type || ''} localDir={currentAsset?.local_dir || null}
        memSummary={memSummaries[String(investigatingAssetId)] || null}
        avSummary={avSummaries[String(investigatingAssetId)] || null}
        vulnSummary={vulnSummaries[String(investigatingAssetId)] || null}
        onSummaryUpdate={(type, assetId, data) => {
          if (type === 'memory') setMemSummaries(p => ({ ...p, [String(assetId)]: data }));
          else if (type === 'av') setAvSummaries(p => ({ ...p, [String(assetId)]: data }));
          else if (type === 'vuln') setVulnSummaries(p => ({ ...p, [String(assetId)]: data }));
        }}
      />

      {isTimelineOpen && timelineAssetId && (
        <div style={ModalOverlay} onClick={() => setIsTimelineOpen(false)}>
          <div onClick={e => e.stopPropagation()} style={{
            width: '95vw', height: '92vh', background: '#050505',
            border: '1px solid #ff4141', display: 'flex', flexDirection: 'column',
            fontFamily: 'monospace', overflow: 'hidden',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '8px 16px', borderBottom: '1px solid #330000', flexShrink: 0 }}>
              <span style={{ color: '#ff4141', fontWeight: 'bold', fontSize: 12, letterSpacing: 1 }}>
                ⏱ UNIFIED_TIMELINE — {caseData?.assets?.find(a => String(a.id) === String(timelineAssetId))?.hostname || timelineAssetId}
              </span>
              <button onClick={() => setIsTimelineOpen(false)}
                style={{ background: 'none', border: 'none', color: '#ff4141', cursor: 'pointer', fontSize: 18, fontFamily: 'monospace' }}>×</button>
            </div>
            <TimelineViewer assetId={timelineAssetId} />
          </div>
        </div>
      )}

      {/* ── Asset Delete Modal ──────────────────────────────────────────── */}
      {deleteStep > 0 && deleteTarget && (
        <div style={ModalOverlay}>
          <div style={{ ...ModalContent, maxWidth: 480, border: '1px solid #ff4141' }}>

            {/* Step 1 — First confirmation */}
            {deleteStep === 1 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>⚠ DELETE ASSET</h2>
              <p style={{ color: '#ccc', fontSize: 11, marginBottom: 8 }}>
                You are about to permanently delete asset:
              </p>
              <p style={{ color: '#ff4141', fontSize: 13, fontWeight: 'bold', marginBottom: 16 }}>
                {deleteTarget.hostname} ({deleteTarget.ip})
              </p>
              <p style={{ color: '#888', fontSize: 10, marginBottom: 20 }}>
                This will delete ALL collected evidence, MFT entries, event logs, registry data, notes, and analysis results for this asset. This cannot be undone.
              </p>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDelete} style={{ ...ExecuteBtn, background: 'transparent', color: '#666', border: '1px solid #333' }}>CANCEL</button>
                <button onClick={() => setDeleteStep(2)} style={{ ...ExecuteBtn, background: '#ff4141', color: '#000' }}>YES, CONTINUE</button>
              </div>
            </>)}

            {/* Step 2 — Second confirmation */}
            {deleteStep === 2 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>⚠ ARE YOU SURE?</h2>
              <p style={{ color: '#ff8888', fontSize: 11, marginBottom: 20 }}>
                All forensic evidence for <strong>{deleteTarget.hostname}</strong> will be permanently destroyed. This action is irreversible and cannot be recovered.
              </p>
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDelete} style={{ ...ExecuteBtn, background: 'transparent', color: '#666', border: '1px solid #333' }}>CANCEL</button>
                <button onClick={() => setDeleteStep(3)} style={{ ...ExecuteBtn, background: '#ff4141', color: '#000' }}>YES, I AM SURE</button>
              </div>
            </>)}

            {/* Step 3 — Math problem */}
            {deleteStep === 3 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>VERIFY YOU ARE HUMAN</h2>
              <p style={{ color: '#ccc', fontSize: 11, marginBottom: 12 }}>
                Solve this to continue:
              </p>
              <p style={{ color: '#ffaa00', fontSize: 18, fontWeight: 'bold', marginBottom: 16, textAlign: 'center', letterSpacing: 2 }}>
                {deleteMath.a} {deleteMath.op} {deleteMath.b} = ?
              </p>
              <input
                value={deleteMathAnswer}
                onChange={e => setDeleteMathAnswer(e.target.value)}
                placeholder="ENTER ANSWER"
                style={{ ...InputStyle, width: '100%', marginBottom: 16, textAlign: 'center', fontSize: 14 }}
                autoFocus
              />
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDelete} style={{ ...ExecuteBtn, background: 'transparent', color: '#666', border: '1px solid #333' }}>CANCEL</button>
                <button
                  onClick={() => { if (parseInt(deleteMathAnswer) === mathAnswer()) setDeleteStep(4); else { setDeleteMathAnswer(''); alert('INCORRECT. Try again.'); } }}
                  style={{ ...ExecuteBtn, background: '#ff4141', color: '#000' }}>VERIFY</button>
              </div>
            </>)}

            {/* Step 4 — Final type-to-confirm */}
            {deleteStep === 4 && (<>
              <h2 style={{ color: '#ff4141', fontSize: 13, marginBottom: 16, letterSpacing: 1 }}>FINAL WARNING</h2>
              <p style={{ color: '#ff8888', fontSize: 11, marginBottom: 8 }}>
                Type the hostname to confirm permanent deletion:
              </p>
              <p style={{ color: '#ffaa00', fontSize: 12, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>
                {deleteTarget.hostname}
              </p>
              <input
                value={deleteConfirmText}
                onChange={e => setDeleteConfirmText(e.target.value)}
                placeholder={`TYPE: ${deleteTarget.hostname}`}
                style={{ ...InputStyle, width: '100%', marginBottom: 16 }}
                autoFocus
              />
              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button onClick={closeDelete} style={{ ...ExecuteBtn, background: 'transparent', color: '#666', border: '1px solid #333' }}>CANCEL</button>
                <button
                  disabled={deleteConfirmText !== deleteTarget.hostname}
                  onClick={confirmDeleteAsset}
                  style={{ ...ExecuteBtn, background: deleteConfirmText === deleteTarget.hostname ? '#ff4141' : '#330000',
                    color: deleteConfirmText === deleteTarget.hostname ? '#000' : '#550000',
                    cursor: deleteConfirmText === deleteTarget.hostname ? 'pointer' : 'not-allowed' }}>
                  PERMANENTLY DELETE
                </button>
              </div>
            </>)}

          </div>
        </div>
      )}

      {editDetailsForm && (
        <div style={ModalOverlay}><div style={ModalContent}>
          <h2 style={{ color: '#00ff41', fontSize: '14px', marginBottom: '20px' }}>[ EDIT_INVESTIGATION_DETAILS ]</h2>
          <div style={{ display: 'grid', gap: '12px' }}>
            {[
              ['missionLead', 'LEAD'],
              ['teamName',    'TEAM'],
              ['support',     'UNIT'],
              ['personnel',   'OPS'],
              ['country',     'FOCUS_COUNTRY'],
            ].map(([field, label]) => (
              <div key={field}>
                <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>{label}</div>
                <input
                  style={InputStyle}
                  value={editDetailsForm[field]}
                  onChange={e => setEditDetailsForm({ ...editDetailsForm, [field]: e.target.value })}
                />
              </div>
            ))}
            <div>
              <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>
                ASSIGNED_ANALYSTS {editDetailsForm.assignedIds.length === 0 && <span style={{ color: '#555' }}>(none — case stays open to every analyst)</span>}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 140, overflowY: 'auto', border: '1px solid #222', padding: 8 }}>
                {assignableUsers.length === 0 ? (
                  <div style={{ color: '#555', fontSize: 11 }}>No users found.</div>
                ) : assignableUsers.map(u => (
                  <label key={u.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: '#ccc', cursor: 'pointer' }}>
                    <input type="checkbox"
                      checked={editDetailsForm.assignedIds.includes(u.id)}
                      onChange={() => toggleAssignedUser(u.id)}
                    />
                    {u.username} <span style={{ color: '#666' }}>[{u.initials}]</span>
                  </label>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
              <button onClick={handleSaveDetails} style={BtnStyle}>COMMIT_CHANGES</button>
              <button onClick={() => setEditDetailsForm(null)} style={{ ...BtnStyle, background: 'transparent', color: '#777', border: '1px solid #333' }}>ABORT</button>
            </div>
          </div>
        </div></div>
      )}

      {linkForm && (
        <div style={ModalOverlay}><div style={ModalContent}>
          <h2 style={{ color: '#00ff41', fontSize: '12px', marginBottom: '20px' }}>[ ESTABLISH_LINK ]: {linkForm.source} ↔ {linkForm.target}</h2>
          <div style={{ display: 'grid', gap: '15px' }}>
            <select style={InputStyle} value={linkForm.link_type} onChange={e => setLinkForm({ ...linkForm, link_type: e.target.value })}>
              <option value="WIRED">WIRED</option><option value="WIRELESS">WIRELESS</option><option value="VPN">VPN</option>
            </select>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
              <input style={InputStyle} value={linkForm.ip_src} onChange={e => setLinkForm({ ...linkForm, ip_src: e.target.value })} placeholder="SRC IP" />
              <input style={InputStyle} value={linkForm.interface_src} onChange={e => setLinkForm({ ...linkForm, interface_src: e.target.value })} placeholder="eth0" />
            </div>
            <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
              <button onClick={handleConfirmLink} style={BtnStyle}>INITIATE_UPLINK</button>
              <button onClick={() => setLinkForm(null)} style={{ ...BtnStyle, background: 'transparent', color: '#777', border: '1px solid #333' }}>ABORT</button>
            </div>
          </div>
        </div></div>
      )}

      {editingConfig && (
        <div style={ModalOverlay}><div style={{ width: '90%', height: '85%', background: '#050505', border: '1px solid #00ff41', display: 'flex', flexDirection: 'column', padding: '20px' }}>
          <div style={{ color: '#00ff41', fontSize: '12px', marginBottom: '15px' }}>[TERMINAL_EDITOR]: {editingConfig.hostname.toUpperCase()}_CONFIG</div>
          <textarea autoFocus value={configBuffer} onChange={e => setConfigBuffer(e.target.value)} style={TextareaStyle} />
          <div style={{ display: 'flex', gap: '15px', marginTop: '20px' }}>
            <button onClick={() => { setActiveNodes(prev => prev.map(n => n.hostname === editingConfig.hostname ? { ...n, config: configBuffer } : n)); setEditingConfig(null); }} style={BtnStyle}>COMMIT_TO_MEMORY</button>
            <button onClick={() => setEditingConfig(null)} style={{ ...BtnStyle, background: 'transparent', color: '#777', border: '1px solid #333' }}>ABORT</button>
          </div>
        </div></div>
      )}

      {showAssetModal && (
        <div style={ModalOverlay}><div style={{ ...ModalContent, width: 480 }}>
          <h2 style={{ color: '#00ff41', fontSize: '14px', marginBottom: '20px' }}>NEW_ASSET_SPECIFICATION</h2>
          <div style={{ display: 'grid', gap: '10px' }}>
            <input style={InputStyle} placeholder="HOSTNAME" value={assetForm.hostname} onChange={e => setAssetForm({ ...assetForm, hostname: e.target.value })} />
            <input style={InputStyle} placeholder="IP_ADDRESS" value={assetForm.ip} onChange={e => setAssetForm({ ...assetForm, ip: e.target.value })} />
            <input style={InputStyle} placeholder="MAC_ADDRESS" value={assetForm.mac} onChange={e => setAssetForm({ ...assetForm, mac: e.target.value })} />
            <div>
              {/* ASSET_TYPE drives which techniques this asset gets, via
                  OPERATING_SYSTEM below it -- it comes first so that's the
                  order the user actually reasons in, not category-then-OS
                  as two independent, easily-desynced choices. */}
              <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>ASSET_TYPE</div>
              <select style={InputStyle} value={assetForm.type} onChange={e => {
                const type = e.target.value;
                // Technique association (see /threat-profile on the backend)
                // filters purely on OPERATING_SYSTEM, not ASSET_TYPE -- a
                // Network Device left with a stale 'Windows'/'Linux' OS
                // silently pulled in that platform's entire technique set
                // instead of the actual Network Devices one. Keeping OS in
                // lockstep with ASSET_TYPE here (both directions) makes
                // that mismatch impossible instead of relying on the user
                // to separately remember to also change OS.
                const os = type === 'Network Device' ? 'Network' : (assetForm.os === 'Network' ? 'Windows' : assetForm.os);
                setAssetForm({ ...assetForm, type, os });
              }}>
                {['Workstation', 'Server', 'Domain Controller', 'Network Device', 'Unknown'].map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>OPERATING_SYSTEM</div>
              {assetForm.type === 'Network Device' ? (
                // Locked, not just defaulted -- 'Network' is the only value
                // that makes sense once ASSET_TYPE says Network Device, so
                // this removes the redundant/inconsistent choice entirely
                // rather than leaving a dropdown the user could still
                // mismatch by hand.
                <div style={{ ...InputStyle, display: 'flex', alignItems: 'center', color: '#666', cursor: 'not-allowed' }}>
                  Network (locked — set by ASSET_TYPE)
                </div>
              ) : (
                <select style={InputStyle} value={assetForm.os} onChange={e => setAssetForm({ ...assetForm, os: e.target.value })}>
                  {['Windows', 'Linux', 'macOS', 'Other'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              )}
            </div>
            <div>
              <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>FORM_FACTOR</div>
              <select style={InputStyle} value={assetForm.formFactor} onChange={e => setAssetForm({ ...assetForm, formFactor: e.target.value })}>
                {ALL_FORM_FACTORS.map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div>
              <div style={{ color: '#888', fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>ANALYSIS_MODE</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                {[['LIVE_REMOTE', 'LIVE_REMOTE', 'Deploy VR to live system'], ['DEAD_DISK_LOCAL', 'DEAD_DISK_LOCAL', 'Image mounted on ORCA host'], ['DEAD_DISK_REMOTE', 'DEAD_DISK_REMOTE', 'Image at analyst site B'], ['UNKNOWN', 'UNKNOWN', 'Determine later']].map(([val, label, hint]) => (
                  <button key={val} onClick={() => setAssetForm({ ...assetForm, analysisMode: val })} title={hint}
                    style={{ background: assetForm.analysisMode === val ? '#00ff41' : 'transparent', color: assetForm.analysisMode === val ? '#000' : '#777', border: `1px solid ${assetForm.analysisMode === val ? '#00ff41' : '#333'}`, padding: '8px 10px', fontSize: 9, fontFamily: 'monospace', cursor: 'pointer', textAlign: 'left', letterSpacing: 1 }}>
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
              <button onClick={handleRegisterAsset} style={BtnStyle}>SAVE_ASSET</button>
              <button onClick={() => setShowAssetModal(false)} style={{ background: '#111', border: 'none', color: '#777', padding: '10px', cursor: 'pointer', fontFamily: 'monospace', fontSize: 10 }}>CANCEL</button>
            </div>
          </div>
        </div></div>
      )}
    </div>
  );
}

const StatTile = ({ label, val }) => (
  <div style={{ border: '1px solid #1a1a1a', padding: '12px' }}>
    <div style={{ fontSize: '8px', color: '#bbb', marginBottom: '5px' }}>{label}</div>
    <div style={{ fontSize: '12px', color: '#eee' }}>{val || '---'}</div>
  </div>
);

const AssetCardStyle = { padding: '10px', border: '1px solid #1a1a1a', marginBottom: '8px', cursor: 'grab', fontSize: '11px' };
const TempBtnStyle   = { background: '#111', color: '#00ff41', border: '1px solid #222', textAlign: 'left', width: '100%', padding: '10px', marginBottom: '8px', cursor: 'pointer', fontSize: '10px', fontFamily: 'monospace' };
const InputStyle     = { background: '#000', border: '1px solid #2a2a2a', padding: '10px', color: '#00ff41', fontSize: '11px', width: '100%', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' };
const TextareaStyle  = { flex: 1, background: '#000', color: '#00ff41', border: '1px solid #111', fontFamily: 'monospace', fontSize: '13px', padding: '20px', outline: 'none' };
const BtnStyle       = { background: '#00ff41', color: '#000', border: 'none', padding: '10px 20px', fontWeight: 'bold', cursor: 'pointer', fontSize: '10px', fontFamily: 'monospace' };
const ModalOverlay   = { position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', background: 'rgba(0,0,0,0.95)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 3000 };
const ModalContent   = { background: '#050505', border: '1px solid #00ff41', padding: '40px', width: '420px' };
const ExecuteBtn     = { padding: '8px 18px', background: '#00ff41', color: '#000', border: 'none', cursor: 'pointer', fontWeight: 'bold', fontSize: '11px', fontFamily: 'monospace' };
