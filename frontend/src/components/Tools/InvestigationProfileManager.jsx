import React, { useState, useEffect, useMemo } from 'react';

const API_BASE = `${import.meta.env.VITE_API_URL}/api/profiles`;

const getAuthHeaders = () => ({
  'Authorization': `Bearer ${localStorage.getItem('orca_token')}`,
  'Content-Type': 'application/json',
});

export default function InvestigationProfileManager() {
  const [profiles, setProfiles] = useState([]);
  const [availableTcodes, setAvailableTcodes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Panel state
  const [panelOpen, setPanelOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState(null); // null = new, object = editing

  // Form state
  const [formName, setFormName] = useState('');
  const [formTcodes, setFormTcodes] = useState([]); // selected t_codes
  const [tcodeSearch, setTcodeSearch] = useState('');
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

  // Delete confirm state
  const [deleteTarget, setDeleteTarget] = useState(null);

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}`, { headers: getAuthHeaders() }).then(r => r.json()),
      fetch(`${API_BASE}/tcodes/available`, { headers: getAuthHeaders() }).then(r => r.json()),
    ]).then(([profs, tcodes]) => {
      setProfiles(Array.isArray(profs) ? profs : []);
      setAvailableTcodes(Array.isArray(tcodes) ? tcodes : []);
    }).catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const filteredTcodes = useMemo(() => {
    if (!tcodeSearch.trim()) return availableTcodes;
    const q = tcodeSearch.toLowerCase();
    return availableTcodes.filter(t =>
      t.t_code.toLowerCase().includes(q) || (t.name || '').toLowerCase().includes(q)
    );
  }, [availableTcodes, tcodeSearch]);

  const openNew = () => {
    setEditingProfile(null);
    setFormName('');
    setFormTcodes([]);
    setTcodeSearch('');
    setFormError('');
    setPanelOpen(true);
  };

  const openEdit = (profile) => {
    setEditingProfile(profile);
    setFormName(profile.name);
    setFormTcodes([...(profile.tcodes || [])]);
    setTcodeSearch('');
    setFormError('');
    setPanelOpen(true);
  };

  const closePanel = () => {
    setPanelOpen(false);
    setEditingProfile(null);
    setFormName('');
    setFormTcodes([]);
    setFormError('');
  };

  const toggleTcode = (tcode) => {
    setFormTcodes(prev =>
      prev.includes(tcode) ? prev.filter(t => t !== tcode) : [...prev, tcode]
    );
  };

  const removeTcode = (tcode) => {
    setFormTcodes(prev => prev.filter(t => t !== tcode));
  };

  const handleSave = async () => {
    if (!formName.trim()) { setFormError('PROFILE_NAME_REQUIRED'); return; }
    if (formTcodes.length === 0) { setFormError('SELECT_AT_LEAST_ONE_TCODE'); return; }
    setSaving(true);
    setFormError('');
    try {
      const body = { name: formName.trim(), tcodes: formTcodes };
      const url = editingProfile ? `${API_BASE}/${editingProfile.id}` : `${API_BASE}`;
      const method = editingProfile ? 'PUT' : 'POST';
      const res = await fetch(url, {
        method,
        headers: getAuthHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setFormError(data.detail || `HTTP_${res.status}`);
        return;
      }
      const saved = await res.json();
      setProfiles(prev =>
        editingProfile
          ? prev.map(p => p.id === saved.id ? saved : p)
          : [...prev, saved]
      );
      closePanel();
    } catch (e) {
      setFormError(e.message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      const res = await fetch(`${API_BASE}/${deleteTarget.id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      if (!res.ok) return;
      setProfiles(prev => prev.filter(p => p.id !== deleteTarget.id));
    } catch {}
    setDeleteTarget(null);
  };

  if (loading) return <div style={loadingStyle}>LOADING_PROFILES...</div>;
  if (error) return <div style={errorStyle}>ERROR: {error}</div>;

  return (
    <div style={{ padding: '40px', background: '#000', minHeight: '100vh', color: '#fff', fontFamily: 'monospace' }}>

      <div style={headerFlex}>
        <div>
          <h2 style={titleGlow}>INVESTIGATION_PROFILES</h2>
          <div style={{ color: '#222', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
            NAMED T-CODE SETS // APPEAR IN INVESTIGATION CREATE DROPDOWN
          </div>
        </div>
        <button onClick={openNew} style={btnDeploy}>NEW_PROFILE +</button>
      </div>

      {/* Profile list */}
      {profiles.length === 0 ? (
        <div style={{ color: '#111', textAlign: 'center', marginTop: '100px', fontSize: '20px', letterSpacing: '10px' }}>
          NO_PROFILES_DEFINED
        </div>
      ) : (
        <div style={gridStyle}>
          {profiles.map(p => (
            <div key={p.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div>
                  <div style={{ color: '#00b8ff', fontSize: '10px', letterSpacing: '2px', marginBottom: '6px' }}>
                    CUSTOM_PROFILE
                  </div>
                  <div style={{ color: '#fff', fontSize: '18px', fontWeight: 900 }}>{p.name}</div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button onClick={() => openEdit(p)} style={btnEdit}>EDIT</button>
                  <button onClick={() => setDeleteTarget(p)} style={btnDelete}>DEL</button>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                {(p.tcodes || []).slice(0, 6).map(t => (
                  <span key={t} style={tchipStyle}>{t}</span>
                ))}
                {(p.tcodes || []).length > 6 && (
                  <span style={{ fontSize: '8px', color: '#444' }}>+{p.tcodes.length - 6} MORE</span>
                )}
                {(p.tcodes || []).length === 0 && (
                  <span style={{ fontSize: '9px', color: '#333' }}>NO_TCODES</span>
                )}
              </div>
              <div style={{ color: '#1a1a1a', fontSize: '9px', marginTop: '16px' }}>
                {(p.tcodes || []).length} T-CODE(S) // UPDATED {new Date(p.updated_at).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create/Edit panel overlay */}
      {panelOpen && (
        <div style={overlayStyle}>
          <div style={panelStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '40px' }}>
              <div style={panelTitle}>
                {editingProfile ? 'EDIT_PROFILE' : 'NEW_PROFILE'}
              </div>
              <div style={{ color: '#111', fontSize: '10px' }}>ORCA_PROFILE_PROTOCOL</div>
            </div>

            <label style={labelStyle}>PROFILE_NAME</label>
            <input
              value={formName}
              onChange={e => setFormName(e.target.value)}
              placeholder="e.g. APT29_CORE_HUNT"
              style={inputStyle}
              autoFocus
            />

            <label style={labelStyle}>
              SELECTED_TCODES ({formTcodes.length})
            </label>
            <div style={chipAreaStyle}>
              {formTcodes.length === 0 && (
                <span style={{ color: '#222', fontSize: '10px' }}>NO_TCODES_SELECTED</span>
              )}
              {formTcodes.map(t => {
                const meta = availableTcodes.find(x => x.t_code === t);
                return (
                  <div key={t} style={selectedChipStyle}>
                    <span style={{ color: '#00ff41' }}>{t}</span>
                    {meta?.name && <span style={{ color: '#555', fontSize: '9px', marginLeft: '6px' }}>{meta.name.slice(0, 25)}</span>}
                    <span onClick={() => removeTcode(t)} style={removeXStyle}>×</span>
                  </div>
                );
              })}
            </div>

            <label style={{ ...labelStyle, marginTop: '24px' }}>TCODE_LIBRARY (CLICK_TO_TOGGLE)</label>
            <input
              value={tcodeSearch}
              onChange={e => setTcodeSearch(e.target.value)}
              placeholder="SEARCH_BY_TCODE_OR_NAME..."
              style={{ ...inputStyle, marginBottom: '8px' }}
            />
            <div style={tcodeListStyle}>
              {filteredTcodes.length === 0 && (
                <div style={{ color: '#333', fontSize: '10px', padding: '20px', textAlign: 'center' }}>
                  NO_MATCHING_TCODES
                </div>
              )}
              {filteredTcodes.map(t => {
                const selected = formTcodes.includes(t.t_code);
                return (
                  <div
                    key={t.t_code}
                    onClick={() => toggleTcode(t.t_code)}
                    style={{
                      ...tcodeRowStyle,
                      color: selected ? '#00ff41' : '#444',
                      borderColor: selected ? '#00ff41' : '#111',
                      background: selected ? 'rgba(0,255,65,0.02)' : 'transparent',
                    }}
                  >
                    <span style={{ fontWeight: 'bold', minWidth: '90px', display: 'inline-block' }}>{t.t_code}</span>
                    <span style={{ color: selected ? '#559955' : '#2a2a2a', fontSize: '10px' }}>{t.name || ''}</span>
                    {selected && <span style={{ marginLeft: 'auto', fontSize: '10px', color: '#00ff41' }}>✓</span>}
                  </div>
                );
              })}
            </div>

            {formError && (
              <div style={{ color: '#ff4444', fontSize: '11px', marginTop: '16px', letterSpacing: '1px' }}>
                ERROR: {formError}
              </div>
            )}

            <div style={{ display: 'flex', gap: '16px', marginTop: '32px' }}>
              <button onClick={closePanel} style={btnAbort}>ABORT</button>
              <button onClick={handleSave} disabled={saving} style={{ ...btnDeploy, opacity: saving ? 0.6 : 1 }}>
                {saving ? 'SAVING...' : (editingProfile ? 'SAVE_CHANGES' : 'COMMIT_PROFILE')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation */}
      {deleteTarget && (
        <div style={overlayStyle}>
          <div style={{ ...panelStyle, maxWidth: '480px', padding: '48px', border: '1px solid #ff4141' }}>
            <h2 style={{ color: '#ff4141', fontSize: '13px', marginBottom: '16px', letterSpacing: '1px' }}>
              ⚠ DELETE PROFILE
            </h2>
            <p style={{ color: '#ccc', fontSize: '11px', marginBottom: '8px' }}>
              Permanently delete this profile?
            </p>
            <p style={{ color: '#ff4141', fontSize: '14px', fontWeight: 'bold', marginBottom: '24px' }}>
              {deleteTarget.name}
            </p>
            <p style={{ color: '#555', fontSize: '10px', marginBottom: '24px' }}>
              This only removes the profile definition. No investigation data is affected.
            </p>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button onClick={() => setDeleteTarget(null)} style={btnAbort}>CANCEL</button>
              <button onClick={handleDelete} style={{ ...btnDeploy, background: '#ff4141', color: '#000' }}>
                DELETE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Styles
const headerFlex      = { display: 'flex', justifyContent: 'space-between', marginBottom: '60px', alignItems: 'center' };
const titleGlow       = { color: '#00b8ff', letterSpacing: '8px', fontSize: '24px', margin: 0 };
const gridStyle       = { display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '24px' };
const cardStyle       = { background: '#050505', border: '1px solid #0a1a2a', padding: '32px' };
const tchipStyle      = { fontSize: '8px', color: '#00b8ff', border: '1px solid #0a1a2a', padding: '2px 6px' };
const btnDeploy       = { background: '#00ff41', color: '#000', border: 'none', padding: '14px 32px', fontWeight: 900, cursor: 'pointer', letterSpacing: '1px', fontFamily: 'monospace', fontSize: '11px' };
const btnAbort        = { background: 'none', color: '#333', border: '1px solid #222', padding: '14px 32px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '11px' };
const btnEdit         = { background: 'none', color: '#444', border: '1px solid #1a1a1a', padding: '6px 14px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px' };
const btnDelete       = { background: 'none', color: '#ff4444', border: '1px solid #2a0a0a', padding: '6px 14px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px' };
const overlayStyle    = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.98)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 };
const panelStyle      = { background: '#000', border: '1px solid #111', padding: '60px', width: '900px', maxHeight: '90vh', overflowY: 'auto' };
const panelTitle      = { color: '#00b8ff', fontSize: '18px', fontWeight: 900, letterSpacing: '2px' };
const labelStyle      = { color: '#222', fontSize: '10px', fontWeight: 'bold', display: 'block', marginBottom: '10px', letterSpacing: '1px' };
const inputStyle      = { width: '100%', background: '#050505', border: '1px solid #1a1a1a', color: '#eee', padding: '14px', marginBottom: '24px', fontSize: '13px', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' };
const chipAreaStyle   = { background: '#050505', border: '1px solid #111', minHeight: '80px', padding: '12px', display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '0px' };
const selectedChipStyle = { background: '#0a150a', border: '1px solid #1a3a1a', padding: '5px 10px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' };
const removeXStyle    = { marginLeft: '8px', color: '#ff4444', cursor: 'pointer', fontWeight: 'bold', fontSize: '13px' };
const tcodeListStyle  = { height: '280px', overflowY: 'auto', background: '#050505', border: '1px solid #111', padding: '8px' };
const tcodeRowStyle   = { padding: '10px 12px', border: '1px solid #111', fontSize: '11px', cursor: 'pointer', marginBottom: '4px', display: 'flex', alignItems: 'center', transition: 'all 0.15s' };
const loadingStyle    = { color: '#00ff41', fontFamily: 'monospace', padding: '60px', fontSize: '13px' };
const errorStyle      = { color: '#ff4444', fontFamily: 'monospace', padding: '60px', fontSize: '13px' };
