import React, { useState, useEffect } from 'react';

const C = {
  green: '#00ff41', red: '#ff4141', amber: '#ffaa00',
  grey: '#888', greyDim: '#444',
  border: '#111', bg: '#050505', bgCard: '#080808',
};

const API = import.meta.env.VITE_API_URL || '';
const CACHE_KEY = 'orca_ioc_correlations';

function loadCache() {
  try { return JSON.parse(sessionStorage.getItem(CACHE_KEY) || 'null'); } catch { return null; }
}
function saveCache(correlations, scannedAt) {
  try { sessionStorage.setItem(CACHE_KEY, JSON.stringify({ correlations, scannedAt })); } catch {}
}

// ── Module-level scan state — survives component unmounts ─────────────────────
// The EventSource lives here so navigating away doesn't kill the in-flight scan.
let _es = null;
let _correlations = {};
let _progress = { index: 0, total: 0, hits: 0 };
let _isScanning = false;
let _lastScanTime = null;
let _notify = null; // callback to currently-mounted component

function _broadcast() {
  if (_notify) _notify();
}

function startScan() {
  if (_isScanning) return;
  _isScanning = true;
  _correlations = {};
  _progress = { index: 0, total: 0, hits: 0 };
  _broadcast();

  const es = new EventSource(`${API}/api/ioc/correlate-stream`);
  _es = es;

  es.onmessage = (e) => {
    try {
      const evt = JSON.parse(e.data);
      if (evt.phase === 'START') {
        _progress = { index: 0, total: evt.total, hits: 0 };
      } else if (evt.phase === 'IOC_RESULT') {
        if (evt.hits?.length > 0) _correlations = { ..._correlations, [evt.value]: evt.hits };
        _progress = {
          index: evt.index,
          total: evt.total,
          hits: _progress.hits + (evt.hits?.length > 0 ? 1 : 0),
        };
      } else if (evt.phase === 'COMPLETE') {
        _lastScanTime = new Date().toISOString();
        _isScanning = false;
        saveCache(_correlations, _lastScanTime);
        es.close(); _es = null;
      } else if (evt.phase === 'ERROR') {
        _isScanning = false;
        es.close(); _es = null;
      }
    } catch {}
    _broadcast();
  };

  es.onerror = () => {
    _isScanning = false;
    es.close(); _es = null;
    _broadcast();
  };
}

function cancelScan() {
  if (_es) { _es.close(); _es = null; }
  _isScanning = false;
  _broadcast();
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function IOCManager() {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isAdding, setIsAdding] = useState(false);
  const [selectedIoc, setSelectedIoc] = useState(null);
  const [error, setError] = useState('');

  // Mirror module-level scan state into React state so the component re-renders
  const [isScanning, setIsScanning] = useState(_isScanning);
  const [scanProgress, setScanProgress] = useState(_progress);
  const [correlations, setCorrelations] = useState(_correlations);
  const [lastScanTime, setLastScanTime] = useState(_lastScanTime);

  const [newIoc, setNewIoc] = useState({
    indicator_type: 'FREE_TEXT', value: '',
    description: '', severity: 'HIGH', threat_actor: '', label: '',
  });
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState(null);

  const iocTypes = {
    HASH_SHA256: { label: 'SHA256',          regex: /^[a-fA-F0-9]{64}$/ },
    HASH_MD5:    { label: 'MD5',             regex: /^[a-fA-F0-9]{32}$/ },
    IP_V4:       { label: 'IPv4',            regex: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/ },
    NETWORK_URI: { label: 'Domain/URL',      regex: /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*\/?$/ },
    FREE_TEXT:   { label: 'String/FileName', regex: /^.{1,255}$/ },
  };

  useEffect(() => {
    // Seed from sessionStorage if no scan is running
    if (!_isScanning) {
      const cached = loadCache();
      if (cached && Object.keys(_correlations).length === 0) {
        _correlations = cached.correlations || {};
        _lastScanTime = cached.scannedAt || null;
      }
    }

    // Register as the active listener — re-syncs React state on every event
    _notify = () => {
      setIsScanning(_isScanning);
      setScanProgress({ ..._progress });
      setCorrelations({ ..._correlations });
      setLastScanTime(_lastScanTime);
    };

    // Sync current module state immediately (handles remount mid-scan)
    setIsScanning(_isScanning);
    setScanProgress({ ..._progress });
    setCorrelations({ ..._correlations });
    setLastScanTime(_lastScanTime);

    fetchIocs();

    // Unregister on unmount — do NOT close the EventSource
    return () => { _notify = null; };
  }, []);

  const fetchIocs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API}/api/ioc/library`, { credentials: 'include' });
      if (res.ok) setIocs(await res.json());
    } catch {}
    finally { setLoading(false); }
  };

  const runCorrelation = () => {
    if (isScanning) { cancelScan(); } else { startScan(); }
  };

  const validateAndAdd = async () => {
    const config = iocTypes[newIoc.indicator_type];
    if (newIoc.indicator_type !== 'FREE_TEXT' && !config.regex.test(newIoc.value)) {
      setError(`INVALID_FORMAT_FOR_${newIoc.indicator_type}`); return;
    }
    try {
      const res = await fetch(`${API}/api/ioc/library`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newIoc),
      });
      if (!res.ok) { setError('SAVE_FAILED'); return; }
      setIocs([await res.json(), ...iocs]);
      setNewIoc({ indicator_type: 'FREE_TEXT', value: '', description: '', severity: 'HIGH', threat_actor: '', label: '' });
      setIsAdding(false); setError('');
    } catch { setError('NETWORK_ERROR'); }
  };

  const deleteIoc = async (ioc) => {
    try {
      const res = await fetch(`${API}/api/ioc/library/${ioc.id}`, { method: 'DELETE', credentials: 'include' });
      if (!res.ok) { setError('DELETE_FAILED'); return; }
      setIocs(iocs.filter(i => i.id !== ioc.id));
      setSelectedIoc(null);
      setError('');
    } catch { setError('NETWORK_ERROR'); }
  };

  const startEdit = (ioc) => {
    setEditForm({
      indicator_type: ioc.indicator_type || 'FREE_TEXT',
      value: ioc.value || '',
      description: ioc.description || '',
      severity: ioc.severity || 'HIGH',
      threat_actor: ioc.threat_actor || '',
      label: ioc.label || '',
    });
    setIsEditing(true);
    setError('');
  };

  const cancelEdit = () => { setIsEditing(false); setEditForm(null); setError(''); };

  const saveEdit = async () => {
    const config = iocTypes[editForm.indicator_type];
    if (editForm.indicator_type !== 'FREE_TEXT' && !config.regex.test(editForm.value)) {
      setError(`INVALID_FORMAT_FOR_${editForm.indicator_type}`); return;
    }
    try {
      const res = await fetch(`${API}/api/ioc/library/${selectedIoc.id}`, {
        method: 'PUT', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editForm),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.detail || 'SAVE_FAILED'); return;
      }
      const updated = await res.json();
      setIocs(iocs.map(i => i.id === updated.id ? updated : i));
      setSelectedIoc(updated);
      setIsEditing(false); setEditForm(null); setError('');
    } catch { setError('NETWORK_ERROR'); }
  };

  const pct = scanProgress.total > 0 ? Math.floor((scanProgress.index / scanProgress.total) * 100) : 0;
  const scanLabel = isScanning
    ? scanProgress.total > 0
      ? `◼ CANCEL  [${scanProgress.index}/${scanProgress.total}]  ${scanProgress.hits} hits`
      : '◼ CANCEL  STARTING...'
    : 'RUN_DB_CORRELATION';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedIoc ? '1fr 360px' : '1fr', gap: 20, color: '#eee', fontFamily: 'monospace' }}>

      <main>
        <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 24, alignItems: 'flex-start' }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 900, color: C.green, margin: 0, letterSpacing: 2 }}>IOC_RELIQUARY</h1>
            <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <button
                onClick={runCorrelation}
                disabled={!isScanning && iocs.length === 0}
                style={{
                  background: isScanning ? '#1a0a0a' : '#0a0a0a',
                  color: isScanning ? C.red : C.green,
                  border: `1px solid ${isScanning ? C.red : '#333'}`,
                  padding: '5px 12px', fontSize: 10, cursor: iocs.length === 0 && !isScanning ? 'not-allowed' : 'pointer',
                  fontFamily: 'monospace', letterSpacing: 1, whiteSpace: 'nowrap',
                }}
              >{scanLabel}</button>

              {(isScanning || pct > 0) && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 120, height: 3, background: '#111', borderRadius: 2 }}>
                    <div style={{
                      height: '100%',
                      width: isScanning && scanProgress.total === 0 ? '100%' : `${pct}%`,
                      background: C.green, transition: 'width 0.2s',
                      animation: isScanning && scanProgress.total === 0 ? 'iocpulse 1s ease infinite alternate' : 'none',
                    }} />
                  </div>
                  {isScanning && scanProgress.total > 0 && (
                    <span style={{ color: C.greyDim, fontSize: 10 }}>{pct}%</span>
                  )}
                </div>
              )}

              {lastScanTime && !isScanning && (
                <span style={{ color: '#999', fontSize: 9 }}>
                  last scan {new Date(lastScanTime).toLocaleString()}
                </span>
              )}
            </div>
          </div>

          <button
            onClick={() => setIsAdding(true)}
            style={{ background: C.green, color: '#000', border: 'none', padding: '8px 18px', fontWeight: 'bold', cursor: 'pointer', fontSize: 11, letterSpacing: 1, flexShrink: 0 }}
          >[+] ADD_IOC</button>
        </header>

        <div style={{ border: `1px solid ${C.border}`, background: C.bgCard }}>
          {loading ? (
            <div style={{ padding: 40, textAlign: 'center', color: C.greyDim, fontSize: 12 }}>LOADING_VAULT...</div>
          ) : iocs.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: C.greyDim, fontSize: 12 }}>No IOCs in library. Add one to begin.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ color: C.greyDim, borderBottom: `1px solid ${C.border}`, textAlign: 'left' }}>
                  <th style={{ padding: '12px 14px' }}>TYPE</th>
                  <th style={{ padding: '12px 14px' }}>VALUE</th>
                  <th style={{ padding: '12px 14px', width: 130 }}>LABEL</th>
                  <th style={{ padding: '12px 14px', width: 90 }}>SEVERITY</th>
                  <th style={{ padding: '12px 14px', width: 140 }}>DB_HITS</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map(ioc => {
                  const matches = correlations[ioc.value] || [];
                  const hasMatch = matches.length > 0;
                  return (
                    <tr
                      key={ioc.id}
                      onClick={() => { setSelectedIoc(ioc); setIsEditing(false); setEditForm(null); setError(''); }}
                      style={{
                        borderBottom: `1px solid ${C.border}`, cursor: 'pointer',
                        background: selectedIoc?.id === ioc.id ? '#0e0e0e' : 'transparent',
                        borderLeft: `3px solid ${hasMatch ? C.red : 'transparent'}`,
                      }}
                      onMouseEnter={e => { if (selectedIoc?.id !== ioc.id) e.currentTarget.style.background = '#090909'; }}
                      onMouseLeave={e => { if (selectedIoc?.id !== ioc.id) e.currentTarget.style.background = 'transparent'; }}
                    >
                      <td style={{ padding: '12px 14px', color: C.green }}>{(ioc.indicator_type || '').replace('HASH_', '')}</td>
                      <td style={{ padding: '12px 14px', color: '#eee', wordBreak: 'break-all', maxWidth: 300 }}>{ioc.value}</td>
                      <td style={{ padding: '12px 14px', color: C.amber, fontSize: 11 }}>{ioc.label || <span style={{ color: '#555' }}>—</span>}</td>
                      <td style={{ padding: '12px 14px', color: ioc.severity === 'CRITICAL' ? C.red : ioc.severity === 'HIGH' ? C.amber : C.grey }}>{ioc.severity}</td>
                      <td style={{ padding: '12px 14px' }}>
                        {hasMatch
                          ? <span style={{ color: C.red, fontSize: 11 }}>▲ {matches.length} hit{matches.length !== 1 ? 's' : ''}</span>
                          : <span style={{ color: '#888', fontSize: 11 }}>—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </main>

      {/* Detail sidebar */}
      {selectedIoc && (
        <aside style={{ background: C.bg, border: `1px solid ${C.border}`, padding: 18, alignSelf: 'start', position: 'sticky', top: 0 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16, alignItems: 'center' }}>
            <span style={{ color: C.green, fontSize: 11, fontWeight: 'bold', letterSpacing: 1 }}>[ INDICATOR ]</span>
            <button onClick={() => { setSelectedIoc(null); setIsEditing(false); setEditForm(null); setError(''); }} style={{ background: 'none', border: 'none', color: C.greyDim, cursor: 'pointer', fontSize: 14 }}>×</button>
          </div>

          {isEditing ? (
            <>
              <label style={Ls}>TYPE</label>
              <select value={editForm.indicator_type} onChange={e => setEditForm({ ...editForm, indicator_type: e.target.value })} style={Is}>
                {Object.entries(iocTypes).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
              </select>

              <label style={Ls}>VALUE</label>
              <input value={editForm.value} onChange={e => { setEditForm({ ...editForm, value: e.target.value }); setError(''); }}
                style={{ ...Is, borderColor: error ? C.red : '#222' }} />

              <label style={Ls}>LABEL (optional)</label>
              <input value={editForm.label} onChange={e => setEditForm({ ...editForm, label: e.target.value })}
                placeholder="e.g. Confirmed Malicious, False Positive" style={Is} />

              <label style={Ls}>SEVERITY</label>
              <select value={editForm.severity} onChange={e => setEditForm({ ...editForm, severity: e.target.value })} style={Is}>
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s}>{s}</option>)}
              </select>

              <label style={Ls}>THREAT ACTOR (optional)</label>
              <input value={editForm.threat_actor} onChange={e => setEditForm({ ...editForm, threat_actor: e.target.value })}
                placeholder="e.g. APT29, Lazarus Group" style={Is} />

              <label style={Ls}>NOTE</label>
              <textarea value={editForm.description} onChange={e => setEditForm({ ...editForm, description: e.target.value })}
                style={{ ...Is, minHeight: 60, resize: 'vertical' }} />

              {error && <div style={{ color: C.red, fontSize: 10, marginBottom: 8 }}>{error}</div>}
              <div style={{ display: 'flex', gap: 8 }}>
                <button onClick={saveEdit} style={{ flex: 1, background: C.green, border: 'none', padding: 8, fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace', fontSize: 10, letterSpacing: 1 }}>SAVE</button>
                <button onClick={cancelEdit} style={{ flex: 1, background: 'none', color: C.greyDim, border: `1px solid ${C.greyDim}`, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10 }}>CANCEL</button>
              </div>
            </>
          ) : (
            <>
              <Field label="TYPE" value={(selectedIoc.indicator_type || '').replace('HASH_', '')} color={C.green} />
              {selectedIoc.label && <Field label="LABEL" value={selectedIoc.label} color={C.amber} />}
              <Field label="SEVERITY" value={selectedIoc.severity} color={selectedIoc.severity === 'CRITICAL' ? C.red : C.amber} />
              {selectedIoc.threat_actor && <Field label="THREAT ACTOR" value={selectedIoc.threat_actor} color={C.amber} />}
              <div style={{ marginBottom: 14 }}>
                <div style={{ fontSize: 9, color: C.greyDim, marginBottom: 4, letterSpacing: 1 }}>VALUE</div>
                <div style={{ color: '#eee', fontSize: 11, wordBreak: 'break-all', background: '#000', padding: '8px 10px', border: `1px solid ${C.border}` }}>{selectedIoc.value}</div>
              </div>
              {selectedIoc.description && <Field label="NOTE" value={selectedIoc.description} />}

              {correlations[selectedIoc.value]?.length > 0 && (
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 9, color: C.red, marginBottom: 6, letterSpacing: 1 }}>EVIDENCE HITS — {correlations[selectedIoc.value].length}</div>
                  <div style={{ maxHeight: 220, overflowY: 'auto', border: `1px solid ${C.border}` }}>
                    {correlations[selectedIoc.value].map((m, idx) => (
                      <div key={idx} style={{ padding: '7px 10px', borderBottom: `1px solid ${C.border}`, fontSize: 10 }}>
                        <div style={{ color: C.green, marginBottom: 2 }}>{m.case_name} / {m.hostname}</div>
                        <div style={{ color: C.greyDim }}>{m.t_code} — {m.detail}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {!correlations[selectedIoc.value] && lastScanTime && (
                <div style={{ color: C.greyDim, fontSize: 10, marginBottom: 14 }}>No evidence hits in last scan.</div>
              )}
              {!lastScanTime && !isScanning && (
                <div style={{ color: '#999', fontSize: 10, marginBottom: 14 }}>Run correlation scan to check evidence.</div>
              )}
              {isScanning && !correlations[selectedIoc.value] && (
                <div style={{ color: C.amber, fontSize: 10, marginBottom: 14 }}>Scan in progress…</div>
              )}

              {error && <div style={{ color: C.red, fontSize: 10, marginBottom: 8 }}>{error}</div>}
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  onClick={() => startEdit(selectedIoc)}
                  style={{ flex: 1, background: 'transparent', border: `1px solid ${C.green}`, color: C.green, padding: 8, fontSize: 10, cursor: 'pointer', letterSpacing: 1 }}
                >EDIT_INDICATOR</button>
                <button
                  onClick={() => deleteIoc(selectedIoc)}
                  style={{ flex: 1, background: 'transparent', border: `1px solid ${C.red}`, color: C.red, padding: 8, fontSize: 10, cursor: 'pointer', letterSpacing: 1 }}
                >DELETE_INDICATOR</button>
              </div>
            </>
          )}
        </aside>
      )}

      {/* Add IOC modal */}
      {isAdding && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.92)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: C.bg, border: `1px solid ${C.green}`, padding: 28, width: 460 }}>
            <h2 style={{ color: C.green, margin: '0 0 18px', fontSize: 16, letterSpacing: 2 }}>IOC_ENTRY_TERMINAL</h2>

            <label style={Ls}>TYPE</label>
            <select value={newIoc.indicator_type} onChange={e => setNewIoc({ ...newIoc, indicator_type: e.target.value })} style={Is}>
              {Object.entries(iocTypes).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>

            <label style={Ls}>VALUE</label>
            <input value={newIoc.value} onChange={e => { setNewIoc({ ...newIoc, value: e.target.value }); setError(''); }}
              placeholder="Hash, IP, domain, filename…" style={{ ...Is, borderColor: error ? C.red : '#222' }} />

            <label style={Ls}>LABEL (optional)</label>
            <input value={newIoc.label} onChange={e => setNewIoc({ ...newIoc, label: e.target.value })}
              placeholder="e.g. Confirmed Malicious, False Positive" style={Is} />

            <label style={Ls}>SEVERITY</label>
            <select value={newIoc.severity} onChange={e => setNewIoc({ ...newIoc, severity: e.target.value })} style={Is}>
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s}>{s}</option>)}
            </select>

            <label style={Ls}>THREAT ACTOR (optional)</label>
            <input value={newIoc.threat_actor} onChange={e => setNewIoc({ ...newIoc, threat_actor: e.target.value })}
              placeholder="e.g. APT29, Lazarus Group" style={Is} />

            <label style={Ls}>NOTE</label>
            <textarea value={newIoc.description} onChange={e => setNewIoc({ ...newIoc, description: e.target.value })}
              placeholder="Justification or context" style={{ ...Is, minHeight: 70, resize: 'vertical' }} />

            {error && <div style={{ color: C.red, fontSize: 10, marginBottom: 12 }}>{error}</div>}
            <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
              <button onClick={validateAndAdd} style={{ flex: 1, background: C.green, border: 'none', padding: 11, fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, letterSpacing: 1 }}>COMMIT</button>
              <button onClick={() => { setIsAdding(false); setError(''); }} style={{ flex: 1, background: 'none', color: C.greyDim, border: `1px solid ${C.greyDim}`, cursor: 'pointer', fontFamily: 'monospace', fontSize: 11 }}>ABORT</button>
            </div>
          </div>
        </div>
      )}

      <style>{`@keyframes iocpulse { from { opacity: 1 } to { opacity: 0.3 } }`}</style>
    </div>
  );
}

function Field({ label, value, color }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 9, color: '#999', marginBottom: 3, letterSpacing: 1 }}>{label}</div>
      <div style={{ fontSize: 11, color: color || '#aaa', fontFamily: 'monospace' }}>{value}</div>
    </div>
  );
}

const Is = { width: '100%', background: '#000', color: '#eee', border: '1px solid #222', padding: 10, marginBottom: 12, fontFamily: 'monospace', fontSize: 11, boxSizing: 'border-box', outline: 'none' };
const Ls = { display: 'block', fontSize: 9, color: '#aaa', letterSpacing: 1, marginBottom: 4 };
