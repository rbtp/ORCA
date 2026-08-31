import React, { useState, useEffect, useRef, useCallback } from 'react';

const C = {
  green:   '#00ff41', greenDim: '#00cc33',
  red:     '#ff4444', amber: '#ffaa00', purple: '#9b59ff',
  white:   '#f0f0f0', grey: '#aaaaaa', greyDim: '#777777',
  border:  '#2a2a2a', borderBright: '#3a3a3a',
  bg:      '#000000', bgCard: '#0d0d0d', bgHover: '#141414', bgHeader: '#111111',
  orange:  '#fb8c00',
};

const getAuth = () => ({ 'Content-Type': 'application/json' });

const API = import.meta.env.VITE_API_URL || '';

const sev = (s) => s === 'high' ? C.red : s === 'medium' ? C.orange : s === 'low' ? C.amber : C.greyDim;

const IOC_ICON = { IP: '🔴', DOMAIN: '🌐', URL: '🔗', REGISTRY: '🗝️', FILEPATH: '📁', EMAIL: '✉️' };

const API_CATEGORIES = {
  'File I/O':   ['createfile','readfile','writefile','deletefile','movefile','copyfile','openfile','findfile','setfileattributes','getfileattributes'],
  'Network':    ['connect','wsaconnect','internetopen','internetconnect','httpsendrequest','httpopenpersonalrequests','send','recv','wsasend','wsarecv','dnsquery','gethostbyname','getaddrinfo'],
  'Registry':   ['regopenkey','regopenkeya','regopenkeyex','regsetvalue','regqueryvalue','regcreatekey','regdeletekey','regclosekey'],
  'Process':    ['createprocess','openprocess','terminateprocess','createthread','openthread','createremotethread','setthreadcontext','getthreadcontext','writeprocessmemory','readprocessmemory'],
  'Memory':     ['virtualalloc','virtualprotect','virtualfree','heapalloc','heapfree','mapviewoffile','unmapviewoffile'],
};

function categorizeFn(fn) {
  const lower = (fn || '').toLowerCase();
  for (const [cat, fns] of Object.entries(API_CATEGORIES)) {
    if (fns.some(f => lower.startsWith(f))) return cat;
  }
  return 'Other';
}

// Simple paginated string list — avoids virtualizing large arrays
function StringList({ items, filter, typeFilter }) {
  const [page, setPage] = useState(0);
  const PAGE = 200;

  const filtered = items.filter(item => {
    const matchText = !filter || (item.string_value || '').toLowerCase().includes(filter.toLowerCase());
    const matchType = !typeFilter || item.string_type === typeFilter;
    return matchText && matchType;
  });

  const total = filtered.length;
  const start = page * PAGE;
  const slice = filtered.slice(start, start + PAGE);
  const pages = Math.ceil(total / PAGE);

  useEffect(() => setPage(0), [filter, typeFilter]);

  return (
    <div>
      <div style={{ padding: '4px 8px', color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>
        {total} strings {total !== items.length ? `(filtered from ${items.length})` : ''}
      </div>
      <div style={{ fontFamily: 'monospace', fontSize: 11 }}>
        {slice.map((row, i) => (
          <div key={i} style={{
            padding: '3px 8px', borderBottom: `1px solid #0a0a0a`,
            background: i % 2 === 0 ? '#080808' : 'transparent',
            display: 'flex', gap: 8, alignItems: 'center',
          }}>
            <span style={{ color: row.string_type === 'decoded' ? C.green : row.string_type === 'stack' ? C.amber : C.greyDim, fontSize: 9, minWidth: 52, flexShrink: 0 }}>{row.string_type}</span>
            {row.is_ioc && <span style={{ color: C.red, fontSize: 9 }}>IOC</span>}
            <span style={{ color: row.is_ioc ? C.amber : C.grey, wordBreak: 'break-all' }}>{row.string_value}</span>
          </div>
        ))}
      </div>
      {pages > 1 && (
        <div style={{ display: 'flex', gap: 8, padding: 8, alignItems: 'center' }}>
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            style={{ background: 'none', border: `1px solid ${C.border}`, color: C.grey, cursor: 'pointer', padding: '3px 10px', fontFamily: 'monospace', fontSize: 11 }}>
            ← Prev
          </button>
          <span style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>
            {page + 1} / {pages} ({total} total)
          </span>
          <button onClick={() => setPage(p => Math.min(pages - 1, p + 1))} disabled={page >= pages - 1}
            style={{ background: 'none', border: `1px solid ${C.border}`, color: C.grey, cursor: 'pointer', padding: '3px 10px', fontFamily: 'monospace', fontSize: 11 }}>
            Next →
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Progress bar for tool status ─────────────────────────────────────────────
function ToolProgress({ label, status, detail }) {
  const color = status === 'complete' ? C.green : status === 'running' ? C.amber : status === 'error' ? C.red : status === 'skipped' ? C.greyDim : C.border;
  const pct = status === 'complete' || status === 'error' || status === 'skipped' ? 100 : status === 'running' ? null : 0;
  return (
    <div style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '6px 0' }}>
      <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace', width: 80, flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, background: '#111', height: 6, borderRadius: 3, overflow: 'hidden', position: 'relative' }}>
        {pct !== null ? (
          <div style={{ height: '100%', background: color, width: `${pct}%`, transition: 'width 0.4s ease' }} />
        ) : (
          <div style={{
            height: '100%', background: `linear-gradient(90deg, transparent, ${color}, transparent)`,
            width: '40%', position: 'absolute',
            animation: 'slide 1.2s linear infinite',
          }} />
        )}
      </div>
      <span style={{ color, fontSize: 10, fontFamily: 'monospace', width: 68, flexShrink: 0 }}>
        {(status || 'pending').toUpperCase()}
      </span>
      {detail && <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>{detail}</span>}
    </div>
  );
}

// ─── Artifact file picker modal ────────────────────────────────────────────────
function ArtifactPickerModal({ assetId, onSelect, onClose }) {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(`${API}/api/behavioral/asset/${assetId}/artifact-files`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(data => { setFiles(data); setLoading(false); })
      .catch(() => setLoading(false));
  }, [assetId]);

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#080808', border: `1px solid ${C.border}`, width: 680, maxHeight: '70vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ color: C.green, fontSize: 11, fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1 }}>SELECT COLLECTED ARTIFACT</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontFamily: 'monospace', fontWeight: 'bold' }}>[ X ]</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>Loading artifact files...</div>}
          {!loading && files.length === 0 && (
            <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>
              No artifact files found for this asset. Run Velociraptor collection first.
            </div>
          )}
          {files.map((f, i) => (
            <div key={i} onClick={() => onSelect(f.source_file)}
              style={{ padding: '8px 14px', borderBottom: `1px solid #0a0a0a`, cursor: 'pointer', fontFamily: 'monospace', fontSize: 11, display: 'flex', gap: 12, background: 'transparent' }}
              onMouseEnter={e => e.currentTarget.style.background = C.bgHover}
              onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
              <span style={{ color: C.greyDim, minWidth: 90, flexShrink: 0 }}>{f.t_code}</span>
              <span style={{ color: C.white, wordBreak: 'break-all' }}>{f.source_file}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── File browser modal (MFT-backed, hash-enriched) ────────────────────────────
// Informational only -- MFT gives metadata (path/size/timestamps/hash), never
// the file's actual bytes, so nothing here feeds into RUN ANALYSIS directly.
// Pulling a specific file's real content for full CAPA/FLOSS/Speakeasy analysis
// is the separate, rarer follow-up case, not this browser's job.
function fmtBytes(n) {
  if (n == null) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function getDefaultTransport() {
  const v = localStorage.getItem('orca_default_transport');
  return (v === 'WINRM' || v === 'SMB_TASK') ? v : 'SMB_TASK';
}

// pending -> staged -> triggered -> received | failed | timeout
const _PULL_TERMINAL = ['received', 'failed', 'timeout'];
const _PULL_POLL_MS = 2500;
const _PULL_MAX_POLLS = 72; // ~3 minutes

function FileBrowserModal({ assetId, onClose, onFileReady }) {
  const [pathStack, setPathStack] = useState(['']); // '' = drive root
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const currentPath = pathStack[pathStack.length - 1];

  // Pull-file sub-flow state
  const [pullOpen, setPullOpen] = useState(false);
  const [pullCreds, setPullCreds] = useState({ username: '', password: '', transport: getDefaultTransport() });
  const [pullShowPass, setPullShowPass] = useState(false);
  const [pullPhase, setPullPhase] = useState('idle'); // idle | starting | polling | done | error
  const [pullJob, setPullJob] = useState(null);
  const [pullError, setPullError] = useState('');
  const pullPollRef = useRef(null);
  const pullPollCountRef = useRef(0);

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    setPullOpen(false);
    setPullPhase('idle');
    setPullError('');
    if (pullPollRef.current) { clearInterval(pullPollRef.current); pullPollRef.current = null; }
    const params = new URLSearchParams({ view: 'tree', path_prefix: currentPath, page_size: '1000', include_dirs: 'true' });
    fetch(`${API}/api/mitre/evidence/${assetId}/mft/query?${params}`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : { results: [] })
      .then(data => { setEntries(data.results || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, [assetId, currentPath]);

  // Stop polling on unmount
  useEffect(() => () => { if (pullPollRef.current) clearInterval(pullPollRef.current); }, []);

  const enterFolder = (name) => setPathStack(prev => [...prev, (currentPath ? currentPath + '\\' : '') + name]);
  const goToCrumb = (idx) => setPathStack(prev => prev.slice(0, idx + 1));

  const selectFile = (e) => {
    setSelected(e);
    setPullOpen(false);
    setPullPhase('idle');
    setPullError('');
    setPullJob(null);
    if (pullPollRef.current) { clearInterval(pullPollRef.current); pullPollRef.current = null; }
  };

  const pollPullJob = (jobId) => {
    pullPollCountRef.current = 0;
    pullPollRef.current = setInterval(async () => {
      pullPollCountRef.current += 1;
      try {
        const r = await fetch(`${API}/api/behavioral/fetch-file/${jobId}`, { headers: getAuth(), credentials: 'include' });
        if (!r.ok) throw new Error('poll failed');
        const data = await r.json();
        setPullJob(data);
        if (_PULL_TERMINAL.includes(data.status)) {
          clearInterval(pullPollRef.current);
          pullPollRef.current = null;
          setPullPhase(data.status === 'received' ? 'done' : 'error');
          if (data.status !== 'received') setPullError(data.error || 'Fetch failed');
        } else if (pullPollCountRef.current >= _PULL_MAX_POLLS) {
          clearInterval(pullPollRef.current);
          pullPollRef.current = null;
          setPullPhase('error');
          setPullError('Timed out waiting on target — the agent may still be running. Check back later or retry.');
        }
      } catch {
        // transient — keep polling until max count
        if (pullPollCountRef.current >= _PULL_MAX_POLLS) {
          clearInterval(pullPollRef.current);
          pullPollRef.current = null;
          setPullPhase('error');
          setPullError('Lost contact with server while polling.');
        }
      }
    }, _PULL_POLL_MS);
  };

  const submitPull = async () => {
    if (!selected || !pullCreds.username || !pullCreds.password) return;
    setPullPhase('starting');
    setPullError('');
    try {
      const r = await fetch(`${API}/api/behavioral/asset/${assetId}/fetch-file`, {
        method: 'POST',
        headers: getAuth(),
        credentials: 'include',
        body: JSON.stringify({
          file_path: selected.p,
          username: pullCreds.username,
          password: pullCreds.password,
          transport: pullCreds.transport,
        }),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.detail || `Fetch trigger failed (${r.status})`);
      setPullJob({ job_id: data.job_id, status: 'triggered' });
      setPullPhase('polling');
      pollPullJob(data.job_id);
    } catch (e) {
      setPullPhase('error');
      setPullError(e.message || 'Fetch trigger failed');
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#080808', border: `1px solid ${C.border}`, width: 820, maxHeight: '75vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ color: C.green, fontSize: 11, fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1 }}>FILE BROWSER — MFT</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontFamily: 'monospace', fontWeight: 'bold' }}>[ X ]</button>
        </div>

        <div style={{ padding: '6px 14px', borderBottom: `1px solid ${C.border}`, fontFamily: 'monospace', fontSize: 10, color: C.greyDim, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {pathStack.map((p, i) => (
            <span key={i} style={{ display: 'flex', alignItems: 'center' }}>
              <span onClick={() => goToCrumb(i)} style={{ cursor: 'pointer', color: i === pathStack.length - 1 ? C.white : C.grey }}>
                {i === 0 ? 'C:' : p.split('\\').pop()}
              </span>
              {i < pathStack.length - 1 && <span style={{ margin: '0 4px' }}>/</span>}
            </span>
          ))}
        </div>

        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>Loading...</div>}
          {!loading && entries.length === 0 && (
            <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>
              Empty, or no MFT evidence collected for this asset yet.
            </div>
          )}
          {entries.map((e, i) => (
            <div key={i}
              onClick={() => e.d ? enterFolder(e.n) : selectFile(e)}
              style={{
                padding: '6px 14px', borderBottom: '1px solid #0a0a0a', cursor: 'pointer',
                fontFamily: 'monospace', fontSize: 11, display: 'flex', gap: 10, alignItems: 'center',
                background: selected === e ? C.bgHover : 'transparent',
              }}
              onMouseEnter={ev => { if (selected !== e) ev.currentTarget.style.background = C.bgHover; }}
              onMouseLeave={ev => { if (selected !== e) ev.currentTarget.style.background = 'transparent'; }}>
              <span style={{ width: 16, flexShrink: 0 }}>{e.d ? '\u{1F4C1}' : '\u{1F4C4}'}</span>
              <span style={{ color: e.u === 0 ? C.red : C.white, flex: 1, wordBreak: 'break-all' }}>
                {e.n}{e.u === 0 ? ' (deleted)' : ''}
              </span>
              {!e.d && <span style={{ color: C.greyDim, minWidth: 70, textAlign: 'right', flexShrink: 0 }}>{fmtBytes(e.sz)}</span>}
              {e.h && (
                <span style={{
                  color: e.hs === 'path' ? C.amber : C.greyDim, fontSize: 9, flexShrink: 0,
                  border: `1px solid ${e.hs === 'path' ? C.amber : C.border}`, padding: '1px 5px',
                }} title={e.hs === 'path' ? 'Hash matched by exact path' : 'Hash matched by filename only (Amcache does not record full paths) -- unconfirmed for this specific file'}>
                  {e.hs === 'path' ? 'HASHED' : 'HASH~'}
                </span>
              )}
              {e.vt?.status === 'found' && e.vt.malicious > 0 && (
                <span style={{ color: C.red, fontSize: 9, flexShrink: 0, border: `1px solid ${C.red}`, padding: '1px 5px', fontWeight: 'bold' }}
                  title="VirusTotal: flagged by one or more engines">
                  ⚠ VT {e.vt.malicious}/{e.vt.total}
                </span>
              )}
            </div>
          ))}
        </div>

        {selected && (
          <div style={{ borderTop: `1px solid ${C.border}`, padding: '10px 14px', fontFamily: 'monospace', fontSize: 10, color: C.grey, background: '#050505' }}>
            <div style={{ color: C.white, marginBottom: 4, wordBreak: 'break-all' }}>{selected.p}</div>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: selected.h ? 4 : 0 }}>
              <span>Size: {fmtBytes(selected.sz)}</span>
              <span>Modified: {(selected.m || '').slice(0, 19).replace('T', ' ') || 'unknown'}</span>
              {selected.ads === 1 && <span style={{ color: C.amber }}>Has ADS</span>}
              {selected.si_lt_fn === 1 && <span style={{ color: C.red }}>Possible timestomp</span>}
            </div>
            {selected.h ? (
              <div>
                <div>
                  <span style={{ color: C.greyDim }}>{selected.hs === 'path' ? 'SHA256 (exact path match)' : 'SHA1 (Amcache, filename match only)'}:</span>{' '}
                  <span style={{ color: C.amber, wordBreak: 'break-all' }}>{selected.h}</span>
                </div>
                <div style={{ marginTop: 4 }}>
                  <span style={{ color: C.greyDim }}>VirusTotal:</span>{' '}
                  {!selected.vt && <span style={{ color: C.greyDim }}>not looked up yet</span>}
                  {selected.vt?.status === 'not_found' && <span style={{ color: C.greyDim }}>unknown to VT (never seen)</span>}
                  {selected.vt?.status === 'found' && selected.vt.malicious > 0 && (
                    <span style={{ color: C.red, fontWeight: 'bold' }}>{selected.vt.malicious}/{selected.vt.total} engines flagged malicious</span>
                  )}
                  {selected.vt?.status === 'found' && selected.vt.malicious === 0 && (
                    <span style={{ color: C.green }}>clean — 0/{selected.vt.total} engines flagged</span>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ color: C.greyDim }}>No hash on file — not seen in Amcache and not in a common malware-drop location.</div>
            )}

            {/* ── Pull-file sub-flow ─────────────────────────────────────────── */}
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
              {pullPhase === 'idle' && !pullOpen && (
                <button onClick={() => setPullOpen(true)}
                  style={{ background: 'none', border: `1px solid ${C.green}`, color: C.green, fontFamily: 'monospace', fontSize: 10, fontWeight: 'bold', padding: '6px 14px', cursor: 'pointer', letterSpacing: 1 }}>
                  PULL FILE
                </button>
              )}

              {pullOpen && pullPhase === 'idle' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ color: C.greyDim, fontSize: 9 }}>
                    Pushes a one-off agent to fetch this exact file's bytes from the target, then self-deletes.
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <input value={pullCreds.username} onChange={e => setPullCreds(p => ({ ...p, username: e.target.value }))}
                      placeholder="DOMAIN\svcaccount  or  .\localadmin"
                      style={{ flex: 1, background: '#0a0a0a', border: `1px solid ${C.border}`, color: C.white, fontFamily: 'monospace', fontSize: 10, padding: '6px 8px' }} />
                    <select value={pullCreds.transport} onChange={e => setPullCreds(p => ({ ...p, transport: e.target.value }))}
                      style={{ background: '#0a0a0a', border: `1px solid ${C.border}`, color: C.white, fontFamily: 'monospace', fontSize: 10, padding: '6px 4px' }}>
                      <option value="SMB_TASK">SMB / SCHTASK</option>
                      <option value="WINRM">WinRM</option>
                    </select>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <input type={pullShowPass ? 'text' : 'password'} value={pullCreds.password} onChange={e => setPullCreds(p => ({ ...p, password: e.target.value }))}
                      placeholder="••••••••"
                      style={{ flex: 1, background: '#0a0a0a', border: `1px solid ${C.border}`, color: C.white, fontFamily: 'monospace', fontSize: 10, padding: '6px 8px' }} />
                    <button onClick={() => setPullShowPass(s => !s)}
                      style={{ background: 'none', border: `1px solid ${C.border}`, color: C.greyDim, fontFamily: 'monospace', fontSize: 9, padding: '0 8px', cursor: 'pointer' }}>
                      {pullShowPass ? 'HIDE' : 'SHOW'}
                    </button>
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button onClick={submitPull} disabled={!pullCreds.username || !pullCreds.password}
                      style={{
                        background: C.green, border: 'none', color: '#000', fontFamily: 'monospace', fontSize: 10, fontWeight: 'bold',
                        padding: '6px 14px', cursor: (!pullCreds.username || !pullCreds.password) ? 'not-allowed' : 'pointer',
                        opacity: (!pullCreds.username || !pullCreds.password) ? 0.4 : 1, letterSpacing: 1,
                      }}>
                      FETCH
                    </button>
                    <button onClick={() => setPullOpen(false)}
                      style={{ background: 'none', border: `1px solid ${C.border}`, color: C.greyDim, fontFamily: 'monospace', fontSize: 10, padding: '6px 14px', cursor: 'pointer' }}>
                      CANCEL
                    </button>
                  </div>
                </div>
              )}

              {(pullPhase === 'starting' || pullPhase === 'polling') && (
                <div style={{ color: C.amber, fontSize: 10 }}>
                  {pullPhase === 'starting' ? 'Building package and triggering agent...' : `Waiting on target agent... (${pullJob?.status || 'triggered'})`}
                </div>
              )}

              {pullPhase === 'done' && pullJob && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ color: C.green }}>
                    ✓ Pulled {fmtBytes(pullJob.file_size)} — SHA256: <span style={{ color: C.amber, wordBreak: 'break-all' }}>{pullJob.sha256}</span>
                  </div>
                  <button onClick={() => onFileReady && onFileReady(pullJob.local_path, selected.n)}
                    style={{ background: C.green, border: 'none', color: '#000', fontFamily: 'monospace', fontSize: 10, fontWeight: 'bold', padding: '6px 14px', cursor: 'pointer', letterSpacing: 1, alignSelf: 'flex-start' }}>
                    → SEND TO ANALYSIS
                  </button>
                </div>
              )}

              {pullPhase === 'error' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ color: C.red, wordBreak: 'break-word' }}>✗ {pullError}</div>
                  <button onClick={() => { setPullPhase('idle'); setPullOpen(true); }}
                    style={{ background: 'none', border: `1px solid ${C.red}`, color: C.red, fontFamily: 'monospace', fontSize: 10, padding: '6px 14px', cursor: 'pointer', alignSelf: 'flex-start' }}>
                    RETRY
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── History picker dropdown ───────────────────────────────────────────────────
function HistoryDropdown({ assetId, onSelect, onClose }) {
  const [jobs, setJobs] = useState([]);

  useEffect(() => {
    fetch(`${API}/api/behavioral/asset/${assetId}/jobs`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(setJobs)
      .catch(() => {});
  }, [assetId]);

  return (
    <div style={{ position: 'absolute', top: '100%', right: 0, background: '#080808', border: `1px solid ${C.border}`, zIndex: 100, minWidth: 400, maxHeight: 320, overflowY: 'auto' }}>
      {jobs.length === 0 && <div style={{ padding: 12, color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>No previous analyses</div>}
      {jobs.map(job => (
        <div key={job.job_id} onClick={() => { onSelect(job.job_id); onClose(); }}
          style={{ padding: '8px 12px', borderBottom: `1px solid #0a0a0a`, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10 }}
          onMouseEnter={e => e.currentTarget.style.background = C.bgHover}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
          <div style={{ color: C.white, marginBottom: 2 }}>{job.submitted_file}</div>
          <div style={{ color: C.greyDim, display: 'flex', gap: 12 }}>
            <span>{(job.submitted_at || '').slice(0, 16).replace('T', ' ')}</span>
            <span style={{ color: job.overall_status === 'complete' ? C.green : job.overall_status === 'error' ? C.red : C.amber }}>
              {(job.overall_status || '').toUpperCase()}
            </span>
            {job.capa_technique_count > 0 && <span style={{ color: C.red }}>{job.capa_technique_count} techniques</span>}
            {job.floss_ioc_count > 0 && <span style={{ color: C.amber }}>{job.floss_ioc_count} IOCs</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

// =============================================================================
// MAIN COMPONENT
// =============================================================================
const BehavioralAnalysisTab = ({ assetId, onSummaryUpdate }) => {
  // Submission state
  const [selectedFile, setSelectedFile]       = useState(null);   // File object
  const [selectedPath, setSelectedPath]       = useState('');     // filepath string
  const [displayName, setDisplayName]         = useState('');
  const [analystInitials, setAnalystInitials] = useState('');
  const [showArtifactPicker, setShowArtifactPicker] = useState(false);
  const [showFileBrowser, setShowFileBrowser]       = useState(false);
  const [showHistory, setShowHistory]         = useState(false);
  const [isDragging, setIsDragging]           = useState(false);

  // Run state
  const [jobId, setJobId]                     = useState(null);
  const [isRunning, setIsRunning]             = useState(false);
  const [runStatus, setRunStatus]             = useState({ capa: 'pending', floss: 'pending', speakeasy: 'pending' });
  const [runCounts, setRunCounts]             = useState({ capa: 0, floss: 0, speakeasy: 0, iocs: 0 });
  const [liveLog, setLiveLog]                 = useState([]);
  const [fileInfo, setFileInfo]               = useState(null);
  const [submitError, setSubmitError]         = useState('');

  // Results state
  const [results, setResults]                 = useState(null);

  // UI state
  const [activeSection, setActiveSection]     = useState('capa');
  const [flossSubTab, setFlossSubTab]         = useState('iocs');
  const [seSubTab, setSeSubTab]               = useState('api');
  const [iocTypeFilter, setIocTypeFilter]     = useState('All');
  const [apiCatFilter, setApiCatFilter]       = useState('All');
  const [stringSearch, setStringSearch]       = useState('');
  const [stringTypeFilter, setStringTypeFilter] = useState('');

  const fileInputRef = useRef(null);
  const logRef = useRef(null);
  const evtSourceRef = useRef(null);
  const jobIdRef = useRef(null);  // always-current job ID for use inside stale closures

  // Auto-scroll live log
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [liveLog]);

  const addLog = useCallback((msg, type = 'log') => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
    setLiveLog(prev => [...prev.slice(-200), { ts, msg, type }]);
  }, []);

  // --- Handle SSE stream ---
  const connectStream = useCallback((jid) => {
    if (evtSourceRef.current) evtSourceRef.current.close();

    const url = `${API}/api/behavioral/stream/${jid}`;
    const es = new EventSource(url);
    evtSourceRef.current = es;

    es.onmessage = (e) => {
      try {
        const evt = JSON.parse(e.data);
        handleStreamEvent(evt);
      } catch {}
    };
    es.onerror = () => {
      es.close();
      setIsRunning(false);
    };
  }, []);

  const handleStreamEvent = useCallback((evt) => {
    const phase = evt.phase;
    if (phase === 'FILE_INFO') {
      setFileInfo(evt);
    } else if (phase === 'CAPA_START') {
      setRunStatus(s => ({ ...s, capa: 'running' }));
      addLog('CAPA: capability analysis started');
    } else if (phase === 'CAPA_TECHNIQUE') {
      setRunCounts(c => ({ ...c, capa: c.capa + 1 }));
      addLog(`CAPA → ${evt.technique_id} (${evt.tactic}): ${evt.technique_name}`);
    } else if (phase === 'CAPA_COMPLETE') {
      setRunStatus(s => ({ ...s, capa: 'complete' }));
      addLog(`CAPA: complete — ${evt.technique_count} techniques in ${evt.elapsed_seconds}s`, 'success');
    } else if (phase === 'FLOSS_START') {
      setRunStatus(s => ({ ...s, floss: 'running' }));
      addLog('FLOSS: string extraction started');
    } else if (phase === 'FLOSS_PROGRESS') {
      setRunCounts(c => ({ ...c, floss: evt.strings_found, iocs: evt.iocs_found }));
    } else if (phase === 'FLOSS_COMPLETE') {
      setRunStatus(s => ({ ...s, floss: 'complete' }));
      setRunCounts(c => ({ ...c, floss: evt.total_strings, iocs: evt.total_iocs }));
      addLog(`FLOSS: complete — ${evt.total_strings} strings, ${evt.total_iocs} IOCs in ${evt.elapsed_seconds}s`, 'success');
    } else if (phase === 'SPEAKEASY_START') {
      setRunStatus(s => ({ ...s, speakeasy: 'running' }));
      addLog('Speakeasy: emulation started (timeout 120s)');
    } else if (phase === 'SPEAKEASY_API_CALL') {
      setRunCounts(c => ({ ...c, speakeasy: c.speakeasy + 1 }));
      const args = Array.isArray(evt.args) ? evt.args.slice(0, 2).join(', ') : '';
      addLog(`Speakeasy → ${evt.func_name}(${args})`);
    } else if (phase === 'SPEAKEASY_NETWORK') {
      addLog(`Speakeasy → NETWORK: ${evt.protocol?.toUpperCase()} ${evt.host}`, 'warn');
    } else if (phase === 'SPEAKEASY_COMPLETE') {
      setRunStatus(s => ({ ...s, speakeasy: 'complete' }));
      addLog(`Speakeasy: complete — ${evt.api_call_count} API calls, ${evt.network_events} network events in ${evt.elapsed_seconds}s`, 'success');
    } else if (phase === 'SPEAKEASY_SKIPPED') {
      setRunStatus(s => ({ ...s, speakeasy: 'skipped' }));
      addLog('Speakeasy: skipped — ELF not supported by Windows emulator', 'warn');
    } else if (phase === 'ERROR') {
      setRunStatus(s => ({ ...s, [evt.tool]: 'error' }));
      addLog(`ERROR (${evt.tool}): ${evt.message}`, 'error');
    } else if (phase === 'PIPELINE_COMPLETE' || phase === 'PIPELINE_ERROR') {
      setIsRunning(false);
      if (evtSourceRef.current) evtSourceRef.current.close();
      // Load full results from DB — use ref to avoid stale closure on jobId
      const jid = jobIdRef.current;
      if (jid) {
        setTimeout(() => {
          fetch(`${API}/api/behavioral/job/${jid}`, { headers: getAuth(), credentials: 'include' })
            .then(r => r.ok ? r.json() : null)
            .then(data => {
              if (!data) return;
              setResults(data);
              const tc = data.capa?.technique_count || 0;
              const ic = data.floss?.ioc_count || 0;
              const ac = data.speakeasy?.api_calls?.length || 0;
              if (onSummaryUpdate) onSummaryUpdate({ techniqueCount: tc, iocCount: ic, apiCallCount: ac });
            })
            .catch(() => {});
        }, 500);
      }
      if (phase === 'PIPELINE_COMPLETE' && evt.overall_status === 'running') {
        addLog('Analysis was interrupted (server restarted while job was running).', 'error');
      } else {
        addLog(phase === 'PIPELINE_COMPLETE' ? 'Pipeline complete.' : `Pipeline error: ${evt.message}`, phase === 'PIPELINE_COMPLETE' ? 'success' : 'error');
      }
    }
  }, [addLog, onSummaryUpdate]);

  // --- Reconnect to an in-progress job (navigate-away recovery) ---
  const reconnectToRunningJob = useCallback((jid) => {
    fetch(`${API}/api/behavioral/job/${jid}`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        const j = data.job || {};
        setRunStatus({
          capa:      j.capa_status      || 'pending',
          floss:     j.floss_status     || 'pending',
          speakeasy: j.speakeasy_status || 'pending',
        });
        setJobId(jid);
        jobIdRef.current = jid;
        setIsRunning(true);
        setResults(null);
        setLiveLog([]);
        addLog(`Reconnected to running job — ${jid.slice(0, 8)}…`, 'warn');
        connectStream(jid);
      })
      .catch(() => {});
  }, [addLog, connectStream]);

  // --- Load latest job on mount; reconnect if one is still running ---
  useEffect(() => {
    if (!assetId) return;
    fetch(`${API}/api/behavioral/asset/${assetId}/jobs`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : [])
      .then(jobs => {
        const running = (jobs || []).find(j => j.overall_status === 'running');
        if (running) {
          reconnectToRunningJob(running.job_id);
          return;
        }
        fetch(`${API}/api/behavioral/asset/${assetId}/latest`, { headers: getAuth(), credentials: 'include' })
          .then(r => r.ok ? r.json() : null)
          .then(data => {
            if (!data) return;
            setResults(data);
            setJobId(data.job?.job_id || null);
            jobIdRef.current = data.job?.job_id || null;
            const tc = data.capa?.technique_count || 0;
            const ic = data.floss?.ioc_count || 0;
            const ac = data.speakeasy?.api_calls?.length || 0;
            if (onSummaryUpdate) onSummaryUpdate({ techniqueCount: tc, iocCount: ic, apiCallCount: ac });
          })
          .catch(() => {});
      })
      .catch(() => {});

    return () => {
      if (evtSourceRef.current) { evtSourceRef.current.close(); evtSourceRef.current = null; }
    };
  }, [assetId, reconnectToRunningJob]);

  // --- Submit handler ---
  const handleSubmit = async () => {
    if (!selectedFile && !selectedPath) {
      setSubmitError('Select a file to analyze.');
      return;
    }
    setSubmitError('');
    setIsRunning(true);
    setResults(null);
    setLiveLog([]);
    setRunStatus({ capa: 'pending', floss: 'pending', speakeasy: 'pending' });
    setRunCounts({ capa: 0, floss: 0, speakeasy: 0, iocs: 0 });
    setFileInfo(null);

    const fd = new FormData();
    fd.append('asset_id', assetId);
    fd.append('analyst_initials', analystInitials);
    if (selectedFile) {
      fd.append('file', selectedFile);
    } else {
      fd.append('file_path', selectedPath);
    }

    try {
      const res = await fetch(`${API}/api/behavioral/submit`, {
        method: 'POST',
        credentials: 'include',
        body: fd,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail?.message || err.detail || 'Submit failed');
      }
      const { job_id } = await res.json();
      setJobId(job_id);
      jobIdRef.current = job_id;
      addLog(`Job submitted — ID: ${job_id}`);
      connectStream(job_id);
    } catch (e) {
      setSubmitError(String(e.message || e));
      setIsRunning(false);
    }
  };

  // --- Load a specific historical job (or reconnect if it's still running) ---
  const loadJob = useCallback((jid) => {
    fetch(`${API}/api/behavioral/job/${jid}`, { headers: getAuth(), credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        if (data.job?.overall_status === 'running') {
          reconnectToRunningJob(jid);
          return;
        }
        setResults(data);
        setJobId(jid);
        jobIdRef.current = jid;
        const tc = data.capa?.technique_count || 0;
        const ic = data.floss?.ioc_count || 0;
        const ac = data.speakeasy?.api_calls?.length || 0;
        if (onSummaryUpdate) onSummaryUpdate({ techniqueCount: tc, iocCount: ic, apiCallCount: ac });
      })
      .catch(() => {});
  }, [reconnectToRunningJob, onSummaryUpdate]);

  // --- File drop handling ---
  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) { setSelectedFile(f); setSelectedPath(''); setDisplayName(f.name); }
  };

  const handleFileInput = (e) => {
    const f = e.target.files[0];
    if (f) { setSelectedFile(f); setSelectedPath(''); setDisplayName(f.name); }
  };

  // --- Derived data ---
  const capaByTactic = {};
  if (results?.capa?.techniques) {
    for (const t of results.capa.techniques) {
      (capaByTactic[t.tactic_name] = capaByTactic[t.tactic_name] || []).push(t);
    }
  }

  const iocs = results?.floss?.iocs || [];
  const allStrings = results?.floss?.all_strings || [];
  const iocTypes = ['All', ...new Set(iocs.map(i => i.ioc_type).filter(Boolean))];
  const filteredIocs = iocTypeFilter === 'All' ? iocs : iocs.filter(i => i.ioc_type === iocTypeFilter);
  // Build lookup for IOC library matches — keyed by lowercase string_value
  const iocMatchMap = new Map((results?.floss?.ioc_matches || []).map(m => [(m.string_value || '').toLowerCase(), m]));

  const apiCalls = results?.speakeasy?.api_calls || [];
  const netEvents = results?.speakeasy?.network_events || [];
  const filteredApis = apiCatFilter === 'All' ? apiCalls : apiCalls.filter(a => categorizeFn(a.func_name) === apiCatFilter);
  const fileRegOps = apiCalls.filter(a => ['File I/O', 'Registry'].includes(categorizeFn(a.func_name)));

  const seStatus = results?.job?.speakeasy_status;
  const seError = results?.job?.speakeasy_error;

  // ─── Styles ────────────────────────────────────────────────────────────────

  const sectionBtn = (id) => ({
    padding: '6px 14px', border: 'none', cursor: 'pointer', fontSize: 10,
    fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1,
    borderBottom: `2px solid ${activeSection === id ? C.green : 'transparent'}`,
    color: activeSection === id ? C.green : C.greyDim,
    background: 'transparent',
  });

  const subBtn = (active) => ({
    padding: '4px 12px', border: `1px solid ${active ? C.green : C.border}`,
    cursor: 'pointer', fontSize: 10, fontFamily: 'monospace',
    color: active ? C.green : C.greyDim, background: active ? 'rgba(0,255,65,0.06)' : 'transparent',
  });

  const filterBtn = (active) => ({
    padding: '3px 10px', border: `1px solid ${active ? C.amber : C.border}`,
    cursor: 'pointer', fontSize: 10, fontFamily: 'monospace',
    color: active ? C.amber : C.greyDim, background: 'transparent',
  });

  const Th = ({ children, w }) => (
    <th style={{ padding: '6px 10px', textAlign: 'left', fontSize: 9, color: C.greyDim, fontWeight: 'bold', letterSpacing: 1, width: w, background: C.bgHeader, borderBottom: `1px solid ${C.border}`, fontFamily: 'monospace' }}>
      {children}
    </th>
  );

  const Td = ({ children, col }) => (
    <td style={{ padding: '5px 10px', fontSize: 11, color: col || C.grey, fontFamily: 'monospace', borderBottom: `1px solid #0a0a0a`, wordBreak: 'break-all' }}>
      {children}
    </td>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: C.bg }}>
      <style>{`@keyframes slide { from { left: -40% } to { left: 100% } }`}</style>

      {/* ── Submission Panel ─────────────────────────────────────────────────── */}
      <div style={{ padding: '10px 16px', background: '#050505', borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
          <span style={{ color: C.green, fontSize: 11, fontWeight: 'bold', fontFamily: 'monospace', letterSpacing: 2 }}>BEHAVIORAL ANALYSIS</span>
          <div style={{ position: 'relative' }}>
            <button onClick={() => setShowHistory(h => !h)}
              style={{ background: 'none', border: `1px solid ${C.border}`, color: C.greyDim, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10, padding: '3px 10px' }}>
              ▼ History
            </button>
            {showHistory && (
              <HistoryDropdown assetId={assetId} onSelect={loadJob} onClose={() => setShowHistory(false)} />
            )}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start', flexWrap: 'wrap' }}>
          {/* Drop zone */}
          <div
            onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            style={{
              flex: 1, minWidth: 220, minHeight: 56, border: `1px dashed ${isDragging ? C.green : C.border}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              cursor: 'pointer', background: isDragging ? 'rgba(0,255,65,0.04)' : 'transparent',
              color: displayName ? C.amber : C.greyDim, fontSize: 11, fontFamily: 'monospace',
              padding: 8, textAlign: 'center',
            }}>
            {displayName || 'Drop file here or click to upload'}
          </div>
          <input ref={fileInputRef} type="file" style={{ display: 'none' }} onChange={handleFileInput} />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <button onClick={() => setShowArtifactPicker(true)}
              style={{ background: 'none', border: `1px solid ${C.border}`, color: C.grey, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10, padding: '5px 12px', whiteSpace: 'nowrap' }}>
              Browse Collected
            </button>
            <button onClick={() => setShowFileBrowser(true)}
              title="Browse the full MFT-derived file listing for this asset, with hashes where known (Amcache / common malware locations). Informational only -- does not submit a file for analysis."
              style={{ background: 'none', border: `1px solid ${C.border}`, color: C.grey, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10, padding: '5px 12px', whiteSpace: 'nowrap' }}>
              Browse Files (MFT)
            </button>
            <button onClick={() => fileInputRef.current?.click()}
              style={{ background: 'none', border: `1px solid ${C.border}`, color: C.grey, cursor: 'pointer', fontFamily: 'monospace', fontSize: 10, padding: '5px 12px', whiteSpace: 'nowrap' }}>
              Upload File
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>Analyst:</span>
              <input value={analystInitials} onChange={e => setAnalystInitials(e.target.value)}
                placeholder="Initials"
                style={{ width: 60, background: '#0a0a0a', border: `1px solid ${C.border}`, color: C.white, fontFamily: 'monospace', fontSize: 11, padding: '4px 6px', outline: 'none' }} />
            </div>
            <button onClick={handleSubmit} disabled={isRunning}
              style={{
                background: isRunning ? '#1a3a1a' : C.green, color: '#000', border: 'none',
                cursor: isRunning ? 'not-allowed' : 'pointer', fontFamily: 'monospace',
                fontSize: 11, fontWeight: 'bold', padding: '6px 18px', letterSpacing: 1,
              }}>
              {isRunning ? '◌ RUNNING...' : '▶ RUN ANALYSIS'}
            </button>
          </div>
        </div>

        <div style={{ marginTop: 4, color: C.greyDim, fontSize: 9, fontFamily: 'monospace' }}>
          Supported: PE32, PE64, ELF (Speakeasy requires PE)
        </div>
        {submitError && (
          <div style={{ marginTop: 4, color: C.red, fontSize: 10, fontFamily: 'monospace' }}>{submitError}</div>
        )}
      </div>

      {/* ── Progress Panel (visible during/after run) ──────────────────────── */}
      {(isRunning || (results && jobId)) && (
        <div style={{ padding: '10px 16px', background: '#040904', borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          {fileInfo && (
            <div style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace', marginBottom: 8 }}>
              <span style={{ color: C.white }}>{displayName || results?.job?.submitted_file}</span>
              {fileInfo.sha256 && <span style={{ marginLeft: 8 }}>SHA256: {fileInfo.sha256.slice(0, 20)}…</span>}
            </div>
          )}
          <ToolProgress label="CAPA" status={runStatus.capa}
            detail={runStatus.capa !== 'pending' ? `${runCounts.capa} techniques` : ''} />
          <ToolProgress label="FLOSS" status={runStatus.floss}
            detail={runStatus.floss !== 'pending' ? `${runCounts.floss} strings, ${runCounts.iocs} IOCs` : ''} />
          <ToolProgress label="Speakeasy" status={runStatus.speakeasy}
            detail={runStatus.speakeasy !== 'pending' ? `${runCounts.speakeasy} API calls` : ''} />

          {liveLog.length > 0 && (
            <div ref={logRef} style={{ marginTop: 8, maxHeight: 80, overflowY: 'auto', background: '#020202', border: `1px solid ${C.border}`, padding: 4 }}>
              {liveLog.map((l, i) => (
                <div key={i} style={{ fontFamily: 'monospace', fontSize: 10, padding: '1px 4px',
                  color: l.type === 'error' ? C.red : l.type === 'success' ? C.green : l.type === 'warn' ? C.amber : C.greyDim }}>
                  <span style={{ opacity: 0.5, marginRight: 6 }}>[{l.ts}]</span>{l.msg}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Results Sections ─────────────────────────────────────────────────── */}
      {results && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {/* Section nav */}
          <div style={{ display: 'flex', background: C.bg, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
            <button style={sectionBtn('capa')} onClick={() => setActiveSection('capa')}>
              ATT&CK TECHNIQUES {results.capa?.technique_count > 0 ? `[${results.capa.technique_count}]` : ''}
            </button>
            <button style={sectionBtn('floss')} onClick={() => setActiveSection('floss')}>
              STRINGS & IOCS {results.floss?.ioc_count > 0 ? `[${results.floss.ioc_count} IOCs]` : ''}
            </button>
            <button style={sectionBtn('speakeasy')} onClick={() => setActiveSection('speakeasy')}>
              EMULATED BEHAVIOR {results.speakeasy?.api_calls?.length > 0 ? `[${results.speakeasy.api_calls.length} calls]` : ''}
            </button>
          </div>

          <div style={{ flex: 1, overflowY: 'auto' }}>

            {/* ── CAPA Section ───────────────────────────────────────────────── */}
            <div style={{ display: activeSection === 'capa' ? 'block' : 'none' }}>
              {results.capa?.technique_count === 0 ? (
                <div style={{ padding: 24, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>
                  No ATT&amp;CK techniques identified — either the binary has no recognized capabilities or analysis has not been run.
                </div>
              ) : (
                <div>
                  <div style={{ padding: '8px 14px', color: C.greyDim, fontSize: 10, fontFamily: 'monospace', borderBottom: `1px solid ${C.border}` }}>
                    ATT&amp;CK TECHNIQUES IDENTIFIED — {results.capa?.technique_count} techniques across {Object.keys(capaByTactic).length} tactics
                  </div>
                  {Object.entries(capaByTactic).map(([tactic, techs]) => (
                    <TacticGroup key={tactic} tactic={tactic} techs={techs} />
                  ))}
                </div>
              )}
            </div>

            {/* ── FLOSS Section ──────────────────────────────────────────────── */}
            <div style={{ display: activeSection === 'floss' ? 'block' : 'none' }}>
              {/* Sub-tab bar */}
              <div style={{ display: 'flex', gap: 6, padding: '8px 14px', borderBottom: `1px solid ${C.border}` }}>
                <button style={subBtn(flossSubTab === 'iocs')} onClick={() => setFlossSubTab('iocs')}>IOCs ({iocs.length})</button>
                <button style={subBtn(flossSubTab === 'all')} onClick={() => setFlossSubTab('all')}>All Strings ({results.floss?.total_strings || 0})</button>
              </div>

              {flossSubTab === 'iocs' && (
                <div>
                  <div style={{ padding: '6px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>INDICATORS OF COMPROMISE — {iocs.length} flagged</span>
                    <div style={{ display: 'flex', gap: 4 }}>
                      {iocTypes.map(t => (
                        <button key={t} style={filterBtn(iocTypeFilter === t)} onClick={() => setIocTypeFilter(t)}>
                          {t} {t !== 'All' ? `(${iocs.filter(i => i.ioc_type === t).length})` : ''}
                        </button>
                      ))}
                    </div>
                  </div>
                  {filteredIocs.length === 0 ? (
                    <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>No IOCs found.</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                      <thead>
                        <tr>
                          <Th w={100}>IOC Type</Th>
                          <Th w={80}>String Type</Th>
                          <Th>Value</Th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIocs.map((ioc, i) => {
                          const match = iocMatchMap.get((ioc.string_value || '').toLowerCase());
                          return (
                            <tr key={i} style={{
                              background: match ? 'rgba(255,170,0,0.07)' : i % 2 === 0 ? '#080808' : 'transparent',
                              outline: match ? '1px solid rgba(255,170,0,0.25)' : undefined,
                            }}>
                              <Td col={C.amber}>{IOC_ICON[ioc.ioc_type] || ''} {ioc.ioc_type}</Td>
                              <Td col={ioc.string_type === 'decoded' ? C.green : ioc.string_type === 'stack' ? C.amber : C.greyDim}>{ioc.string_type}</Td>
                              <Td>
                                <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', flexDirection: 'column' }}>
                                  <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                                    <CopyableValue value={ioc.string_value} />
                                    {match && (
                                      <span style={{ padding: '1px 5px', fontSize: 9, background: 'rgba(255,170,0,0.15)', color: C.amber, border: `1px solid rgba(255,170,0,0.5)`, borderRadius: 2, flexShrink: 0 }}
                                        title={[match.threat_actor, match.description].filter(Boolean).join(' — ')}>
                                        MATCHED
                                      </span>
                                    )}
                                  </div>
                                  {match && (match.threat_actor || match.severity) && (
                                    <div style={{ color: C.greyDim, fontSize: 9, fontFamily: 'monospace' }}>
                                      {match.threat_actor && <span style={{ color: C.amber }}>{match.threat_actor}</span>}
                                      {match.severity && <span style={{ marginLeft: 5 }}>[{match.severity.toUpperCase()}]</span>}
                                    </div>
                                  )}
                                </div>
                              </Td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {flossSubTab === 'all' && (
                <div>
                  {(results?.floss?.total_strings || 0) > allStrings.length && (
                    <div style={{ padding: '5px 14px', fontSize: 9, color: C.amber, background: 'rgba(255,170,0,0.06)', borderBottom: `1px solid ${C.border}` }}>
                      ⚠ Showing first {allStrings.length.toLocaleString()} of {results.floss.total_strings.toLocaleString()} strings — search below only covers these.
                    </div>
                  )}
                  <div style={{ padding: '6px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <input value={stringSearch} onChange={e => setStringSearch(e.target.value)}
                      placeholder="Search strings..."
                      style={{ background: '#0a0a0a', border: `1px solid ${C.border}`, color: C.white, fontFamily: 'monospace', fontSize: 11, padding: '3px 8px', outline: 'none', width: 200 }} />
                    {['', 'static', 'stack', 'decoded', 'tight'].map(t => (
                      <button key={t} style={filterBtn(stringTypeFilter === t)} onClick={() => setStringTypeFilter(t)}>
                        {t || 'All'}
                      </button>
                    ))}
                  </div>
                  <StringList items={allStrings} filter={stringSearch} typeFilter={stringTypeFilter || undefined} />
                </div>
              )}
            </div>

            {/* ── Speakeasy Section ──────────────────────────────────────────── */}
            <div style={{ display: activeSection === 'speakeasy' ? 'block' : 'none' }}>
              {(seStatus === 'skipped' || seStatus === 'unsupported') ? (
                <div style={{ padding: 20, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>
                  ℹ Speakeasy emulation is not available for ELF binaries.<br />
                  Speakeasy emulates a Windows environment and requires PE32/PE64 executables.<br />
                  CAPA and FLOSS results are still available above.
                </div>
              ) : seStatus === 'error' && seError?.includes('timeout') ? (
                <div>
                  <div style={{ padding: 16, color: C.amber, fontFamily: 'monospace', fontSize: 11, borderBottom: `1px solid ${C.border}` }}>
                    ⚠ Speakeasy emulation timed out after 120 seconds.<br />
                    This may indicate the binary is environment-aware or uses anti-emulation techniques.<br />
                    Partial results (if any) are shown below.
                  </div>
                  <SpeeakeasyContent subTab={seSubTab} setSubTab={setSeSubTab} apiCatFilter={apiCatFilter} setApiCatFilter={setApiCatFilter} filteredApis={filteredApis} netEvents={netEvents} fileRegOps={fileRegOps} subBtn={subBtn} filterBtn={filterBtn} Th={Th} Td={Td} />
                </div>
              ) : seStatus === 'error' ? (
                <div style={{ padding: 20, color: C.red, fontFamily: 'monospace', fontSize: 11 }}>
                  Speakeasy error: {seError}
                </div>
              ) : (
                <SpeeakeasyContent subTab={seSubTab} setSubTab={setSeSubTab} apiCatFilter={apiCatFilter} setApiCatFilter={setApiCatFilter} filteredApis={filteredApis} netEvents={netEvents} fileRegOps={fileRegOps} subBtn={subBtn} filterBtn={filterBtn} Th={Th} Td={Td} />
              )}
            </div>

          </div>
        </div>
      )}

      {/* ── Modals ───────────────────────────────────────────────────────────── */}
      {showArtifactPicker && (
        <ArtifactPickerModal
          assetId={assetId}
          onSelect={(path) => {
            setSelectedPath(path);
            setSelectedFile(null);
            setDisplayName(path.split(/[\\/]/).pop());
            setShowArtifactPicker(false);
          }}
          onClose={() => setShowArtifactPicker(false)}
        />
      )}
      {showFileBrowser && (
        <FileBrowserModal
          assetId={assetId}
          onClose={() => setShowFileBrowser(false)}
          onFileReady={(localPath, name) => {
            setSelectedPath(localPath);
            setSelectedFile(null);
            setDisplayName(name);
            setShowFileBrowser(false);
          }}
        />
      )}
    </div>
  );
};

// ─── Tactic group (collapsible) ────────────────────────────────────────────────
function TacticGroup({ tactic, techs }) {
  const [open, setOpen] = useState(true);
  return (
    <div style={{ borderBottom: `1px solid ${C.border}` }}>
      <div onClick={() => setOpen(o => !o)}
        style={{ padding: '6px 14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, background: '#070707' }}>
        <span style={{ color: C.greyDim, fontSize: 10 }}>{open ? '▼' : '▶'}</span>
        <span style={{ color: C.amber, fontFamily: 'monospace', fontSize: 11, fontWeight: 'bold', letterSpacing: 1 }}>{tactic.toUpperCase()}</span>
        <span style={{ background: '#2a1500', color: C.amber, fontSize: 9, padding: '1px 6px', fontFamily: 'monospace' }}>{techs.length}</span>
      </div>
      {open && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={{ padding: '5px 14px', textAlign: 'left', fontSize: 9, color: '#bbb', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1, background: C.bgHeader, borderBottom: `1px solid ${C.border}`, width: 110 }}>TECHNIQUE ID</th>
              <th style={{ padding: '5px 14px', textAlign: 'left', fontSize: 9, color: '#bbb', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1, background: C.bgHeader, borderBottom: `1px solid ${C.border}` }}>TECHNIQUE NAME</th>
              <th style={{ padding: '5px 14px', textAlign: 'left', fontSize: 9, color: '#bbb', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1, background: C.bgHeader, borderBottom: `1px solid ${C.border}`, width: 200 }}>NAMESPACE</th>
              <th style={{ padding: '5px 14px', textAlign: 'left', fontSize: 9, color: '#bbb', fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1, background: C.bgHeader, borderBottom: `1px solid ${C.border}`, width: 100 }}>SEVERITY</th>
            </tr>
          </thead>
          <tbody>
            {techs.map((t, i) => (
              <tr key={i} style={{ background: i % 2 === 0 ? '#060606' : 'transparent' }}>
                <td style={{ padding: '5px 14px', fontSize: 11, fontFamily: 'monospace', borderBottom: `1px solid #0a0a0a` }}>
                  <a href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}/`}
                    target="_blank" rel="noopener noreferrer"
                    style={{ color: C.purple, textDecoration: 'none' }}
                    onMouseEnter={e => e.target.style.textDecoration = 'underline'}
                    onMouseLeave={e => e.target.style.textDecoration = 'none'}>
                    {t.technique_id}
                  </a>
                </td>
                <td style={{ padding: '5px 14px', fontSize: 11, color: C.white, fontFamily: 'monospace', borderBottom: `1px solid #0a0a0a` }}>{t.technique_name}</td>
                <td style={{ padding: '5px 14px', fontSize: 10, color: C.greyDim, fontFamily: 'monospace', borderBottom: `1px solid #0a0a0a` }}>{t.namespace || '—'}</td>
                <td style={{ padding: '5px 14px', fontSize: 10, color: sev(t.severity), fontFamily: 'monospace', borderBottom: `1px solid #0a0a0a`, textTransform: 'uppercase' }}>{t.severity || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ─── Speakeasy content panels ──────────────────────────────────────────────────
function SpeeakeasyContent({ subTab, setSubTab, apiCatFilter, setApiCatFilter, filteredApis, netEvents, fileRegOps, subBtn, filterBtn, Th, Td }) {
  const cats = ['All', ...Object.keys(API_CATEGORIES), 'Other'];
  return (
    <div>
      <div style={{ display: 'flex', gap: 6, padding: '8px 14px', borderBottom: `1px solid ${C.border}` }}>
        <button style={subBtn(subTab === 'api')} onClick={() => setSubTab('api')}>API Calls ({filteredApis.length})</button>
        <button style={subBtn(subTab === 'network')} onClick={() => setSubTab('network')}>Network ({netEvents.length})</button>
        <button style={subBtn(subTab === 'fileregistry')} onClick={() => setSubTab('fileregistry')}>File/Registry ({fileRegOps.length})</button>
      </div>

      {subTab === 'api' && (
        <div>
          <div style={{ padding: '6px 14px', borderBottom: `1px solid ${C.border}`, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>EMULATED API CALLS — {filteredApis.length} shown</span>
            {cats.map(c => <button key={c} style={filterBtn(apiCatFilter === c)} onClick={() => setApiCatFilter(c)}>{c}</button>)}
          </div>
          {filteredApis.length === 0 ? (
            <div style={{ padding: 16, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>No API calls recorded.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr><Th w={180}>API FUNCTION</Th><Th w={80}>CATEGORY</Th><Th>ARGUMENTS</Th></tr></thead>
              <tbody>
                {filteredApis.slice(0, 500).map((a, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? '#080808' : 'transparent' }}>
                    <Td col={C.green}>{a.func_name}</Td>
                    <Td col={C.greyDim}>{categorizeFn(a.func_name)}</Td>
                    <Td>{formatArgs(a.args)}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {filteredApis.length > 500 && (
            <div style={{ padding: '6px 14px', color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>
              Showing first 500 of {filteredApis.length} API calls.
            </div>
          )}
        </div>
      )}

      {subTab === 'network' && (
        <div>
          {netEvents.length === 0 ? (
            <div style={{ padding: 16, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>No network events recorded.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr><Th w={70}>PROTOCOL</Th><Th>HOST / IP</Th><Th w={70}>PORT</Th><Th>URL</Th></tr></thead>
              <tbody>
                {netEvents.map((n, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? '#080808' : 'transparent' }}>
                    <Td col={C.amber}>{(n.protocol || '').toUpperCase()}</Td>
                    <Td col={C.red}>{n.host}</Td>
                    <Td>{n.port || '—'}</Td>
                    <Td col={C.greyDim}>{n.url || '—'}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {subTab === 'fileregistry' && (
        <div>
          {fileRegOps.length === 0 ? (
            <div style={{ padding: 16, color: C.greyDim, fontFamily: 'monospace', fontSize: 11 }}>No file/registry operations recorded.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead><tr><Th w={180}>OPERATION</Th><Th w={80}>CATEGORY</Th><Th>PATH / ARGUMENTS</Th></tr></thead>
              <tbody>
                {fileRegOps.slice(0, 500).map((a, i) => (
                  <tr key={i} style={{ background: i % 2 === 0 ? '#080808' : 'transparent' }}>
                    <Td col={C.green}>{a.func_name}</Td>
                    <Td col={C.greyDim}>{categorizeFn(a.func_name)}</Td>
                    <Td>{formatArgs(a.args)}</Td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function formatArgs(args) {
  if (!args) return '—';
  try {
    const parsed = typeof args === 'string' ? JSON.parse(args) : args;
    if (Array.isArray(parsed)) return parsed.slice(0, 3).join(', ');
    return JSON.stringify(parsed).slice(0, 200);
  } catch {
    return String(args).slice(0, 200);
  }
}

function CopyableValue({ value }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    });
  };
  return (
    <span onClick={copy} style={{ cursor: 'pointer', color: copied ? C.green : C.white, wordBreak: 'break-all' }}
      title="Click to copy">
      {value}{copied && <span style={{ marginLeft: 6, fontSize: 9, color: C.green }}>✓ copied</span>}
    </span>
  );
}

export default BehavioralAnalysisTab;
