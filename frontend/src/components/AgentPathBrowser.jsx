import React, { useState, useEffect, useCallback } from 'react';

// Browse files/folders on an agent's computer (the analyst workstation running
// the ORCA agent), for path fields that are used on that agent: image path,
// ClamAV scan target, vuln-scan path.
//   mode 'file': pick a file      mode 'dir': pick a folder      mode 'any': either

const G = '#00ff41', DIM = '#666', BORDER = '#2a2a2a', AMBER = '#ffaa00', RED = '#ff4444';
const btn = {
  background: '#0a0a0a', border: `1px solid ${BORDER}`, color: G, fontFamily: 'monospace',
  fontSize: 10, padding: '5px 10px', cursor: 'pointer', letterSpacing: 1,
};

export const DISK_IMAGE_RX = /\.(e01|ex01|s01|l01|aff4?|vhdx?|vmdk|vdi|qcow2?|dd|raw|img|bin|iso|dmg|00[01])$/i;

const fmtSize = n => {
  if (n == null) return '';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const fmtTime = t => (t ? new Date(t * 1000).toLocaleString() : '');

// Folder to open first: the field's folder (a file's parent), else the drive list.
const startFolder = (value, mode) => {
  const v = (value || '').trim();
  if (!v) return '';
  if (/^[A-Za-z]:\\?$/.test(v)) return v.length === 2 ? v + '\\' : v;
  if (/[\\/]$/.test(v)) return v;
  const looksLikeFile = mode !== 'dir' && /\.[^\\/.]{1,6}$/.test(v);
  if (!looksLikeFile) return v;
  const i = Math.max(v.lastIndexOf('\\'), v.lastIndexOf('/'));
  if (i < 0) return '';
  const p = v.slice(0, i);
  return /^[A-Za-z]:$/.test(p) ? p + '\\' : p;
};

export function AgentPathBrowser({ agentId, assetId, mode = 'any', initialPath, onSelect, onClose, title, highlight }) {
  const [path, setPath] = useState(null);
  const [typed, setTyped] = useState('');
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');

  const load = useCallback(async (p, fallbackToDrives = false) => {
    setLoading(true); setError(''); setSelected(null); setFilter('');
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/agent/${encodeURIComponent(agentId)}/browse`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: p, asset_id: assetId != null ? Number(assetId) : null }),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j.detail || `HTTP ${r.status}`);
      setData(j); setPath(j.path); setTyped(j.path);
    } catch (e) {
      if (fallbackToDrives && p) {
        setLoading(false);
        await load('', false);
        setError(`${p}: ${e.message}`);
        return;
      }
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [agentId, assetId]);

  useEffect(() => { load(startFolder(initialPath, mode), true); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const entries = (data?.entries || []).filter(e => !filter || e.name.toLowerCase().includes(filter.toLowerCase()));
  const atDrives = path === '';
  const selectedFolder = selected && (selected.type === 'dir' || selected.type === 'drive');
  const folderTarget = mode === 'file' ? null : selectedFolder ? selected.path : (atDrives || path == null ? null : path);
  const canPickFile = mode !== 'dir' && selected && selected.type === 'file';

  const open = e => {
    if (e.type === 'drive' && e.ready === false) { setError(`${e.name} is not ready (no media?)`); return; }
    if (e.type === 'drive' || e.type === 'dir') load(e.path);
    else if (mode !== 'dir') onSelect(e.path);
  };

  return (
    <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 10000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div onClick={e => e.stopPropagation()} data-testid="agent-path-browser"
        style={{ width: 'min(860px, 94vw)', height: 'min(620px, 88vh)', background: '#050505', border: `1px solid ${G}`, display: 'flex', flexDirection: 'column', fontFamily: 'monospace', fontSize: 11, color: '#ccc' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${BORDER}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ color: G, letterSpacing: 1 }}>{title || 'BROWSE'} <span style={{ color: DIM }}>— on the agent computer</span></span>
          <button onClick={onClose} style={{ ...btn, border: 'none', color: DIM }}>✕</button>
        </div>

        <div style={{ padding: '8px 14px', display: 'flex', gap: 6, borderBottom: `1px solid ${BORDER}` }}>
          <button onClick={() => load('')} title="Drives" style={btn}>DRIVES</button>
          <button onClick={() => load(data?.parent ?? '')} disabled={atDrives} title="Up one folder" style={{ ...btn, opacity: atDrives ? 0.4 : 1 }}>▲ UP</button>
          <input value={typed} onChange={e => setTyped(e.target.value)} onKeyDown={e => e.key === 'Enter' && load(typed.trim())}
            placeholder="Type a folder (e.g. E:\ or \\server\share) and press Enter"
            style={{ flex: 1, background: '#000', border: `1px solid ${BORDER}`, color: G, fontFamily: 'monospace', fontSize: 11, padding: '5px 8px', outline: 'none' }} />
          <button onClick={() => load(typed.trim())} style={btn}>GO</button>
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="FILTER..."
            style={{ width: 120, background: '#000', border: `1px solid ${BORDER}`, color: G, fontFamily: 'monospace', fontSize: 11, padding: '5px 8px', outline: 'none' }} />
        </div>

        {error && <div style={{ padding: '6px 14px', color: RED, borderBottom: `1px solid ${BORDER}` }}>{error}</div>}
        {data?.truncated && <div style={{ padding: '6px 14px', color: AMBER }}>Showing the first 5000 entries; type a more specific folder or use FILTER.</div>}

        <div style={{ flex: 1, overflowY: 'auto' }}>
          {loading && <div style={{ padding: 14, color: DIM }}>LOADING...</div>}
          {!loading && entries.length === 0 && !error && <div style={{ padding: 14, color: DIM }}>{filter ? 'No match.' : 'Empty folder.'}</div>}
          {!loading && entries.map(e => {
            const isSel = selected?.path === e.path;
            const hl = e.type === 'file' && highlight && highlight.test(e.name);
            const dimmed = e.type === 'file' && mode === 'dir';
            return (
              <div key={e.path} onClick={() => setSelected(e)} onDoubleClick={() => open(e)} title={e.path}
                style={{ display: 'flex', gap: 10, padding: '4px 14px', cursor: 'pointer', alignItems: 'center',
                  background: isSel ? 'rgba(0,255,65,0.12)' : 'transparent', opacity: dimmed ? 0.4 : 1,
                  color: e.type === 'file' ? (hl ? AMBER : '#bbb') : G }}>
                <span style={{ width: 18 }}>{e.type === 'drive' ? '🖴' : e.type === 'dir' ? '📁' : '📄'}</span>
                <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {e.name}{e.type === 'drive' && (e.label || e.kind) ? `  ${[e.label, e.kind].filter(Boolean).join(' · ')}` : ''}
                </span>
                <span style={{ width: 80, textAlign: 'right', color: DIM }}>{fmtSize(e.size)}</span>
                <span style={{ width: 160, textAlign: 'right', color: DIM }}>{fmtTime(e.mtime)}</span>
              </div>
            );
          })}
        </div>

        <div style={{ padding: '10px 14px', borderTop: `1px solid ${BORDER}`, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ flex: 1, color: DIM, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {selected ? selected.path : (path || 'Double-click a drive or folder to open it')}
          </span>
          {mode !== 'dir' && (
            <button onClick={() => canPickFile && onSelect(selected.path)} disabled={!canPickFile}
              style={{ ...btn, background: canPickFile ? G : '#0a0a0a', color: canPickFile ? '#000' : DIM, opacity: canPickFile ? 1 : 0.5 }}>
              SELECT FILE
            </button>
          )}
          {mode !== 'file' && (
            <button onClick={() => folderTarget && onSelect(folderTarget)} disabled={!folderTarget}
              style={{ ...btn, background: folderTarget ? G : '#0a0a0a', color: folderTarget ? '#000' : DIM, opacity: folderTarget ? 1 : 0.5 }}>
              {selectedFolder ? 'SELECT THIS FOLDER' : 'SELECT CURRENT FOLDER'}
            </button>
          )}
          <button onClick={onClose} style={btn}>CANCEL</button>
        </div>
      </div>
    </div>
  );
}

// "BROWSE" button + dialog. Disabled (with a hint) until an agent is chosen.
export default function PathBrowseButton({ agentId, assetId, mode, value, onSelect, title, highlight, style }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => agentId && setOpen(true)} disabled={!agentId}
        title={agentId ? 'Browse folders and files on the selected agent\'s computer' : 'Select an agent first: browsing shows that agent\'s computer'}
        style={{ ...btn, opacity: agentId ? 1 : 0.4, cursor: agentId ? 'pointer' : 'not-allowed', ...style }}>
        📂 BROWSE
      </button>
      {open && (
        <AgentPathBrowser agentId={agentId} assetId={assetId} mode={mode} initialPath={value} title={title} highlight={highlight}
          onClose={() => setOpen(false)}
          onSelect={p => { setOpen(false); onSelect(p); }} />
      )}
    </>
  );
}
