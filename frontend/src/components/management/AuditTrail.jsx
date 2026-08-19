import React, { useState, useEffect, useMemo } from 'react';

export default function AuditTrail() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [caseFilter, setCaseFilter] = useState('ALL');
  const [assetFilter, setAssetFilter] = useState('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/admin/audit-log`, {
        credentials: 'include',
      });
      const data = await res.json();
      if (res.ok && Array.isArray(data)) setLogs(data);
    } catch (err) { console.error('FETCH_ERROR:', err); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchLogs(); }, []);

  const cases = useMemo(() => [...new Set(logs.map(l => l.case_name).filter(Boolean))].sort(), [logs]);
  const assets = useMemo(() => {
    const pool = caseFilter === 'ALL' ? logs : logs.filter(l => l.case_name === caseFilter);
    return [...new Set(pool.map(l => l.asset_hostname).filter(Boolean))].sort();
  }, [logs, caseFilter]);

  const filtered = useMemo(() => logs.filter(l =>
    (caseFilter === 'ALL' || l.case_name === caseFilter) &&
    (assetFilter === 'ALL' || l.asset_hostname === assetFilter)
  ), [logs, caseFilter, assetFilter]);

  return (
    <div style={ContainerStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={HeaderStyle}>USER_ACTIVITY_AUDIT_TRAIL</h3>
        <button style={RefreshBtn} onClick={fetchLogs}>↺ REFRESH</button>
      </div>

      <div style={{ display: 'flex', gap: '16px', marginBottom: '18px' }}>
        <div style={InputGroup}>
          <label style={LabelStyle}>INVESTIGATION</label>
          <select style={InputStyle} value={caseFilter}
            onChange={(e) => { setCaseFilter(e.target.value); setAssetFilter('ALL'); }}>
            <option value="ALL">ALL_INVESTIGATIONS ({logs.length})</option>
            {cases.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        <div style={InputGroup}>
          <label style={LabelStyle}>ASSET</label>
          <select style={InputStyle} value={assetFilter} onChange={(e) => setAssetFilter(e.target.value)}>
            <option value="ALL">ALL_ASSETS</option>
            {assets.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
      </div>

      {loading ? (
        <div style={{ color: '#666', fontSize: '11px', padding: '20px' }}>LOADING_AUDIT_LOG...</div>
      ) : filtered.length === 0 ? (
        <div style={{ color: '#666', fontSize: '11px', padding: '20px' }}>NO_LOGGED_ACTIVITY</div>
      ) : (
        <table style={TableStyle}>
          <thead>
            <tr style={HeadRow}>
              <th>TIMESTAMP</th>
              <th>OPERATOR</th>
              <th>ACTION</th>
              <th>INVESTIGATION</th>
              <th>ASSET</th>
              <th>TECHNIQUE</th>
              <th>DETAILS</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(l => (
              <tr key={l.id} style={BodyRow}>
                <td style={{ color: '#888', whiteSpace: 'nowrap' }}>{new Date(l.ts).toLocaleString([], { hour12: false })}</td>
                <td style={{ color: '#00ff41' }}>{l.username}{l.user_initials ? ` [${l.user_initials}]` : ''}</td>
                <td style={{ color: '#ff4141' }}>{l.action}</td>
                <td>{l.case_name || '—'}</td>
                <td>{l.asset_hostname || '—'}</td>
                <td>{l.t_code || '—'}</td>
                <td style={{ color: '#aaa' }}>{l.details || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// STYLES
const ContainerStyle = { padding: '20px', background: '#050505', border: '1px solid #111' };
const HeaderStyle = { color: '#00ff41', fontSize: '14px', letterSpacing: '2px', margin: 0 };
const RefreshBtn = { background: 'none', border: '1px dashed #00ff41', color: '#00ff41', padding: '8px 16px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px' };
const InputGroup = { display: 'flex', flexDirection: 'column', gap: '6px', minWidth: '220px' };
const LabelStyle = { color: '#aaa', fontSize: '9px', fontFamily: 'monospace' };
const InputStyle = { background: '#000', border: '1px solid #222', color: '#00ff41', padding: '8px', fontSize: '11px', fontFamily: 'monospace', outline: 'none' };
const TableStyle = { width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '11px' };
const HeadRow = { textAlign: 'left', color: '#aaa', borderBottom: '1px solid #111' };
const BodyRow = { borderBottom: '1px solid #0a0a0a', height: '36px' };
