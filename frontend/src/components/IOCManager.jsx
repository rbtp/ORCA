import React, { useState, useEffect } from 'react';

export default function IOCManager() {
  const [iocs, setIocs] = useState([]);
  const [isAdding, setIsAdding] = useState(false);
  const [selectedIoc, setSelectedIoc] = useState(null);
  const [error, setError] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [correlations, setCorrelations] = useState({});
  const [loading, setLoading] = useState(true);

  const [newIoc, setNewIoc] = useState({
    indicator_type: 'FREE_TEXT',
    value: '',
    description: '',
    severity: 'HIGH',
  });

  const API_BASE = `${import.meta.env.VITE_API_URL}/api/ioc`;

  const iocTypes = {
    HASH_SHA256: { label: 'SHA256', regex: /^[a-fA-F0-9]{64}$/ },
    HASH_MD5:    { label: 'MD5',    regex: /^[a-fA-F0-9]{32}$/ },
    IP_V4:       { label: 'IPv4',   regex: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/ },
    NETWORK_URI: { label: 'Domain/URL', regex: /^(https?:\/\/)?([\da-z.-]+)\.([a-z.]{2,6})([\/\w .-]*)*\/?$/ },
    FREE_TEXT:   { label: 'String/FileName', regex: /^.{1,255}$/ },
  };

  useEffect(() => {
    fetchIocs();
  }, []);

  const fetchIocs = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/library`, {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) setIocs(await res.json());
    } catch (err) {
      console.error('Failed to load IOCs:', err);
    } finally {
      setLoading(false);
    }
  };

  const runGlobalCorrelation = async () => {
    setIsScanning(true);
    setScanProgress(10);
    const newCorrelations = {};
    try {
      for (let i = 0; i < iocs.length; i++) {
        const ioc = iocs[i];
        const res = await fetch(`${API_BASE}/search?query=${encodeURIComponent(ioc.value)}`, {
          credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        });
        if (res.ok) {
          const data = await res.json();
          if (data.data?.length > 0) {
            newCorrelations[ioc.value] = data.data.map(hit => ({
              case_name: hit.case_origin,
              hostname: hit.hostname,
              t_code: hit.t_code,
              detail: hit.artifact_alias || 'Raw Match',
            }));
          }
        } else if (res.status === 401) break;
        setScanProgress(Math.floor(((i + 1) / iocs.length) * 100));
      }
      setCorrelations(newCorrelations);
    } catch (err) {
      console.error('Correlation scan failed:', err);
    } finally {
      setTimeout(() => { setIsScanning(false); setScanProgress(0); }, 500);
    }
  };

  const validateAndAdd = async () => {
    const config = iocTypes[newIoc.indicator_type];
    if (newIoc.indicator_type !== 'FREE_TEXT' && !config.regex.test(newIoc.value)) {
      setError(`INVALID_FORMAT_FOR_${newIoc.indicator_type}`);
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/library`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newIoc),
      });
      if (!res.ok) { setError('SAVE_FAILED'); return; }
      const created = await res.json();
      setIocs([created, ...iocs]);
      setNewIoc({ indicator_type: 'FREE_TEXT', value: '', description: '', severity: 'HIGH' });
      setIsAdding(false);
      setError('');
    } catch (err) {
      setError('NETWORK_ERROR');
    }
  };

  const deleteIoc = async (ioc) => {
    try {
      await fetch(`${API_BASE}/library/${ioc.id}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      setIocs(iocs.filter(i => i.id !== ioc.id));
      setSelectedIoc(null);
    } catch (err) {
      console.error('Delete failed:', err);
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: selectedIoc ? '1fr 350px' : '1fr', gap: '20px', animation: 'fadeIn 0.4s ease', color: '#eee', fontFamily: 'monospace' }}>
      <main>
        <header style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '30px' }}>
          <div>
            <h1 style={{ fontSize: '24px', fontWeight: '900', color: '#00ff41', margin: 0 }}>IOC_RELIQUARY</h1>
            <div style={{ display: 'flex', gap: '15px', alignItems: 'center', marginTop: '10px' }}>
              <button
                onClick={runGlobalCorrelation}
                disabled={isScanning || iocs.length === 0}
                style={{ background: isScanning ? '#111' : '#222', color: '#00ff41', border: '1px solid #333', padding: '5px 10px', fontSize: '10px', cursor: 'pointer' }}
              >
                {isScanning ? `SCANNING_DB_${scanProgress}%` : 'RUN_DB_CORRELATION'}
              </button>
              <div style={{ height: '2px', width: '100px', background: '#111' }}>
                <div style={{ height: '100%', width: `${scanProgress}%`, background: '#00ff41', transition: 'width 0.1s' }} />
              </div>
            </div>
          </div>
          <button onClick={() => setIsAdding(true)} style={{ background: '#00ff41', color: '#000', border: 'none', padding: '10px 20px', fontWeight: 'bold', cursor: 'pointer' }}>[+] ADD_IOC</button>
        </header>

        <div style={{ border: '1px solid #111', background: '#080808' }}>
          {loading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: '#444' }}>LOADING_VAULT...</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ color: '#444', borderBottom: '1px solid #111', textAlign: 'left' }}>
                  <th style={{ padding: '15px' }}>TYPE</th>
                  <th style={{ padding: '15px' }}>VALUE</th>
                  <th style={{ padding: '15px' }}>SEVERITY</th>
                  <th style={{ padding: '15px' }}>DB_CORRELATION</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map(ioc => {
                  const matches = correlations[ioc.value] || [];
                  const hasMatch = matches.length > 0;
                  return (
                    <tr
                      key={ioc.id}
                      onClick={() => setSelectedIoc(ioc)}
                      style={{
                        borderBottom: '1px solid #111',
                        cursor: 'pointer',
                        background: selectedIoc?.id === ioc.id ? '#111' : 'transparent',
                        borderLeft: hasMatch ? '4px solid #ff4141' : '4px solid transparent',
                      }}
                    >
                      <td style={{ padding: '15px', color: '#00ff41' }}>{(ioc.indicator_type || '').replace('HASH_', '')}</td>
                      <td style={{ padding: '15px', color: '#eee' }}>{ioc.value}</td>
                      <td style={{ padding: '15px', color: ioc.severity === 'CRITICAL' ? '#ff4141' : '#888' }}>{ioc.severity}</td>
                      <td style={{ padding: '15px' }}>
                        {hasMatch ? (
                          <div style={{ color: '#ff4141' }}>
                            <strong>{matches.length} HITS FOUND</strong>
                            <div style={{ fontSize: '9px', color: '#666' }}>{matches[0].case_name} @ {matches[0].hostname}</div>
                          </div>
                        ) : (
                          <span style={{ color: '#222' }}>NO_HITS</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </main>

      {selectedIoc && (
        <aside style={{ background: '#050505', border: '1px solid #111', padding: '20px', position: 'sticky', top: '0', height: 'fit-content' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '20px' }}>
            <span style={{ color: '#00ff41', fontSize: '12px', fontWeight: 'bold' }}>[ INDICATOR_DETAILS ]</span>
            <button onClick={() => setSelectedIoc(null)} style={{ background: 'none', border: 'none', color: '#444', cursor: 'pointer' }}>X</button>
          </div>
          <div style={{ marginBottom: '15px' }}>
            <div style={{ fontSize: '9px', color: '#444', marginBottom: '5px' }}>VALUE</div>
            <div style={{ color: '#eee', fontSize: '11px', wordBreak: 'break-all', background: '#000', padding: '10px', border: '1px solid #111' }}>{selectedIoc.value}</div>
          </div>
          {selectedIoc.description && (
            <div style={{ marginBottom: '15px' }}>
              <div style={{ fontSize: '9px', color: '#444', marginBottom: '5px' }}>NOTE</div>
              <div style={{ color: '#888', fontSize: '11px', background: '#000', padding: '10px', border: '1px solid #111' }}>{selectedIoc.description}</div>
            </div>
          )}
          {correlations[selectedIoc.value] && (
            <div style={{ marginBottom: '20px' }}>
              <div style={{ fontSize: '9px', color: '#ff4141', marginBottom: '5px' }}>ACTIVE_CORRELATIONS</div>
              <div style={{ maxHeight: '200px', overflowY: 'auto' }}>
                {correlations[selectedIoc.value].map((m, idx) => (
                  <div key={idx} style={{ padding: '8px', borderBottom: '1px solid #111', fontSize: '10px' }}>
                    <div style={{ color: '#00ff41' }}>{m.case_name} / {m.hostname}</div>
                    <div style={{ color: '#444' }}>{m.t_code} - {m.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
          <button
            onClick={() => deleteIoc(selectedIoc)}
            style={{ width: '100%', marginTop: '30px', background: 'transparent', border: '1px solid #ff4141', color: '#ff4141', padding: '10px', fontSize: '10px', cursor: 'pointer' }}
          >
            DELETE_INDICATOR
          </button>
        </aside>
      )}

      {isAdding && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.95)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ background: '#050505', border: '1px solid #00ff41', padding: '30px', width: '450px' }}>
            <h2 style={{ color: '#00ff41', margin: '0 0 20px 0', fontSize: '18px' }}>IOC_ENTRY_TERMINAL</h2>
            <select
              value={newIoc.indicator_type}
              onChange={(e) => setNewIoc({ ...newIoc, indicator_type: e.target.value })}
              style={{ width: '100%', background: '#000', color: '#eee', border: '1px solid #222', padding: '12px', marginBottom: '15px' }}
            >
              {Object.entries(iocTypes).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <input
              value={newIoc.value}
              onChange={(e) => { setNewIoc({ ...newIoc, value: e.target.value }); setError(''); }}
              placeholder="IOC value (hash, IP, domain, string...)"
              style={{ width: '100%', background: '#000', color: '#eee', border: `1px solid ${error ? '#ff4141' : '#222'}`, padding: '12px', boxSizing: 'border-box', marginBottom: '15px' }}
            />
            <select
              value={newIoc.severity}
              onChange={(e) => setNewIoc({ ...newIoc, severity: e.target.value })}
              style={{ width: '100%', background: '#000', color: '#eee', border: '1px solid #222', padding: '12px', marginBottom: '15px' }}
            >
              {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <textarea
              value={newIoc.description}
              onChange={(e) => setNewIoc({ ...newIoc, description: e.target.value })}
              placeholder="Note / Justification"
              style={{ width: '100%', background: '#000', color: '#eee', border: '1px solid #222', padding: '12px', minHeight: '80px', boxSizing: 'border-box', marginBottom: '5px' }}
            />
            {error && <div style={{ color: '#ff4141', fontSize: '10px', marginBottom: '15px' }}>{error}</div>}
            <div style={{ display: 'flex', gap: '15px', marginTop: '15px' }}>
              <button onClick={validateAndAdd} style={{ flex: 1, background: '#00ff41', border: 'none', padding: '12px', fontWeight: 'bold', cursor: 'pointer' }}>COMMIT</button>
              <button onClick={() => { setIsAdding(false); setError(''); }} style={{ flex: 1, background: 'none', color: '#444', border: '1px solid #444', cursor: 'pointer' }}>ABORT</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
