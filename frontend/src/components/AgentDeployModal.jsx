import { useState, useEffect, useRef } from 'react';

const API = `${import.meta.env.VITE_API_URL}`;
const C = {
  green: '#00ff41', greenDim: '#00cc33',
  red: '#ff4444', amber: '#ffaa00',
  white: '#f0f0f0', grey: '#aaaaaa', greyDim: '#555',
  border: '#1a1a1a', bg: '#000', bgCard: '#080808', bgHeader: '#0a0a0a',
};
const mono = { fontFamily: 'monospace' };
const Inp = {
  background: '#050505', border: `1px solid ${C.border}`,
  color: C.white, padding: '6px 10px', fontSize: 11,
  fontFamily: 'monospace', outline: 'none', width: '100%', boxSizing: 'border-box',
};
const Btn = {
  padding: '7px 16px', border: 'none', cursor: 'pointer',
  fontWeight: 'bold', fontSize: 11, fontFamily: 'monospace',
};

const ts = () => new Date().toLocaleTimeString([], { hour12: false });
const getAuth = () => ({ 'Content-Type': 'application/json' });

function StatusDot({ status }) {
  const col = status === 'ONLINE' ? C.green : C.greyDim;
  return <span style={{ color: col, marginRight: 6 }}>●</span>;
}

export default function AgentDeployModal({ isOpen, onClose }) {
  const [fleet, setFleet]           = useState([]);
  const [ip, setIp]                 = useState('');
  const [username, setUsername]     = useState('');
  const [password, setPassword]     = useState('');
  const [logs, setLogs]             = useState([]);
  const [isDeploying, setIsDeploying] = useState(false);
  const [psexecOk, setPsexecOk]     = useState(null); // null=checking, true/false
  const [deployDone, setDeployDone] = useState(null);  // null/'SUCCESS'/'FAILED'
  const [confirmDelete, setConfirmDelete] = useState(null); // agent_id pending confirm
  const logsEndRef = useRef(null);

  const addLog = (m, type = 'info') =>
    setLogs(p => [...p, { t: ts(), m, type }]);

  const handleDelete = async (agentId) => {
    try {
      await fetch(`${API}/api/agent/${agentId}`, { method: 'DELETE', credentials: 'include', headers: getAuth() });
      setFleet(f => f.filter(a => a.agent_id !== agentId));
    } catch {}
    setConfirmDelete(null);
  };

  // Load fleet + psexec status when modal opens
  useEffect(() => {
    if (!isOpen) return;
    setLogs([]); setDeployDone(null);

    fetch(`${API}/api/agent/list`, { credentials: 'include', headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(setFleet)
      .catch(() => {});

    fetch(`${API}/api/agent/deploy/psexec-status`, { credentials: 'include', headers: getAuth() })
      .then(r => r.json())
      .then(d => setPsexecOk(d.available))
      .catch(() => setPsexecOk(false));
  }, [isOpen]);

  // Auto-scroll logs
  useEffect(() => { logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);

  // Refresh fleet every 10s while modal is open
  useEffect(() => {
    if (!isOpen) return;
    const id = setInterval(() => {
      fetch(`${API}/api/agent/list`, { credentials: 'include', headers: getAuth() })
        .then(r => r.ok ? r.json() : [])
        .then(setFleet)
        .catch(() => {});
    }, 10000);
    return () => clearInterval(id);
  }, [isOpen]);

  const handleDeploy = async () => {
    if (!ip.trim() || !username.trim() || !password.trim()) return;
    setIsDeploying(true); setDeployDone(null); setLogs([]);
    addLog(`Starting deployment to ${ip}...`);

    try {
      const resp = await fetch(`${API}/api/agent/deploy`, {
        method: 'POST',
        credentials: 'include',
        headers: getAuth(),
        body: JSON.stringify({ ip: ip.trim(), username: username.trim(), password }),
      });

      if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        addLog('BACKEND_ERROR: ' + (e.detail || resp.statusText), 'error');
        setIsDeploying(false); setDeployDone('FAILED');
        return;
      }

      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(line => {
          if (!line.startsWith('data: ')) return;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'log')   addLog(evt.data);
            if (evt.type === 'error') addLog(evt.data, 'error');
            if (evt.type === 'done') {
              setDeployDone(evt.data);
              setIsDeploying(false);
              // Refresh fleet after deployment
              fetch(`${API}/api/agent/list`, { credentials: 'include', headers: getAuth() })
                .then(r => r.json()).then(setFleet).catch(() => {});
            }
          } catch {}
        });
      }
    } catch (e) {
      addLog('STREAM_ERROR: ' + e.message, 'error');
      setIsDeploying(false); setDeployDone('FAILED');
    }
  };

  if (!isOpen) return null;

  const online  = fleet.filter(a => a.status === 'ONLINE').length;
  const offline = fleet.length - online;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,0.85)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 860, maxHeight: '90vh',
        background: C.bg, border: `1px solid #222`,
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>

        {/* Header */}
        <div style={{
          background: C.bgHeader, borderBottom: `1px solid ${C.border}`,
          padding: '12px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <div style={{ ...mono, fontSize: 11, color: C.green, letterSpacing: 2 }}>
            [ AGENT_FLEET_MANAGER ]
          </div>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
            <span style={{ ...mono, fontSize: 10, color: C.green }}>● ONLINE: {online}</span>
            <span style={{ ...mono, fontSize: 10, color: C.greyDim }}>○ OFFLINE: {offline}</span>
            <button onClick={onClose} style={{ ...Btn, background: 'none', border: `1px solid #333`, color: '#666', padding: '4px 10px' }}>✕</button>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>

          {/* Fleet table */}
          <div style={{ borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
            <div style={{ padding: '8px 20px', background: '#060606', borderBottom: `1px solid ${C.border}` }}>
              <span style={{ ...mono, fontSize: 9, color: C.greyDim, letterSpacing: 1 }}>REGISTERED_AGENTS</span>
            </div>
            {fleet.length === 0 ? (
              <div style={{ ...mono, fontSize: 11, color: C.greyDim, padding: '16px 20px' }}>
                NO AGENTS REGISTERED — deploy one below.
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', ...mono, fontSize: 11 }}>
                <thead>
                  <tr style={{ background: '#060606' }}>
                    {['AGENT_ID', 'HOSTNAME', 'ANALYST', 'CAPABILITIES', 'LAST_SEEN', 'STATUS', ''].map(h => (
                      <th key={h} style={{ padding: '6px 16px', textAlign: 'left', color: C.greyDim, fontSize: 9, letterSpacing: 1, borderBottom: `1px solid ${C.border}`, fontWeight: 'normal' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {fleet.map(a => {
                    const lastSeen = a.last_seen ? new Date(a.last_seen).toLocaleTimeString([], { hour12: false }) : '—';
                    const caps = Array.isArray(a.capabilities) ? a.capabilities.join(', ') : '—';
                    return (
                      <tr key={a.agent_id} style={{ borderBottom: `1px solid #0a0a0a` }}>
                        <td style={{ padding: '7px 16px', color: C.greyDim, fontSize: 10 }}>{a.agent_id}</td>
                        <td style={{ padding: '7px 16px', color: C.white }}>{a.hostname}</td>
                        <td style={{ padding: '7px 16px', color: C.grey }}>{a.analyst || '—'}</td>
                        <td style={{ padding: '7px 16px', color: C.greyDim, fontSize: 10 }}>{caps}</td>
                        <td style={{ padding: '7px 16px', color: C.greyDim, fontSize: 10 }}>{lastSeen}</td>
                        <td style={{ padding: '7px 16px' }}>
                          <StatusDot status={a.status} />
                          <span style={{ color: a.status === 'ONLINE' ? C.green : C.greyDim, fontSize: 10 }}>{a.status}</span>
                        </td>
                        <td style={{ padding: '7px 16px', whiteSpace: 'nowrap' }}>
                          {confirmDelete === a.agent_id ? (
                            <span style={{ display: 'flex', gap: 6 }}>
                              <button onClick={() => handleDelete(a.agent_id)} style={{ ...Btn, padding: '3px 10px', background: C.red, color: '#fff', fontSize: 10 }}>CONFIRM</button>
                              <button onClick={() => setConfirmDelete(null)} style={{ ...Btn, padding: '3px 8px', background: 'none', border: `1px solid #333`, color: C.greyDim, fontSize: 10 }}>CANCEL</button>
                            </span>
                          ) : (
                            <button onClick={() => setConfirmDelete(a.agent_id)} style={{ ...Btn, padding: '3px 10px', background: 'none', border: `1px solid #2a0000`, color: '#552222', fontSize: 10 }}>✕ REMOVE</button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* Deploy form */}
          <div style={{ padding: '20px', flexShrink: 0 }}>
            <div style={{ ...mono, fontSize: 9, color: C.greyDim, letterSpacing: 1, marginBottom: 16 }}>
              DEPLOY_NEW_AGENT — Remote installation via PsExec
              {psexecOk === false && (
                <span style={{ color: C.amber, marginLeft: 12 }}>
                  ⚠ psexec.exe not found in backend/bin/ — auto-deploy unavailable
                </span>
              )}
              {psexecOk === true && (
                <span style={{ color: C.green, marginLeft: 12 }}>✓ PsExec ready</span>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 10, alignItems: 'end', marginBottom: 16 }}>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>TARGET_IP</div>
                <input value={ip} onChange={e => setIp(e.target.value)}
                  placeholder="10.11.110.50" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && psexecOk && handleDeploy()} />
              </div>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>USERNAME</div>
                <input value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="DOMAIN\admin" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && psexecOk && handleDeploy()} />
              </div>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>PASSWORD</div>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && psexecOk && handleDeploy()} />
              </div>
              <button
                onClick={handleDeploy}
                disabled={isDeploying || !psexecOk || !ip.trim() || !username.trim() || !password.trim()}
                style={{
                  ...Btn,
                  background: isDeploying ? C.amber : deployDone === 'SUCCESS' ? C.greenDim : C.green,
                  color: '#000',
                  opacity: (!psexecOk || !ip.trim() || !username.trim() || !password.trim()) && !isDeploying ? 0.4 : 1,
                  whiteSpace: 'nowrap',
                }}
              >
                {isDeploying ? '⟳ DEPLOYING...' : '▶ DEPLOY_AGENT'}
              </button>
            </div>

            {/* Manual install note */}
            {psexecOk === false && (
              <div style={{ padding: '10px 14px', background: 'rgba(255,170,0,0.05)', border: `1px solid ${C.amber}`, marginBottom: 12 }}>
                <div style={{ ...mono, fontSize: 10, color: C.amber, marginBottom: 6 }}>MANUAL_INSTALL — Run on target workstation:</div>
                <div style={{ ...mono, fontSize: 10, color: C.greyDim, userSelect: 'all', lineHeight: 1.6 }}>
                  {`python -c "import urllib.request; urllib.request.urlretrieve('${window.location.origin}/api/agent/download/orca_agent.py','orca_agent.py')" && pip install requests && python orca_agent.py`}
                </div>
              </div>
            )}

            {/* Deployment log */}
            {logs.length > 0 && (
              <div style={{ background: '#040404', border: `1px solid ${C.border}`, padding: '10px 14px', maxHeight: 200, overflowY: 'auto' }}>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 6, letterSpacing: 1 }}>DEPLOYMENT_LOG</div>
                {logs.map((l, i) => (
                  <div key={i} style={{
                    ...mono, fontSize: 10, lineHeight: 1.7,
                    color: l.type === 'error' ? C.red : l.type === 'success' ? C.green : C.grey,
                  }}>
                    <span style={{ color: '#999', marginRight: 8 }}>[{l.t}]</span>{l.m}
                  </div>
                ))}
                {deployDone && (
                  <div style={{ ...mono, fontSize: 11, fontWeight: 'bold', marginTop: 6,
                    color: deployDone === 'SUCCESS' ? C.green : C.red }}>
                    {deployDone === 'SUCCESS' ? '✓ DEPLOYMENT_COMPLETE' : '✗ DEPLOYMENT_FAILED'}
                  </div>
                )}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
