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
  const [deployDone, setDeployDone] = useState(null);  // null/'SUCCESS'/'FAILED'
  const [confirmDelete, setConfirmDelete] = useState(null); // agent_id pending confirm
  const [installToken, setInstallToken]   = useState(null); // {server_url, token} once generated
  const [installLoading, setInstallLoading] = useState(false);
  const logsEndRef = useRef(null);
  // This modal is permanently mounted by App.jsx (isOpen just toggles an
  // early `return null` below, the instance never unmounts) -- so nothing
  // React's own unmount lifecycle would normally handle for us happens
  // here automatically. abortRef lets closing mid-deploy actually stop the
  // in-flight stream instead of leaving it running against a closed modal.
  const abortRef = useRef(null);

  const addLog = (m, type = 'info') =>
    setLogs(p => [...p, { t: ts(), m, type }]);

  const handleDelete = async (agentId) => {
    try {
      await fetch(`${API}/api/agent/${agentId}`, { method: 'DELETE', credentials: 'include', headers: getAuth() });
      setFleet(f => f.filter(a => a.agent_id !== agentId));
    } catch {}
    setConfirmDelete(null);
  };

  // Load fleet when modal opens
  useEffect(() => {
    if (!isOpen) return;
    setLogs([]); setDeployDone(null); setInstallToken(null);

    fetch(`${API}/api/agent/list`, { credentials: 'include', headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(setFleet)
      .catch(() => {});
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

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const resp = await fetch(`${API}/api/agent/deploy`, {
        method: 'POST',
        credentials: 'include',
        headers: getAuth(),
        body: JSON.stringify({ ip: ip.trim(), username: username.trim(), password }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const e = await resp.json().catch(() => ({}));
        addLog('BACKEND_ERROR: ' + (e.detail || resp.statusText), 'error');
        setIsDeploying(false); setDeployDone('FAILED'); setPassword('');
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
              // Credential's only job was authenticating this one deploy
              // attempt -- nothing past this point needs it, so it doesn't
              // sit in memory for the rest of the session (this modal never
              // unmounts) on success OR failure.
              setPassword('');
              // Refresh fleet after deployment
              fetch(`${API}/api/agent/list`, { credentials: 'include', headers: getAuth() })
                .then(r => r.json()).then(setFleet).catch(() => {});
            }
          } catch {}
        });
      }
    } catch (e) {
      if (e.name === 'AbortError') return; // closed mid-deploy, not a real failure
      addLog('STREAM_ERROR: ' + e.message, 'error');
      setIsDeploying(false); setDeployDone('FAILED'); setPassword('');
    }
  };

  const handleClose = () => {
    abortRef.current?.abort();
    setPassword('');
    onClose();
  };

  const handleGenerateInstallToken = async () => {
    setInstallLoading(true);
    try {
      const r = await fetch(`${API}/api/agent/mint-install-token`, { method: 'POST', credentials: 'include', headers: getAuth() });
      if (r.ok) setInstallToken(await r.json());
    } catch {}
    finally { setInstallLoading(false); }
  };

  const installCommand = installToken ? [
    `python -c "import json,urllib.request;`,
    `urllib.request.urlretrieve('${installToken.server_url}/api/agent/download/orca_agent.py','orca_agent.py');`,
    `open('config.json','w').write(json.dumps({'server_url':'${installToken.server_url}','token':'${installToken.token}','bin_dir':'./bin','poll_interval':5}))"`,
    `&& pip install requests --quiet && python orca_agent.py`,
  ].join(' ') : '';

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
            <button onClick={handleClose} style={{ ...Btn, background: 'none', border: `1px solid #333`, color: '#666', padding: '4px 10px' }}>✕</button>
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
              DEPLOY_NEW_AGENT — Remote installation via SMB / Task Scheduler
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 10, alignItems: 'end', marginBottom: 16 }}>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>TARGET_IP</div>
                <input value={ip} onChange={e => setIp(e.target.value)}
                  placeholder="10.11.110.50" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && handleDeploy()} />
              </div>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>USERNAME</div>
                <input value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="DOMAIN\admin" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && handleDeploy()} />
              </div>
              <div>
                <div style={{ ...mono, fontSize: 9, color: C.greyDim, marginBottom: 4 }}>PASSWORD</div>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)}
                  placeholder="••••••••" style={Inp}
                  onKeyDown={e => e.key === 'Enter' && !isDeploying && handleDeploy()} />
              </div>
              <button
                onClick={handleDeploy}
                disabled={isDeploying || !ip.trim() || !username.trim() || !password.trim()}
                style={{
                  ...Btn,
                  background: isDeploying ? C.amber : deployDone === 'SUCCESS' ? C.greenDim : C.green,
                  color: '#000',
                  opacity: (!ip.trim() || !username.trim() || !password.trim()) && !isDeploying ? 0.4 : 1,
                  whiteSpace: 'nowrap',
                }}
              >
                {isDeploying ? '⟳ DEPLOYING...' : '▶ DEPLOY_AGENT'}
              </button>
            </div>

            {/* Manual install — for machines the SMB deploy above can't reach:
                the Docker host itself (no self-SMB), or anywhere you'd rather
                set up by hand. */}
            <div style={{ padding: '10px 14px', background: 'rgba(255,170,0,0.05)', border: `1px solid ${C.amber}`, marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <div style={{ ...mono, fontSize: 10, color: C.amber }}>MANUAL_INSTALL — run on the target machine (incl. this server's own Windows host)</div>
                <button onClick={handleGenerateInstallToken} disabled={installLoading}
                  style={{ ...Btn, padding: '3px 10px', fontSize: 9, background: 'none', border: `1px solid ${C.amber}`, color: C.amber }}>
                  {installLoading ? '⟳' : installToken ? '↻ REGENERATE' : '▶ GENERATE_COMMAND'}
                </button>
              </div>
              {installToken ? (
                <div style={{ ...mono, fontSize: 10, color: C.greyDim, userSelect: 'all', lineHeight: 1.6, wordBreak: 'break-all' }}>
                  {installCommand}
                </div>
              ) : (
                <div style={{ ...mono, fontSize: 10, color: C.greyDim, lineHeight: 1.6 }}>
                  Generates a one-time install command with a scoped agent token embedded — needs Python
                  on the target already. For a persistent Windows service instead (survives reboots), use
                  the token above with <span style={{ color: C.grey }}>agent/install.bat</span> from the repo.
                </div>
              )}
            </div>

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
