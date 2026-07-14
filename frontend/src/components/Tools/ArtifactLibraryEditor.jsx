import React, { useState, useEffect } from 'react';
import axios from 'axios';

const ArtifactLibraryEditor = () => {
  const [step, setStep] = useState(1);
  const [mode, setMode] = useState('edit');
  const [showWizard, setShowWizard] = useState(false);
  const [wizardTarget, setWizardTarget] = useState('RAW'); 
  const [tCodes, setTCodes] = useState([]);
  const [selectedTCode, setSelectedTCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [consoleOutput, setConsoleOutput] = useState('');
  const [testData, setTestData] = useState([]);
  const [activePayloadTab, setActivePayloadTab] = useState('RAW');
  const [statusMsg, setStatusMsg] = useState(null);
  
  const [formData, setFormData] = useState({
    live_analysis: '',
    dead_disk_analysis: '',
    collection_strategy: '',
    custom_vql: '',
    surgical_yaml: ''
  });

  const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

  // Helper to get auth header
  const getAuthHeader = () => ({
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('orca_token')}`,
      'Content-Type': 'application/json'
    }
  });

  useEffect(() => {
    const fetchCodes = async () => {
      try {
        const res = await axios.get(`${API_BASE}/techniques`, getAuthHeader());
        const data = Array.isArray(res.data) ? res.data : (res.data.techniques || []);
        setTCodes(data);
      } catch (err) {
        console.error("TECH_FETCH_ERR:", err);
        setTCodes([]);
      }
    };
    fetchCodes();
  }, []);

  const handleNextToEdit = async () => {
    if (mode === 'edit' && selectedTCode) {
      setLoading(true);
      try {
        const res = await axios.get(`${API_BASE}/library/${selectedTCode}`, getAuthHeader());
        setFormData({
          live_analysis: res.data.live_analysis || '',
          dead_disk_analysis: res.data.dead_disk_analysis || '',
          collection_strategy: res.data.collection_strategy || '',
          custom_vql: res.data.custom_vql || '',
          surgical_yaml: res.data.surgical_yaml || ''
        });
        if (res.data.surgical_yaml) setActivePayloadTab('YAML');
        setStep(2);
      } catch (err) {
        setStatusMsg({ type: 'error', text: 'TECHNIQUE_DATA_UNREACHABLE' });
      } finally {
        setLoading(false);
      }
    } else {
      setStep(2);
    }
  };

  const handleSave = async () => {
    const submissionData = { ...formData };
    if (activePayloadTab === 'RAW') {
      submissionData.surgical_yaml = '';
    } else {
      submissionData.custom_vql = '';
    }

    try {
      await axios.post(`${API_BASE}/library/${selectedTCode}/update`, submissionData, getAuthHeader());
      setStatusMsg({ type: 'success', text: 'GLOBAL_LIBRARY_SYNCHRONIZED' });
      setStep(1);
    } catch (err) {
      setStatusMsg({ type: 'error', text: 'COMMIT_FAILED' });
    }
  };

  const handleTestVQL = async () => {
    setTesting(true);
    setConsoleOutput("[*] INITIALIZING SANDBOX... EXECUTING VELOCIRAPTOR\n");
    setTestData([]);
    
    const payload = activePayloadTab === 'RAW' ? formData.custom_vql : formData.surgical_yaml;
    
    try {
      const res = await axios.post(`${API_BASE}/library/test`, { 
        vql: payload,
        is_yaml: activePayloadTab === 'YAML'
      }, getAuthHeader());
      
      if (res.data.success) {
        setConsoleOutput(prev => prev + `[+] SUCCESS: Query returned ${res.data.total_count} rows.\n`);
        setTestData(res.data.data);
      } else {
        setConsoleOutput(prev => prev + `[!] VR ERROR: ${res.data.error}`);
      }
    } catch (err) {
      setConsoleOutput(prev => prev + `[!] CONNECTION ERROR: ${err.message}`);
    } finally {
      setTesting(false);
    }
  };

  const TerminalInput = ({ label, value, onChange, isCode = false }) => (
    <div style={{ marginBottom: '30px' }}>
      <label style={{ display: 'block', fontSize: '10px', color: isCode ? '#00ff41' : '#444', marginBottom: '10px', letterSpacing: '2px', fontWeight: 'bold' }}>
        [ {label.toUpperCase()} ]
      </label>
      <textarea 
        style={{ 
          width: '100%', 
          height: isCode ? '300px' : '120px', 
          background: isCode ? '#020202' : '#050505', 
          border: `1px solid ${isCode ? '#003300' : '#111'}`, 
          color: isCode ? '#00ff41' : '#eee', 
          padding: '15px', 
          fontFamily: 'monospace', 
          fontSize: '13px', 
          outline: 'none',
          resize: 'vertical'
        }}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );

  if (showWizard) {
    return <VQLWizard
      tCode={selectedTCode}
      target={wizardTarget}
      onClose={() => setShowWizard(false)}
      onAccept={(output, isYaml) => {
        if (isYaml) {
          setFormData(f => ({ ...f, surgical_yaml: output }));
          setActivePayloadTab('YAML');
        } else {
          setFormData(f => ({ ...f, custom_vql: output }));
          setActivePayloadTab('RAW');
        }
        setShowWizard(false);
      }}
    />;
  }

  const StatusBanner = () => statusMsg ? (
    <div style={{
      padding: '10px 16px', marginBottom: '20px', fontFamily: 'monospace', fontSize: '11px',
      background: statusMsg.type === 'success' ? 'rgba(0,255,65,0.06)' : 'rgba(255,68,68,0.06)',
      border: `1px solid ${statusMsg.type === 'success' ? '#00ff41' : '#ff4444'}`,
      color: statusMsg.type === 'success' ? '#00ff41' : '#ff4444',
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    }}>
      <span>{statusMsg.type === 'success' ? '✓' : '✗'} {statusMsg.text}</span>
      <button onClick={() => setStatusMsg(null)} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '14px' }}>×</button>
    </div>
  ) : null;

  if (step === 1) {
    return (
      <div style={{ animation: 'fadeIn 0.5s ease' }}>
        <h2 style={{ fontSize: '24px', fontWeight: '900', color: '#00ff41', marginBottom: '30px' }}>ARTIFACT_LIBRARY_EDITOR</h2>
        <StatusBanner />
        <div style={{ maxWidth: '600px', border: '1px solid #111', padding: '30px', background: '#080808' }}>
          <div style={{ marginBottom: '25px' }}>
            <label style={{ display: 'block', fontSize: '10px', color: '#444', marginBottom: '10px' }}>INTENT_MODE</label>
            <select 
              style={{ width: '100%', padding: '12px', background: '#000', border: '1px solid #222', color: '#eee', fontFamily: 'monospace' }}
              value={mode} 
              onChange={(e) => setMode(e.target.value)}
            >
              <option value="edit">UPDATE_EXISTING_MAPPING</option>
              <option value="add">INITIALIZE_NEW_MAPPING</option>
            </select>
          </div>
          <div style={{ marginBottom: '30px' }}>
            <label style={{ display: 'block', fontSize: '10px', color: '#444', marginBottom: '10px' }}>TECHNIQUE_SELECTION</label>
            <select 
              style={{ width: '100%', padding: '12px', background: '#000', border: '1px solid #222', color: '#eee', fontFamily: 'monospace' }}
              value={selectedTCode} 
              onChange={(e) => setSelectedTCode(e.target.value)}
            >
              <option value="">-- SELECT_T_CODE --</option>
              {tCodes.map(t => (
                <option key={t.t_code} value={t.t_code}>{t.t_code} | {t.name || t.technique_name}</option>
              ))}
            </select>
          </div>
          <button 
            onClick={handleNextToEdit} 
            disabled={!selectedTCode || loading}
            style={{ width: '100%', padding: '15px', background: 'transparent', border: '1px solid #00ff41', color: '#00ff41', cursor: 'pointer', fontFamily: 'monospace', fontWeight: 'bold' }}
          >
            {loading ? "FETCHING_DATA..." : "ACCESS_LOGIC_CORE"}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ animation: 'fadeIn 0.5s ease', paddingBottom: '100px' }}>
      <StatusBanner />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px', borderBottom: '1px solid #111', paddingBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: '900', color: '#00ff41', margin: 0 }}>LOGIC_CONFIG: {selectedTCode}</h2>
          <div style={{ fontSize: '10px', color: '#444', marginTop: '5px' }}>GLOBAL_LIBRARY_UPLINK_ACTIVE</div>
        </div>
        <div style={{ display: 'flex', gap: '15px' }}>
          <button onClick={() => setStep(1)} style={{ background: 'none', border: '1px solid #222', color: '#555', padding: '8px 20px', cursor: 'pointer', fontFamily: 'monospace' }}>ABORT</button>
          <button onClick={handleSave} style={{ background: '#00ff41', border: 'none', color: '#000', padding: '8px 25px', cursor: 'pointer', fontFamily: 'monospace', fontWeight: 'bold' }}>COMMIT_CHANGES</button>
        </div>
      </div>

      <div style={{ maxWidth: '1000px' }}>
        <TerminalInput label="Live Analysis Logic" value={formData.live_analysis} onChange={(v) => setFormData({...formData, live_analysis: v})} />
        <TerminalInput label="Dead Disk Strategy" value={formData.dead_disk_analysis} onChange={(v) => setFormData({...formData, dead_disk_analysis: v})} />
        <TerminalInput label="Collection Parameters" value={formData.collection_strategy} onChange={(v) => setFormData({...formData, collection_strategy: v})} />
        
        <div style={{ display: 'flex', gap: '2px', marginBottom: '-1px' }}>
          <button 
            onClick={() => setActivePayloadTab('RAW')}
            style={{ 
              padding: '10px 20px', fontSize: '10px', fontFamily: 'monospace', cursor: 'pointer',
              background: activePayloadTab === 'RAW' ? '#020202' : '#000',
              color: activePayloadTab === 'RAW' ? '#00ff41' : '#444',
              border: `1px solid ${activePayloadTab === 'RAW' ? '#003300' : '#111'}`,
              borderBottom: activePayloadTab === 'RAW' ? '1px solid #020202' : '1px solid #111'
            }}
          >
            [SURGICAL_VQL_PAYLOAD_RAW]
          </button>
          <button 
            onClick={() => setActivePayloadTab('YAML')}
            style={{ 
              padding: '10px 20px', fontSize: '10px', fontFamily: 'monospace', cursor: 'pointer',
              background: activePayloadTab === 'YAML' ? '#020202' : '#000',
              color: activePayloadTab === 'YAML' ? '#00ff41' : '#444',
              border: `1px solid ${activePayloadTab === 'YAML' ? '#003300' : '#111'}`,
              borderBottom: activePayloadTab === 'YAML' ? '1px solid #020202' : '1px solid #111'
            }}
          >
            [SURGICAL_VQL_PAYLOAD_YAML]
          </button>
        </div>

        <div style={{ position: 'relative' }}>
          {activePayloadTab === 'RAW' ? (
            <TerminalInput label="VQL_RAW" value={formData.custom_vql} onChange={(v) => setFormData({...formData, custom_vql: v})} isCode={true} />
          ) : (
            <TerminalInput label="VQL_YAML_ARTIFACT" value={formData.surgical_yaml} onChange={(v) => setFormData({...formData, surgical_yaml: v})} isCode={true} />
          )}
          <div style={{ position: 'absolute', top: '10px', right: '10px', display: 'flex', gap: 6, zIndex: 10 }}>
            <button
              onClick={() => { setWizardTarget(activePayloadTab); setShowWizard(true); }}
              style={{ background: '#ffaa00', color: '#000', border: 'none', padding: '5px 15px', fontSize: '10px', fontFamily: 'monospace', fontWeight: 'bold', cursor: 'pointer' }}
            >
              ⚡ WIZARD
            </button>
            <button
              onClick={handleTestVQL}
              disabled={testing}
              style={{ background: '#00ff41', color: '#000', border: 'none', padding: '5px 15px', fontSize: '10px', fontFamily: 'monospace', fontWeight: 'bold', cursor: 'pointer' }}
            >
              {testing ? "RUNNING..." : "TEST_VQL"}
            </button>
          </div>
        </div>

        <div style={{ marginTop: '20px', background: '#050505', border: '1px solid #111', padding: '20px', fontFamily: 'monospace', fontSize: '12px' }}>
          <div style={{ color: '#555', marginBottom: '10px', fontSize: '10px' }}>DEBUG_CONSOLE_FEEDBACK</div>
          <pre style={{ color: '#00ff41', whiteSpace: 'pre-wrap', margin: 0 }}>{consoleOutput || "READY_FOR_VALIDATION..."}</pre>
          
          {testData.length > 0 && (
            <div style={{ marginTop: '20px', maxHeight: '400px', overflow: 'auto', borderTop: '1px solid #111', paddingTop: '10px' }}>
              <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', fontSize: '11px', color: '#888' }}>
                <thead>
                  <tr style={{ color: '#eee' }}>
                    {Object.keys(testData[0]).map(key => <th key={key} style={{ padding: '5px', borderBottom: '1px solid #222' }}>{key}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {testData.map((row, i) => (
                    <tr key={i}>
                      {Object.values(row).map((val, j) => (
                        <td key={j} style={{ padding: '5px', borderBottom: '1px solid #111' }}>
                          {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};


// ── VQL Wizard ─────────────────────────────────────────────────────────────
const VQL_SOURCES = [
  {
    id: 'event_logs', label: 'EVENT LOGS', icon: '📋',
    description: 'Parse Windows EVTX event log files',
    plugin: 'parse_evtx',
    template: (cfg) => {
      const channelMap = {
        Security: 'C:/Windows/System32/winevt/logs/Security.evtx',
        System: 'C:/Windows/System32/winevt/logs/System.evtx',
        Application: 'C:/Windows/System32/winevt/logs/Application.evtx',
        Sysmon: 'C:/Windows/System32/winevt/logs/Microsoft-Windows-Sysmon%4Operational.evtx',
        PowerShell: 'C:/Windows/System32/winevt/logs/Microsoft-Windows-PowerShell%4Operational.evtx',
        TaskScheduler: 'C:/Windows/System32/winevt/logs/Microsoft-Windows-TaskScheduler%4Operational.evtx',
      };
      const path = channelMap[cfg.channel] || channelMap.Security;
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'System.TimeCreated.SystemTime AS EventTime, System.EventID.Value AS EventID, System.Computer AS Computer, EventData';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM parse_evtx(filename=\'' + path + '\')' + where;
    },
    channels: ['Security','System','Application','Sysmon','PowerShell','TaskScheduler'],
    defaultFields: [
      { id: 'ts', label: 'Timestamp', vql: 'System.TimeCreated.SystemTime AS EventTime' },
      { id: 'eid', label: 'EventID', vql: 'System.EventID.Value AS EventID' },
      { id: 'computer', label: 'Computer', vql: 'System.Computer AS Computer' },
      { id: 'user', label: 'UserID', vql: 'System.Security.UserID AS UserID' },
      { id: 'msg', label: 'Message', vql: 'EventData' },
      { id: 'record', label: 'RecordID', vql: 'System.EventRecordID AS RecordID' },
    ],
    filterFields: ['System.EventID.Value', 'System.Computer', 'System.Security.UserID'],
  },
  {
    id: 'registry', label: 'REGISTRY', icon: '🗝️',
    description: 'Query Windows registry keys and values',
    plugin: 'reg_values',
    template: (cfg) => {
      const path = cfg.regPath || 'HKEY_LOCAL_MACHINE/SOFTWARE/**';
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'Key, Name, Data, Type, Mtime';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM reg_values(globs=\'' + path + '\')' + where;
    },
    regPaths: [
      'HKEY_LOCAL_MACHINE/SOFTWARE/**',
      'HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Services/**',
      'HKEY_USERS/*/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/**',
      'HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run/**',
    ],
    defaultFields: [
      { id: 'key', label: 'Key Path', vql: 'Key' },
      { id: 'name', label: 'Value Name', vql: 'Name' },
      { id: 'data', label: 'Data', vql: 'Data' },
      { id: 'type', label: 'Type', vql: 'Type' },
      { id: 'mtime', label: 'Modified', vql: 'Mtime' },
    ],
    filterFields: ['Name', 'Type', 'Key'],
  },
  {
    id: 'filesystem', label: 'FILE SYSTEM', icon: '📁',
    description: 'Search filesystem using glob patterns',
    plugin: 'glob',
    template: (cfg) => {
      const pattern = cfg.globPattern || 'C:/Windows/System32/**/*.exe';
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'FullPath, Size, Mtime, Atime, Ctime, IsDir';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM glob(globs=\'' + pattern + '\')' + where;
    },
    commonPaths: [
      'C:/Windows/System32/**/*.exe',
      'C:/Windows/Temp/**',
      'C:/Users/*/AppData/Roaming/**',
      'C:/Users/*/Desktop/**',
      'C:/$Recycle.Bin/**',
    ],
    defaultFields: [
      { id: 'path', label: 'Full Path', vql: 'FullPath' },
      { id: 'size', label: 'Size', vql: 'Size' },
      { id: 'mtime', label: 'Modified', vql: 'Mtime' },
      { id: 'atime', label: 'Accessed', vql: 'Atime' },
      { id: 'ctime', label: 'Created', vql: 'Ctime' },
      { id: 'isdir', label: 'Is Dir', vql: 'IsDir' },
    ],
    filterFields: ['FullPath', 'Size', 'IsDir', 'Mtime'],
  },
  {
    id: 'prefetch', label: 'PREFETCH', icon: '⚡',
    description: 'Parse Windows Prefetch execution artifacts',
    plugin: 'prefetch',
    template: (cfg) => {
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT Executable, Path, LastRunTimes, RunCount, FilesAccessed, FullPath' +
        '\nFROM foreach(' +
        "\n  row={SELECT FullPath FROM glob(globs='C:/Windows/Prefetch/*.pf')}," +
        '\n  query={SELECT Executable, Path, LastRunTimes, RunCount, FilesAccessed, FullPath' +
        '\n         FROM prefetch(filename=FullPath)}' +
        '\n)' + where;
    },
    defaultFields: [
      { id: 'exe', label: 'Executable', vql: 'Executable' },
      { id: 'path', label: 'Path', vql: 'Path' },
      { id: 'times', label: 'Last Run Times', vql: 'LastRunTimes' },
      { id: 'count', label: 'Run Count', vql: 'RunCount' },
    ],
    filterFields: ['Executable', 'RunCount', 'Path'],
  },
  {
    id: 'processes', label: 'PROCESSES', icon: '⚙️',
    description: 'Enumerate running processes',
    plugin: 'pslist',
    template: (cfg) => {
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'Pid, Ppid, Name, Exe, CommandLine, Username, CreateTime';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM pslist()' + where;
    },
    defaultFields: [
      { id: 'pid', label: 'PID', vql: 'Pid' },
      { id: 'ppid', label: 'PPID', vql: 'Ppid' },
      { id: 'name', label: 'Name', vql: 'Name' },
      { id: 'exe', label: 'Executable', vql: 'Exe' },
      { id: 'cmd', label: 'Command Line', vql: 'CommandLine' },
      { id: 'user', label: 'Username', vql: 'Username' },
      { id: 'time', label: 'Create Time', vql: 'CreateTime' },
    ],
    filterFields: ['Name', 'Pid', 'Username', 'CommandLine'],
  },
  {
    id: 'network', label: 'NETWORK', icon: '🌐',
    description: 'Collect network connections',
    plugin: 'netstat',
    template: (cfg) => {
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'Pid, FamilyString, TypeString, Status, Laddr.IP, Laddr.Port, Raddr.IP, Raddr.Port';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM netstat()' + where;
    },
    defaultFields: [
      { id: 'pid', label: 'PID', vql: 'Pid' },
      { id: 'status', label: 'Status', vql: 'Status' },
      { id: 'laddr', label: 'Local Address', vql: 'Laddr.IP' },
      { id: 'lport', label: 'Local Port', vql: 'Laddr.Port' },
      { id: 'raddr', label: 'Remote Address', vql: 'Raddr.IP' },
      { id: 'rport', label: 'Remote Port', vql: 'Raddr.Port' },
    ],
    filterFields: ['Status', 'FamilyString', 'Raddr.IP', 'Raddr.Port', 'Pid'],
  },
  {
    id: 'wmi', label: 'WMI', icon: '🔌',
    description: 'Query Windows Management Instrumentation',
    plugin: 'wmi',
    template: (cfg) => {
      const query = cfg.wmiQuery || 'SELECT * FROM Win32_Process';
      const ns = cfg.wmiNamespace || 'root/cimv2';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return "SELECT *\nFROM wmi(query='" + query + "', namespace='" + ns + "')" + where;
    },
    wmiQueries: [
      'SELECT * FROM Win32_Process',
      'SELECT * FROM Win32_Service WHERE State = "Running"',
      'SELECT * FROM Win32_StartupCommand',
      'SELECT * FROM Win32_UserAccount',
    ],
    defaultFields: [],
    filterFields: [],
  },
  {
    id: 'mft', label: 'MFT', icon: '🗃️',
    description: 'Parse the NTFS Master File Table',
    plugin: 'Artifact.Windows.NTFS.MFT',
    template: (cfg) => {
      const fields = cfg.fields.length ? cfg.fields.join(', ') : 'OSPath, FileName, FileSize, IsDir, InUse, Created0x10, LastModified0x10, SI_Lt_FN, HasADS';
      const where = cfg.filters.length ? '\nWHERE ' + cfg.filters.map(f => f.expr).join('\n  AND ') : '';
      return 'SELECT ' + fields + '\nFROM Artifact.Windows.NTFS.MFT()' + where;
    },
    defaultFields: [
      { id: 'path', label: 'Full Path', vql: 'OSPath' },
      { id: 'name', label: 'File Name', vql: 'FileName' },
      { id: 'size', label: 'File Size', vql: 'FileSize' },
      { id: 'inuse', label: 'In Use', vql: 'InUse' },
      { id: 'created', label: 'Created', vql: 'Created0x10' },
      { id: 'timestomp', label: 'Timestomp Flag', vql: 'SI_Lt_FN' },
      { id: 'ads', label: 'Has ADS', vql: 'HasADS' },
    ],
    filterFields: ['FileName', 'OSPath', 'IsDir', 'InUse', 'SI_Lt_FN', 'HasADS', 'FileSize'],
  },
];

const FILTER_OPERATORS = [
  { op: '=~', label: 'matches regex' },
  { op: '=', label: 'equals' },
  { op: '!=', label: 'not equals' },
  { op: '>', label: 'greater than' },
  { op: '<', label: 'less than' },
];

const WLabel = { fontSize: 10, color: '#555', letterSpacing: 1, fontWeight: 'bold', display: 'block', marginBottom: 8 };
const WInput = { width: '100%', background: '#050505', border: '1px solid #222', color: '#eee', padding: '10px', fontFamily: 'monospace', fontSize: 12, outline: 'none', boxSizing: 'border-box' };
const WBtn = { padding: '8px 20px', fontFamily: 'monospace', fontSize: 11, fontWeight: 'bold', cursor: 'pointer', border: 'none' };

function VQLWizard({ onClose, onAccept, tCode, target }) {
  const [wStep, setWStep] = React.useState(1);
  const [source, setSource] = React.useState(null);
  const [config, setConfig] = React.useState({
    channel: 'Security', regPath: '', globPattern: '', wmiQuery: '', wmiNamespace: 'root/cimv2',
    fields: [], filters: [],
  });
  const [filterField, setFilterField] = React.useState('');
  const [filterOp, setFilterOp] = React.useState('=~');
  const [filterVal, setFilterVal] = React.useState('');
  const [generatedVQL, setGeneratedVQL] = React.useState('');

  const toggleField = (vql) => setConfig(c => ({
    ...c, fields: c.fields.includes(vql) ? c.fields.filter(f => f !== vql) : [...c.fields, vql]
  }));

  const addFilter = () => {
    if (!filterField || filterField === '--') return;
    const expr = filterField + ' ' + filterOp + ' ' + filterVal;
    setConfig(c => ({ ...c, filters: [...c.filters, { id: Date.now(), expr }] }));
    setFilterField(''); setFilterVal('');
  };

  const removeFilter = (id) => setConfig(c => ({ ...c, filters: c.filters.filter(f => f.id !== id) }));

  const goToPreview = () => {
    if (!source) return;
    setGeneratedVQL(source.template(config));
    setWStep(4);
  };

  const handleAccept = () => {
    if (target === 'YAML') {
      const indent = generatedVQL.split('\n').map(l => '      ' + l).join('\n');
      const safeName = (tCode || 'Artifact').replace(/[^a-zA-Z0-9]/g, '_');
      const yaml = 'name: Custom.' + safeName + '\n' +
        'description: |\n' +
        '  Custom detection for ' + (tCode || 'artifact') + ' - generated by VQL Wizard.\n' +
        'sources:\n' +
        '  - name: Detection\n' +
        '    description: Primary detection query\n' +
        '    query: |\n' +
        indent;
      onAccept(yaml, true);
    } else {
      onAccept(generatedVQL, false);
    }
  };

  const stepLabels = ['SOURCE', 'FIELDS', 'FILTERS', 'PREVIEW'];

  return (
    <div style={{ background: '#000', color: '#eee', fontFamily: 'monospace', paddingBottom: 80 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 30, borderBottom: '1px solid #111', paddingBottom: 20 }}>
        <div>
          <h2 style={{ color: '#ffaa00', margin: 0, fontSize: 22, fontWeight: 900 }}>VQL_WIZARD</h2>
          <div style={{ color: '#444', fontSize: 10, marginTop: 4 }}>
            {'BUILD ' + (target === 'YAML' ? 'YAML ARTIFACT' : 'VQL QUERY') + ' FOR ' + (tCode || 'SELECTED TCODE')}
          </div>
        </div>
        <button onClick={onClose} style={{ ...WBtn, background: 'none', border: '1px solid #222', color: '#555' }}>CANCEL</button>
      </div>

      <div style={{ display: 'flex', gap: 2, marginBottom: 30 }}>
        {stepLabels.map((s, i) => (
          <div key={s} style={{
            flex: 1, padding: '8px 0', textAlign: 'center', fontSize: 10,
            background: wStep === i+1 ? '#ffaa00' : wStep > i+1 ? '#1a1200' : '#0a0a0a',
            color: wStep === i+1 ? '#000' : wStep > i+1 ? '#ffaa00' : '#333',
            border: '1px solid ' + (wStep >= i+1 ? '#ffaa00' : '#111'),
            fontWeight: wStep === i+1 ? 'bold' : 'normal',
          }}>
            {i+1}. {s}
          </div>
        ))}
      </div>

      {wStep === 1 && (
        <div>
          <label style={WLabel}>SELECT DATA SOURCE</label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 10, marginBottom: 24 }}>
            {VQL_SOURCES.map(src => (
              <div key={src.id} onClick={() => { setSource(src); setConfig(c => ({ ...c, fields: src.defaultFields.slice(0,4).map(f=>f.vql) })); }}
                style={{ padding: 14, border: '1px solid ' + (source && source.id === src.id ? '#ffaa00' : '#1a1a1a'),
                  background: source && source.id === src.id ? 'rgba(255,170,0,0.05)' : '#050505', cursor: 'pointer' }}>
                <div style={{ fontSize: 18, marginBottom: 4 }}>{src.icon}</div>
                <div style={{ color: source && source.id === src.id ? '#ffaa00' : '#aaa', fontWeight: 'bold', fontSize: 11, marginBottom: 4 }}>{src.label}</div>
                <div style={{ color: '#444', fontSize: 9 }}>{src.description}</div>
              </div>
            ))}
          </div>

          {source && source.id === 'event_logs' && (
            <div style={{ marginBottom: 20 }}>
              <label style={WLabel}>CHANNEL</label>
              <select value={config.channel} onChange={e => setConfig(c => ({ ...c, channel: e.target.value }))} style={{ ...WInput, marginBottom: 0 }}>
                {source.channels.map(ch => <option key={ch} value={ch}>{ch}</option>)}
              </select>
            </div>
          )}
          {source && source.id === 'registry' && (
            <div style={{ marginBottom: 20 }}>
              <label style={WLabel}>REGISTRY PATH</label>
              <select onChange={e => setConfig(c => ({ ...c, regPath: e.target.value }))} style={{ ...WInput, marginBottom: 8 }}>
                <option value="">-- common paths --</option>
                {source.regPaths.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <input value={config.regPath} onChange={e => setConfig(c => ({ ...c, regPath: e.target.value }))} placeholder="or type custom path..." style={{ ...WInput }} />
            </div>
          )}
          {source && source.id === 'filesystem' && (
            <div style={{ marginBottom: 20 }}>
              <label style={WLabel}>GLOB PATTERN</label>
              <select onChange={e => setConfig(c => ({ ...c, globPattern: e.target.value }))} style={{ ...WInput, marginBottom: 8 }}>
                <option value="">-- common patterns --</option>
                {source.commonPaths.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <input value={config.globPattern} onChange={e => setConfig(c => ({ ...c, globPattern: e.target.value }))} placeholder="or type custom glob..." style={{ ...WInput }} />
            </div>
          )}
          {source && source.id === 'wmi' && (
            <div style={{ marginBottom: 20 }}>
              <label style={WLabel}>WMI QUERY</label>
              <select onChange={e => setConfig(c => ({ ...c, wmiQuery: e.target.value }))} style={{ ...WInput, marginBottom: 8 }}>
                <option value="">-- common queries --</option>
                {source.wmiQueries.map(q => <option key={q} value={q}>{q}</option>)}
              </select>
              <input value={config.wmiQuery} onChange={e => setConfig(c => ({ ...c, wmiQuery: e.target.value }))} placeholder="or type custom query..." style={{ ...WInput, marginBottom: 8 }} />
              <input value={config.wmiNamespace} onChange={e => setConfig(c => ({ ...c, wmiNamespace: e.target.value }))} placeholder="Namespace: root/cimv2" style={{ ...WInput }} />
            </div>
          )}

          <button disabled={!source} onClick={() => setWStep(2)}
            style={{ ...WBtn, background: source ? '#ffaa00' : '#1a1200', color: source ? '#000' : '#555' }}>
            NEXT: FIELDS
          </button>
        </div>
      )}

      {wStep === 2 && source && (
        <div>
          <label style={WLabel}>SELECT FIELDS</label>
          {source.defaultFields.length > 0 ? (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 24 }}>
              {source.defaultFields.map(f => {
                const active = config.fields.includes(f.vql);
                return (
                  <div key={f.id} onClick={() => toggleField(f.vql)} style={{
                    padding: '8px 14px', border: '1px solid ' + (active ? '#ffaa00' : '#222'),
                    background: active ? 'rgba(255,170,0,0.08)' : '#050505', cursor: 'pointer', fontSize: 11,
                    color: active ? '#ffaa00' : '#555',
                  }}>
                    {active ? '✓' : '○'} {f.label}
                    <div style={{ fontSize: 9, color: '#333', marginTop: 2 }}>{f.vql}</div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ color: '#555', fontSize: 11, marginBottom: 20 }}>SELECT * — all fields returned</div>
          )}
          <div style={{ display: 'flex', gap: 10 }}>
            <button onClick={() => setWStep(1)} style={{ ...WBtn, background: 'none', border: '1px solid #333', color: '#555' }}>BACK</button>
            <button onClick={() => setWStep(3)} style={{ ...WBtn, background: '#ffaa00', color: '#000' }}>NEXT: FILTERS</button>
          </div>
        </div>
      )}

      {wStep === 3 && source && (
        <div>
          <label style={WLabel}>ADD WHERE FILTERS (optional)</label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: 2 }}>
              <label style={{ ...WLabel, marginBottom: 4 }}>FIELD</label>
              <select value={filterField} onChange={e => setFilterField(e.target.value)} style={{ ...WInput }}>
                <option value="">-- field --</option>
                {(source.filterFields || []).map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ ...WLabel, marginBottom: 4 }}>OP</label>
              <select value={filterOp} onChange={e => setFilterOp(e.target.value)} style={{ ...WInput }}>
                {FILTER_OPERATORS.map(op => <option key={op.op} value={op.op}>{op.op} {op.label}</option>)}
              </select>
            </div>
            <div style={{ flex: 2 }}>
              <label style={{ ...WLabel, marginBottom: 4 }}>VALUE</label>
              <input value={filterVal} onChange={e => setFilterVal(e.target.value)} placeholder="value" style={{ ...WInput }} />
            </div>
            <button onClick={addFilter} style={{ ...WBtn, background: '#ffaa00', color: '#000' }}>+ ADD</button>
          </div>
          {config.filters.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              {config.filters.map(f => (
                <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 12px',
                  background: '#050505', border: '1px solid #1a1a1a', marginBottom: 6, fontSize: 11 }}>
                  <span style={{ color: '#ffaa00' }}>{f.expr}</span>
                  <button onClick={() => removeFilter(f.id)} style={{ background: 'none', border: 'none', color: '#ff4141', cursor: 'pointer' }}>x</button>
                </div>
              ))}
            </div>
          )}
          <div style={{ display: 'flex', gap: 10 }}>
            <button onClick={() => setWStep(2)} style={{ ...WBtn, background: 'none', border: '1px solid #333', color: '#555' }}>BACK</button>
            <button onClick={goToPreview} style={{ ...WBtn, background: '#ffaa00', color: '#000' }}>PREVIEW VQL</button>
          </div>
        </div>
      )}

      {wStep === 4 && (
        <div>
          <label style={WLabel}>GENERATED {target === 'YAML' ? 'YAML ARTIFACT' : 'VQL'} — EDIT IF NEEDED</label>
          <textarea value={generatedVQL} onChange={e => setGeneratedVQL(e.target.value)}
            style={{ width: '100%', height: 220, background: '#020202', border: '1px solid #003300',
              color: '#00ff41', padding: 15, fontFamily: 'monospace', fontSize: 13, outline: 'none',
              resize: 'vertical', boxSizing: 'border-box', marginBottom: 20 }} />
          <div style={{ background: '#050505', border: '1px solid #1a1a1a', padding: 14, marginBottom: 20, fontSize: 10, color: '#555' }}>
            <div style={{ color: '#ffaa00', marginBottom: 6 }}>REVIEW BEFORE ACCEPTING</div>
            <div>- Plugin name is correct for your Velociraptor version</div>
            <div>- Field names match plugin output</div>
            <div>- String values use single quotes</div>
            <div>- Regex uses =~ operator</div>
            <div>- Test with TEST_VQL after accepting</div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <button onClick={() => setWStep(3)} style={{ ...WBtn, background: 'none', border: '1px solid #333', color: '#555' }}>BACK</button>
            <button onClick={handleAccept} style={{ ...WBtn, background: '#00ff41', color: '#000', fontSize: 13 }}>
              ACCEPT — DROP INTO {target === 'YAML' ? 'YAML' : 'VQL'} EDITOR
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default ArtifactLibraryEditor;