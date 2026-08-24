import React, { useState, useEffect, useRef, useMemo } from 'react';
import BehavioralAnalysisTab from '../BehavioralAnalysisTab';
import { useAuth } from '../../context/AuthContext';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';

// ── Palette ────────────────────────────────────────────────────────────────
const C = {
  green:    '#00ff41', greenDim: '#00cc33',
  red:      '#ff4444', amber: '#ffaa00', purple: '#9b59ff',
  white:    '#f0f0f0', grey: '#aaaaaa', greyDim: '#777777',
  border:   '#2a2a2a', borderBright: '#3a3a3a',
  bg:       '#000000', bgCard: '#0d0d0d', bgHover: '#141414', bgHeader: '#111111',
};

const MITRE_NAMES = {
  "T1003":"OS Credential Dumping","T1003.001":"LSASS Memory","T1003.002":"SAM",
  "T1003.004":"LSA Secrets","T1003.005":"Cached Domain Credentials","T1005":"Data from Local System",
  "T1007":"System Service Discovery","T1012":"Query Registry","T1014":"Rootkit",
  "T1016":"System Network Configuration Discovery","T1021":"Remote Services",
  "T1027":"Obfuscated Files","T1027.007":"Dynamic API Resolution",
  "T1036":"Masquerading","T1036.005":"Match Legitimate Name or Location",
  "T1049":"System Network Connections Discovery","T1053.005":"Scheduled Task",
  "T1055":"Process Injection","T1055.001":"DLL Injection","T1055.002":"PE Injection",
  "T1055.003":"Thread Execution Hijacking","T1055.012":"Process Hollowing",
  "T1055.015":"Process Ghosting","T1056.001":"Keylogging","T1057":"Process Discovery",
  "T1059":"Command and Scripting Interpreter","T1059.001":"PowerShell",
  "T1059.003":"Windows Command Shell","T1059.004":"Unix Shell",
  "T1068":"Exploitation for Privilege Escalation","T1069":"Permission Groups Discovery",
  "T1070":"Indicator Removal","T1070.004":"File Deletion","T1071":"Application Layer Protocol",
  "T1078":"Valid Accounts","T1082":"System Information Discovery",
  "T1083":"File and Directory Discovery","T1105":"Ingress Tool Transfer",
  "T1106":"Native API","T1112":"Modify Registry","T1129":"Shared Modules",
  "T1134":"Access Token Manipulation","T1140":"Deobfuscate/Decode Files",
  "T1218":"System Binary Proxy Execution","T1486":"Data Encrypted for Impact",
  "T1518":"Software Discovery","T1542.003":"Pre-OS Boot: Bootkit",
  "T1543.003":"Windows Service","T1546.011":"Application Shimming",
  "T1547.001":"Registry Run Keys / Startup Folder","T1553":"Subvert Trust Controls",
  "T1553.004":"Install Root Certificate","T1556.001":"Modify Authentication Process",
  "T1562.001":"Disable or Modify Tools","T1562.006":"Indicator Blocking",
  "T1563":"Remote Service Session Hijacking","T1564.001":"Hidden Files and Directories",
  "T1564.004":"NTFS File Attributes","T1574":"Hijack Execution Flow",
  "T1574.001":"DLL Search Order Hijacking","T1574.006":"Dynamic Linker Hijacking",
  "T1620":"Reflective Code Loading","T1622":"Debugger Evasion",
};

const THREAT_ACTORS = [
  "APT1 (Comment Crew / Unit 61398)",
  "APT28 (Fancy Bear / Sofacy / Pawn Storm)",
  "APT29 (Cozy Bear / The Dukes)",
  "APT32 (OceanLotus / Cobalt Kitty)",
  "APT38 / Lazarus Group (Hidden Cobra)",
  "APT41 (Winnti / BARIUM / Double Dragon)",
  "BlackCat / ALPHV","Carbanak / FIN7 / Navigator Group",
  "Cl0p Ransomware","Conti Ransomware","DarkHotel (Tapaoux)",
  "Equation Group (NSA / GCHQ-linked)","Gamaredon (Primitive Bear)",
  "Hive Ransomware","Kimsuky (Thallium / Black Banshee)","LockBit Ransomware",
  "MuddyWater (Static Kitten)","NotPetya / Sandworm (GRU Unit 74455)",
  "REvil / Sodinokibi","Ryuk Ransomware","ShadowPad (APT41-linked)",
  "TA505 (Evil Corp-linked)","Turla (Venomous Bear / Waterbug)",
  "WannaCry (Lazarus Group)","Winnti Group (APT41 overlap)",
  "Wizard Spider (Ryuk / TrickBot)",
];

const VOL_PLUGINS = {
  windows: {
    "Process Analysis":  ["windows.pslist","windows.psscan","windows.pstree","windows.malware.psxview","windows.cmdline","windows.cmdscan","windows.consoles","windows.envars","windows.handles","windows.sessions","windows.getsids","windows.getservicesids","windows.privileges","windows.joblinks","windows.kpcrs"],
    "Code Injection":    ["windows.malware.malfind","windows.malware.hollowprocesses","windows.malware.processghosting","windows.vadinfo","windows.vadwalk","windows.vadyarascan","windows.vadregexscan","windows.dlllist","windows.malware.ldrmodules","windows.memmap","windows.pedump","windows.threads","windows.thrdscan","windows.suspended_threads","windows.malware.pebmasquerade","windows.malware.suspicious_threads","windows.orphan_kernel_threads","windows.pe_symbols","windows.virtmap"],
    "Credentials":       ["windows.registry.hashdump","windows.registry.cachedump","windows.registry.lsadump","windows.malware.skeleton_key_check","windows.truecrypt"],
    "Registry":          ["windows.registry.hivelist","windows.registry.hivescan","windows.registry.printkey","windows.registry.userassist","windows.registry.certificates","windows.registry.getcellroutine","windows.registry.amcache","windows.shimcachemem"],
    "Network":           ["windows.netscan","windows.netstat","windows.mutantscan"],
    "Rootkit/Evasion":   ["windows.ssdt","windows.callbacks","windows.modules","windows.modscan","windows.driverscan","windows.driverirp","windows.malware.drivermodule","windows.unloadedmodules","windows.etwpatch","windows.malware.unhooked_system_calls","windows.malware.direct_system_calls","windows.malware.indirect_system_calls","windows.mbrscan","windows.bigpools","windows.timers","windows.devicetree","windows.poolscanner"],
    "DLL/Module":        ["windows.dlllist","windows.malware.ldrmodules","windows.iat","windows.pe_symbols"],
    "Files/MFT":         ["windows.filescan","windows.mftscan","windows.dumpfiles","windows.symlinkscan","windows.strings","windows.verinfo"],
    "Persistence":       ["windows.svcscan","windows.malware.svcdiff","windows.registry.scheduled_tasks","windows.windows","windows.windowstations","windows.statistics"],
    "System Info":       ["windows.info","windows.psxview"],
  },
  linux: {
    "Process Analysis":  ["linux.pslist","linux.psscan","linux.pstree","linux.cmdline","linux.bash","linux.envars","linux.proc","linux.pidhashtable","linux.pscallstack"],
    "Code Injection":    ["linux.malfind","linux.proc_maps","linux.memmap","linux.vadinfo","linux.vmaregexscan","linux.vmayarascan","linux.ptrace","linux.suspicious_threads","linux.orphan_kernel_threads"],
    "Network":           ["linux.sockstat","linux.sockscan","linux.netfilter","linux.ifconfig","linux.ip","linux.lsof"],
    "Rootkit/Evasion":   ["linux.check_afinfo","linux.check_modules","linux.check_syscall","linux.check_sysctl","linux.ebpf","linux.ftrace","linux.hidden_modules","linux.lsmod","linux.kthreads","linux.tracepoints","linux.tty_check","linux.keyboard_notifiers"],
    "Files":             ["linux.filescan","linux.lsof","linux.symlinkscan","linux.mountinfo","linux.mount","linux.list_files","linux.pagecache","linux.regexscan"],
    "Credentials":       ["linux.tty_check","linux.keyboard_notifiers","linux.capabilities"],
    "System Info":       ["linux.dmesg","linux.vmcoreinfo","linux.kallsyms","linux.kmsg","linux.boottime","linux.iomem","linux.yarascan","linux.strings"],
  },
  mac: {
    "Process Analysis":  ["mac.pslist","mac.psscan","mac.pstree","mac.cmdline","mac.bash","mac.envars"],
    "Code Injection":    ["mac.malfind","mac.proc_maps","mac.memmap","mac.vadinfo"],
    "Network":           ["mac.sockstat","mac.sockscan","mac.lsof","mac.ifconfig","mac.ip"],
    "Rootkit/Evasion":   ["mac.check_syscall","mac.hidden_modules","mac.kauth_listeners","mac.kauth_scopes","mac.socket_filters","mac.trustedbsd"],
    "Files":             ["mac.filescan","mac.lsof","mac.symlinkscan","mac.mountinfo","mac.pagecache"],
    "System Info":       ["mac.dmesg","mac.yarascan","mac.strings"],
  },
};

const TRIAGE_TREE = [
  { id: 'EVENT_LOGS', label: 'EVENT LOGS', children: [
    { id: 'EVENT_LOGS_SECURITY',      label: 'Security' },
    { id: 'EVENT_LOGS_APPLICATION',   label: 'Application' },
    { id: 'EVENT_LOGS_SYSMON',        label: 'Sysmon' },
    { id: 'EVENT_LOGS_POWERSHELL',    label: 'PowerShell' },
    { id: 'EVENT_LOGS_SYSTEM',        label: 'System' },
    { id: 'EVENT_LOGS_TASKSCHEDULER', label: 'Task Scheduler' },
    { id: 'EVENT_LOGS_WMI',           label: 'WMI Activity' },
    { id: 'EVENT_LOGS_WINRM',         label: 'WinRM' },
  ]},
  { id: 'PREFETCH',        label: 'PREFETCH',          children: [] },
  { id: 'MFT',             label: 'MFT',               children: [] },
  { id: 'REGISTRY', label: 'REGISTRY', children: [] },
  { id: 'BROWSER', label: 'BROWSER ARTIFACTS', children: [
    { id: 'BROWSER_CHROME',  label: 'Chrome' },
    { id: 'BROWSER_EDGE',    label: 'Edge' },
    { id: 'BROWSER_FIREFOX', label: 'Firefox' },
  ]},
  { id: 'LNK_JUMPLISTS',   label: 'LNK / JUMP LISTS',  children: [] },
  { id: 'SCHEDULED_TASKS', label: 'SCHEDULED TASKS',   children: [] },
  { id: 'WMI_PERSISTENCE', label: 'WMI PERSISTENCE',   children: [] },
  { id: 'SRUM',            label: 'SRUM',              children: [] },
  { id: 'AMCACHE',         label: 'AMCACHE',           children: [] },
  { id: 'RECYCLE_BIN',     label: 'RECYCLE BIN',       children: [] },
  { id: 'USB_ARTIFACTS',   label: 'USB ARTIFACTS',     children: [] },
];

const CONF_COLOR = { H: C.red, M: C.amber, L: C.green };
const getAuth = () => ({ 'Content-Type': 'application/json' });
const ts = () => new Date().toLocaleTimeString([], { hour12: false });

// ── Shared micro-styles ────────────────────────────────────────────────────
const Inp = { background: C.bg, border: `1px solid ${C.border}`, color: C.white, padding: '5px 8px', fontSize: 11, fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box' };
const Btn = { padding: '6px 14px', background: C.green, color: '#000', border: 'none', cursor: 'pointer', fontWeight: 'bold', fontSize: 11, fontFamily: 'monospace', whiteSpace: 'nowrap', flexShrink: 0 };
const Lbl = { color: C.greyDim, fontSize: 10, minWidth: 115, flexShrink: 0, fontFamily: 'monospace', paddingTop: 3 };
const CtxItem = { padding: '8px 14px', fontSize: 11, color: C.green, cursor: 'pointer', borderBottom: `1px solid #1a1a1a`, fontFamily: 'monospace' };

// ── Reusable ───────────────────────────────────────────────────────────────
const Card = ({ title, children, style }) => (
  <div style={{ border: `1px solid ${C.border}`, background: C.bgCard, ...style }}>
    <div style={{ padding: '5px 12px', background: C.bgHeader, borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.greyDim, fontWeight: 'bold', letterSpacing: 1 }}>{title}</div>
    {children}
  </div>
);

const LogCol = ({ logs, width = 270 }) => (
  <div style={{ width, borderLeft: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
    <div style={{ padding: '5px 10px', background: C.bgHeader, borderBottom: `1px solid ${C.border}`, fontSize: 9, color: C.greyDim, letterSpacing: 1 }}>EXECUTION_LOG</div>
    <div style={{ flex: 1, overflowY: 'auto', padding: 4 }}>
      {logs.map((l, i) => (
        <div key={i} style={{ padding: '2px 5px', fontSize: 10, fontFamily: 'monospace', borderBottom: `1px solid #080808`,
          color: l.type === 'error' ? C.red : l.type === 'success' ? C.green : C.greyDim }}>
          <span style={{ opacity: 0.5, marginRight: 5 }}>[{l.t}]</span>{l.m}
        </div>
      ))}
    </div>
  </div>
);

// ── Collection status bar (top of window) ─────────────────────────────────
const CollectionStatusBar = ({ tacticList }) => {
  if (!tacticList || tacticList.length === 0) return null;
  const total      = tacticList.length;
  const withEvidence = tacticList.filter(t => t.evidence_imported).length;
  const noArtifacts  = tacticList.filter(t => (t.verdict || '').toUpperCase() === 'NO_ARTIFACTS').length;
  const pending      = total - withEvidence - noArtifacts;
  const pct          = Math.round(((withEvidence + noArtifacts) / total) * 100);
  if (pending === 0) return null; // collection complete — hide bar
  return (
    <div style={{ background: '#050f05', borderBottom: `1px solid ${C.green}`, padding: '5px 20px', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 16 }}>
      <span style={{ color: C.green, fontSize: 10, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>
        COLLECTING — {withEvidence + noArtifacts}/{total} COMPLETE
      </span>
      <div style={{ flex: 1, background: '#111', height: 4, overflow: 'hidden' }}>
        <div style={{ height: '100%', background: C.green, width: `${pct}%`, transition: 'width 0.8s ease' }} />
      </div>
      <span style={{ color: C.greyDim, fontSize: 10, whiteSpace: 'nowrap' }}>
        {withEvidence > 0 && <span style={{ color: C.green }}>{withEvidence} HIT </span>}
        {noArtifacts > 0 && <span style={{ color: C.greyDim }}>{noArtifacts} EMPTY </span>}
        <span style={{ color: '#ffaa00' }}>{pending} PENDING</span>
      </span>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// OVERVIEW TAB  — replace the entire OverviewTab component in EvidenceWindow.jsx
// Lines 139-259 in the original file
// ══════════════════════════════════════════════════════════════════════════════
const OverviewTab = ({ tacticList, memSummary, avSummary, vulnSummary, behavioralSummary, capaIdentifiedTechniques = new Set(), isNetworkDevice, netConfigText, netConfigFile, netConfigSaving, onConfigLoad }) => {
  const configFileRef = React.useRef(null);
  const handleConfigFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => onConfigLoad(ev.target.result || '', file.name);
    reader.readAsText(file);
  };
  const [techExpanded, setTechExpanded] = useState(false);

  const total        = tacticList?.length || 0;
  const withEvidence = tacticList?.filter(t => t.evidence_imported)?.length || 0;
  const noArtifacts  = tacticList?.filter(t => (t.verdict || '').toUpperCase() === 'NO_ARTIFACTS')?.length || 0;
  const pending      = total - withEvidence - noArtifacts;
  const pct          = total > 0 ? Math.round((withEvidence / total) * 100) : 0;

  // VERDICT COUNTS
  // UNDETERMINED = anything that is NOT explicitly MALICIOUS or NON-MALICIOUS
  // (covers null, undefined, 'UNDETERMINED', empty string, or any other value)
  const malicious    = (tacticList || []).filter(t => (t.verdict || '').toUpperCase() === 'MALICIOUS').length;
  const nonMalicious = (tacticList || []).filter(t => (t.verdict || '').toUpperCase() === 'NON-MALICIOUS').length;
  const undetermined = total - malicious - nonMalicious;

  const vCounts = [
    ['UNDETERMINED', undetermined, C.greyDim],
    ['MALICIOUS',    malicious,    C.red],
    ['NON-MALICIOUS',nonMalicious, C.green],
  ];

  const vCol = { MALICIOUS: C.red, 'NON-MALICIOUS': C.green, UNDETERMINED: C.greyDim };

  return (
    <div style={{ padding: 18, overflowY: 'auto', height: '100%', display: 'flex', flexDirection: 'column', gap: 14, boxSizing: 'border-box' }}>

      {isNetworkDevice && (
        <Card title="DEVICE_CONFIG">
          <input ref={configFileRef} type="file"
            accept=".txt,.cfg,.conf,.log,.ios,.xml,.json,.yaml,.yml"
            onChange={handleConfigFile} style={{ display: 'none' }} />
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: netConfigText ? 8 : 0 }}>
            <button onClick={() => configFileRef.current?.click()} style={{
              background: netConfigText ? 'transparent' : C.green, color: netConfigText ? C.green : '#000',
              border: `1px solid ${C.green}`, padding: '4px 14px', fontSize: 10,
              fontFamily: 'monospace', fontWeight: 'bold', cursor: 'pointer'
            }}>
              {netConfigText ? '↺ REPLACE CONFIG' : '⬆ UPLOAD DEVICE CONFIG'}
            </button>
            {netConfigFile && <span style={{ color: C.greyDim, fontSize: 10 }}>{netConfigFile}</span>}
            {netConfigSaving && <span style={{ color: C.amber, fontSize: 10 }}>SAVING…</span>}
          </div>
          {netConfigText && (
            <div style={{ color: C.greyDim, fontSize: 10 }}>
              {netConfigText.split('\n').length} lines loaded — visible in all technique evidence panels
            </div>
          )}
        </Card>
      )}

      {/* Collection progress */}
      <Card title="ARTIFACT_COLLECTION_PROGRESS">
        <div style={{ padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ color: C.white, fontSize: 12 }}>
              <span style={{ color: C.green, fontWeight: 'bold' }}>{withEvidence}</span> hits &nbsp;·&nbsp;
              <span style={{ color: C.greyDim, fontWeight: 'bold' }}>{noArtifacts}</span> empty &nbsp;·&nbsp;
              <span style={{ color: '#ffaa00', fontWeight: 'bold' }}>{pending}</span> pending
              <span style={{ color: C.greyDim }}> / {total} total</span>
            </span>
            <span style={{ color: C.green, fontWeight: 'bold' }}>{pct}%</span>
          </div>
          <div style={{ background: '#1a1a1a', height: 7, display: 'flex' }}>
            <div style={{ background: C.green,   height: '100%', width: `${total > 0 ? (withEvidence  / total) * 100 : 0}%`, transition: 'width 0.5s ease' }} />
            <div style={{ background: C.greyDim, height: '100%', width: `${total > 0 ? (noArtifacts   / total) * 100 : 0}%`, transition: 'width 0.5s ease' }} />
            <div style={{ background: '#ffaa00', height: '100%', width: `${total > 0 ? (pending       / total) * 100 : 0}%`, transition: 'width 0.5s ease' }} />
          </div>
          <div style={{ display: 'flex', gap: 14, marginTop: 6 }}>
            {[['█ EVIDENCE', C.green], ['█ NO_ARTIFACTS', C.greyDim], ['█ PENDING', '#ffaa00']].map(([l, c]) => (
              <span key={l} style={{ color: c, fontSize: 9 }}>{l}</span>
            ))}
          </div>
        </div>
      </Card>

      {/* Verdict counters + collapsible technique table */}
      <Card title="VERDICT_ANALYSIS">
        {/* Verdict tiles */}
        <div style={{ padding: 14, display: 'flex', gap: 12, flexWrap: 'wrap', borderBottom: `1px solid ${C.border}` }}>
          {total === 0 ? (
            <span style={{ color: C.greyDim, fontSize: 11 }}>NO_VERDICTS_ASSIGNED</span>
          ) : (
            vCounts.map(([label, count, col]) => (
              <div key={label} style={{ border: `1px solid ${col}`, padding: '10px 18px', display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 88 }}>
                <span style={{ color: col, fontSize: 26, fontWeight: 'bold' }}>{count}</span>
                <span style={{ color: col, fontSize: 9, letterSpacing: 1, marginTop: 3 }}>{label}</span>
              </div>
            ))
          )}
        </div>

        {/* Collapsible technique table toggle */}
        <div
          onClick={() => setTechExpanded(p => !p)}
          style={{ padding: '7px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            cursor: 'pointer', userSelect: 'none',
            background: techExpanded ? 'rgba(0,255,65,0.03)' : 'transparent' }}
        >
          <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>
            TECHNIQUE_SUMMARY ({total})
          </span>
          <span style={{ color: C.greyDim, fontSize: 10 }}>{techExpanded ? '▲ COLLAPSE' : '▼ EXPAND'}</span>
        </div>

        {/* Technique table — only rendered when expanded */}
        {techExpanded && (
          <div style={{ maxHeight: 300, overflowY: 'auto', borderTop: `1px solid ${C.border}` }}>
            {total === 0 ? (
              <div style={{ color: C.greyDim, fontSize: 11, padding: 14 }}>NO_TECHNIQUES_LOADED</div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
                <thead>
                  <tr style={{ background: C.bgHeader, position: 'sticky', top: 0 }}>
                    {['T_CODE', 'TECHNIQUE', 'EVIDENCE', 'VERDICT'].map(h => (
                      <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: C.greyDim,
                        borderBottom: `1px solid ${C.border}`, fontWeight: 'bold' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {tacticList.map((t, i) => {
                    const v   = (t.verdict || 'UNDETERMINED').toUpperCase();
                    const col = vCol[v] || C.greyDim;
                    return (
                      <tr key={i} style={{ borderBottom: `1px solid #0a0a0a` }}>
                        <td style={{ padding: '5px 10px', color: C.green, whiteSpace: 'nowrap' }}>
                          {t.t_code}
                          {capaIdentifiedTechniques.has(t.t_code) && (
                            <span style={{ marginLeft: 6, padding: '1px 4px', fontSize: 8, background: 'rgba(255,170,0,0.12)', color: C.amber, border: `1px solid rgba(255,170,0,0.4)`, borderRadius: 2, verticalAlign: 'middle' }}>CAPA</span>
                          )}
                        </td>
                        <td style={{ padding: '5px 10px', color: C.grey }}>{t.technique_name || t.name}</td>
                        <td style={{ padding: '5px 10px', color: t.evidence_imported ? C.purple : (t.verdict?.toUpperCase() === 'NO_ARTIFACTS' ? C.greyDim : '#ffaa00') }}>
                          {t.evidence_imported ? '✓' : t.verdict?.toUpperCase() === 'NO_ARTIFACTS' ? 'EMPTY' : 'PENDING'}
                        </td>
                        <td style={{ padding: '5px 10px', color: col }}>{v}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}
      </Card>

      {/* Memory summary */}
      <Card title="MEMORY_ANALYSIS_SUMMARY">
        {memSummary ? (
          <div style={{ padding: 14, display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            {[['PLUGINS_RUN', memSummary.pluginsRun], ['TOTAL_ROWS', memSummary.totalRows], ['LAST_PLUGIN', memSummary.lastPlugin || '---']].map(([l, v]) => (
              <div key={l} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
                <span style={{ color: C.white, fontSize: 15, fontWeight: 'bold', fontFamily: 'monospace' }}>{String(v)}</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: C.greyDim, flexShrink: 0 }} />
            <span style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>
              PENDING_ANALYSIS — No results available. Run a plugin in the MEMORY_ANALYSIS tab to populate this section.
            </span>
          </div>
        )}
      </Card>

      {/* AV summary */}
      <Card title="MALWARE_SCAN_SUMMARY">
        {avSummary ? (
          <div style={{ padding: 14, display: 'flex', gap: 0 }}>
            {[['SCANNED', avSummary.scanned, C.white], ['INFECTED', avSummary.infected, avSummary.infected > 0 ? C.red : C.green],
              ['STATUS', avSummary.infected > 0 ? '⚠ THREATS_DETECTED' : '✓ CLEAN', avSummary.infected > 0 ? C.red : C.green]
            ].map(([l, v, col]) => (
              <div key={l} style={{ padding: '8px 18px', borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
                <span style={{ color: col, fontSize: typeof v === 'number' ? 20 : 11, fontWeight: 'bold', fontFamily: 'monospace' }}>{String(v)}</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: C.greyDim, flexShrink: 0 }} />
            <span style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>
              PENDING_ANALYSIS — No results available. Run ClamAV in the KNOWN_MALWARE_SIGNATURES tab to populate this section.
            </span>
          </div>
        )}
      </Card>

      {/* Vuln summary */}
      <Card title="VULNERABILITY_SCAN_SUMMARY">
        {vulnSummary ? (
          <div style={{ padding: 14, display: 'flex', gap: 0 }}>
            {[
              ['TOTAL',    vulnSummary.total,    C.white],
              ['CRITICAL', vulnSummary.critical, vulnSummary.critical > 0 ? C.red     : C.greyDim],
              ['HIGH',     vulnSummary.high,     vulnSummary.high     > 0 ? '#ff8800' : C.greyDim],
              ['MEDIUM',   vulnSummary.medium,   vulnSummary.medium   > 0 ? C.amber   : C.greyDim],
              ['LOW',      vulnSummary.low,      C.green],
            ].map(([l, v, col]) => (
              <div key={l} style={{ padding: '8px 18px', borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
                <span style={{ color: col, fontSize: 20, fontWeight: 'bold', fontFamily: 'monospace' }}>{String(v)}</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: C.greyDim, flexShrink: 0 }} />
            <span style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>
              PENDING_ANALYSIS — No results available. Run a vuln scan in the VULN_SCAN tab to populate this section.
            </span>
          </div>
        )}
      </Card>

      {/* Behavioral analysis summary */}
      <Card title="BEHAVIORAL_ANALYSIS_SUMMARY">
        {behavioralSummary ? (
          <div style={{ padding: 14, display: 'flex', gap: 0 }}>
            {[
              ['ATT&CK TECHNIQUES', behavioralSummary.techniqueCount, behavioralSummary.techniqueCount > 0 ? C.red : C.greyDim],
              ['IOCS_EXTRACTED',    behavioralSummary.iocCount,       behavioralSummary.iocCount       > 0 ? C.amber : C.greyDim],
              ['API_CALLS',         behavioralSummary.apiCallCount,   C.green],
            ].map(([l, v, col]) => (
              <div key={l} style={{ padding: '8px 18px', borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
                <span style={{ color: col, fontSize: 20, fontWeight: 'bold', fontFamily: 'monospace' }}>{String(v)}</span>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ padding: 18, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: C.greyDim, flexShrink: 0 }} />
            <span style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace' }}>
              PENDING_ANALYSIS — No results available. Submit a binary in the BEHAVIORAL ANALYSIS tab to populate this section.
            </span>
          </div>
        )}
      </Card>

    </div>
  );
};


// ── Delete-evidence confirmation — three sequential gates before the DELETE
// fires: (1) plain confirm, (2) a math check to filter out reflexive clicking,
// (3) an explicit "this is logged" warning. The backend writes an audit_log
// row itself once the DELETE actually lands, so gate 3 is just making sure
// the analyst has read that before committing.
const DeleteEvidenceModal = ({ tCode, deleting, onCancel, onConfirm }) => {
  const [gate, setGate] = useState(1);
  const makeProblem = () => {
    const a = Math.floor(Math.random() * 40) + 5;
    const b = Math.floor(Math.random() * 40) + 5;
    const op = Math.random() < 0.5 ? '+' : '-';
    return { a, b, op, result: op === '+' ? a + b : a - b };
  };
  const [problem, setProblem] = useState(makeProblem);
  const [answer, setAnswer]   = useState('');
  const [mathError, setMathError] = useState(false);

  const submitMath = () => {
    if (parseInt(answer, 10) === problem.result) {
      setGate(3);
    } else {
      setMathError(true);
      setProblem(makeProblem());
      setAnswer('');
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000 }}>
      <div style={{ width: 420, background: '#0a0a0a', border: `1px solid ${C.red}`, padding: 22, fontFamily: 'monospace' }}>
        {gate === 1 && (
          <>
            <div style={{ color: C.red, fontSize: 13, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>DELETE_EVIDENCE — {tCode}</div>
            <div style={{ color: C.grey, fontSize: 12, marginBottom: 20, lineHeight: 1.5 }}>
              Are you sure you want to delete all evidence collected for this technique? This cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={() => setGate(2)} style={{ ...Btn, background: C.red, color: '#fff' }}>YES, CONTINUE</button>
              <button onClick={onCancel} style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.greyDim }}>CANCEL</button>
            </div>
          </>
        )}
        {gate === 2 && (
          <>
            <div style={{ color: C.red, fontSize: 13, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>VERIFY — SOLVE TO CONTINUE</div>
            <div style={{ color: C.white, fontSize: 18, marginBottom: 12 }}>{problem.a} {problem.op} {problem.b} = ?</div>
            {mathError && <div style={{ color: C.amber, fontSize: 11, marginBottom: 8 }}>INCORRECT — new problem generated, try again</div>}
            <input autoFocus type="number" value={answer} onChange={e => setAnswer(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && submitMath()}
              style={{ ...Inp, width: 100, marginBottom: 18, fontSize: 14 }} />
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={submitMath} style={{ ...Btn, background: C.red, color: '#fff' }}>SUBMIT</button>
              <button onClick={onCancel} style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.greyDim }}>CANCEL</button>
            </div>
          </>
        )}
        {gate === 3 && (
          <>
            <div style={{ background: 'rgba(255,68,68,0.1)', border: `1px solid ${C.red}`, padding: 14, marginBottom: 18 }}>
              <div style={{ color: C.red, fontSize: 12, fontWeight: 'bold' }}>⚠ You are deleting evidence from an investigation.</div>
              <div style={{ color: C.red, fontSize: 11, marginTop: 8, lineHeight: 1.5 }}>
                This activity is logged and attributed to your account in the audit trail.
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={onConfirm} disabled={deleting}
                style={{ ...Btn, background: C.red, color: '#fff', opacity: deleting ? 0.5 : 1 }}>
                {deleting ? 'DELETING...' : 'CONFIRM_DELETE'}
              </button>
              <button onClick={onCancel} disabled={deleting}
                style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.greyDim }}>ABORT</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// ARTIFACT ANALYSIS TAB
// ══════════════════════════════════════════════════════════════════════════════
// Artifacts that use server-side pagination (row counts too large for client-side)
const PAGINATED_TCODES = new Set([
  'EVENT_LOGS_SECURITY','EVENT_LOGS_APPLICATION','EVENT_LOGS_SYSMON',
  'EVENT_LOGS_POWERSHELL','EVENT_LOGS_SYSTEM','EVENT_LOGS_TASKSCHEDULER',
  'EVENT_LOGS_WMI','EVENT_LOGS_WINRM','SRUM',
]);
const EV_PAGE_SIZE = 100;

const ArtifactAnalysisTab = ({ assetId, assetName, tacticList: initTactics, caseName, onCollectionStarted, collab, analysisMode = 'UNKNOWN', assetIp = '', isNetworkDevice = false, netConfigText = '', netConfigFile = '' }) => {
  const [tactics, setTactics]           = useState(initTactics || []);
  const [sel, setSel]                   = useState(null);
  const [protocol, setProtocol]         = useState(null);
  const [analytics, setAnalytics]       = useState(null);
  const [analyticsTab, setAnalyticsTab] = useState(null);
  const [guidanceTab, setGuidanceTab]   = useState('CURATED');
  const [guidanceOpen, setGuidanceOpen] = useState(false);
  const [evidenceRows, setEvidenceRows] = useState([]);
  const [activeSource, setActiveSource] = useState(null);
  const [loadingEv, setLoadingEv]       = useState(false);
  const [filter, setFilter]             = useState('');
  const [starredOnly, setStarredOnly]   = useState(false);
  const [visibleCount, setVisibleCount] = useState(50);  // virtual scroll page size
  // Server-side pagination state (for large artifacts)
  const [evPage, setEvPage]             = useState(0);
  const [evTotal, setEvTotal]           = useState(0);
  const [evSearch, setEvSearch]         = useState('');
  const [evSearchInput, setEvSearchInput] = useState('');
  const [isCollecting, setIsCollecting] = useState(false);
  const [drive, setDrive]               = useState('C:');
  const [remapEnabled, setRemapEnabled] = useState(false);
  const [remapMounted, setRemapMounted] = useState('N');
  // Remote execution state
  const [notes, setNotes]               = useState([]);
  const [noteIn, setNoteIn]             = useState('');
  const [noteType, setNoteType]         = useState('NOTE');
  const [ctxMenu, setCtxMenu]           = useState({ visible: false, x: 0, y: 0, text: '' });
  const [submitting, setSubmitting]     = useState(false);
  const pollRef = useRef(null);

  useEffect(() => { setTactics(initTactics || []); }, [initTactics]);
  useEffect(() => { if (tactics.length > 0 && !sel) setSel(tactics[0].t_code); }, [tactics]);

  useEffect(() => {
    if (!sel) return;
    setProtocol(null);
    setAnalytics(null);
    setGuidanceOpen(false);
    setEvPage(0);
    setEvTotal(0);
    setEvSearch('');
    setEvSearchInput('');
    setStarredOnly(false);
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/library/${sel}`, { headers: getAuth() })
      .then(r => r.json()).then(setProtocol).catch(() => setProtocol(null));
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/analytics/${sel}`, { headers: getAuth() })
      .then(r => r.json()).then(data => {
        setAnalytics(data?.analytics_by_platform && Object.keys(data.analytics_by_platform).length > 0 ? data : null);
        setAnalyticsTab(data?.platforms?.[0] || null);
      }).catch(() => setAnalytics(null));
    loadEvidence(sel);
    loadNotes(sel);
  }, [sel]);

  useEffect(() => {
    refreshTactics();
    return () => stopPoll();
  }, [assetId, caseName]);

  const startPoll = () => { if (pollRef.current) return; pollRef.current = setInterval(refreshTactics, 8000); };
  const stopPoll  = () => { clearInterval(pollRef.current); pollRef.current = null; };

  const refreshTactics = async () => {
    if (!caseName || !assetId) return;
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/threat-profile/${encodeURIComponent(caseName)}?asset_id=${assetId}`, { headers: getAuth() });
      if (r.status === 401) { stopPoll(); handle401(); return; }
      const d = await r.json();
      if (Array.isArray(d)) setTactics(d);
    } catch {}
  };

  const loadEvidence = async (tCode, page = 0, search = '', starredOnlyArg = false) => {
    setLoadingEv(true); setEvidenceRows([]); setActiveSource(null); setVisibleCount(50);
    try {
      if (PAGINATED_TCODES.has(tCode)) {
        const params = new URLSearchParams({ page, page_size: EV_PAGE_SIZE });
        if (search) params.set('search', search);
        if (starredOnlyArg) params.set('starred_only', 'true');
        const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${tCode}/rows?${params}`, { headers: getAuth() });
        const d = await r.json();
        setEvidenceRows(d.rows || []);
        setEvTotal(d.total || 0);
        setEvPage(page);
      } else {
        const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${tCode}`, { headers: getAuth() });
        const d = await r.json();
        const content = d.rows || d;
        if (Array.isArray(content) && content.length > 0 && content[0].VQLSource) {
          const grouped = content.reduce((acc, row) => {
            const src = (row.VQLSource || 'General').split('/').pop();
            if (!acc[src]) acc[src] = [];
            acc[src].push(row);
            return acc;
          }, {});
          setEvidenceRows(grouped);
          setActiveSource(Object.keys(grouped)[0]);
        } else {
          setEvidenceRows(Array.isArray(content) ? content : []);
        }
        setEvTotal(0);
        setEvPage(0);
      }
    } catch { setEvidenceRows([]); }
    finally { setLoadingEv(false); }
  };

  // v2 notes — author-aware
  const loadNotes = async (tCode) => {
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${tCode}/notes/v2`, { headers: getAuth() });
      if (r.ok) setNotes(await r.json());
    } catch { setNotes([]); }
  };

  const updateVerdict = async (verdict) => {
    if (!sel) return;
    await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/verdict`,
      { method: 'POST', headers: getAuth(), body: JSON.stringify({ verdict }) });
    refreshTactics();
  };

  const updateRowStarred = (rowId, starred) => {
    setEvidenceRows(prev => {
      if (Array.isArray(prev)) return prev.map(r => r._orca_row_id === rowId ? { ...r, _orca_starred: starred } : r);
      if (prev && typeof prev === 'object') {
        const next = {};
        for (const k of Object.keys(prev)) next[k] = prev[k].map(r => r._orca_row_id === rowId ? { ...r, _orca_starred: starred } : r);
        return next;
      }
      return prev;
    });
  };

  const toggleStar = async (row) => {
    if (!row._orca_row_id || !sel) return;
    const next = !row._orca_starred;
    updateRowStarred(row._orca_row_id, next);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/row/${row._orca_row_id}/star`,
        { method: 'POST', headers: getAuth(), body: JSON.stringify({ starred: next }) });
      if (!r.ok) updateRowStarred(row._orca_row_id, !next);
    } catch { updateRowStarred(row._orca_row_id, !next); }
  };

  // ── Technique claim ─────────────────────────────────────────────────────
  const handleSelectTechnique = (tCode) => {
    setSel(tCode);
  };

  const handleSubmit = async () => {
    if (!sel || !collab) return;
    setSubmitting(true);
    try {
      await collab.submitTechnique(assetId, sel);
      refreshTactics();
    } catch {}
    finally { setSubmitting(false); }
  };

  const handleRelease = async () => {
    if (!sel || !collab) return;
    await collab.releaseTechnique(assetId, sel);
  };

  // Derive lock state for currently selected technique
  const lockKey     = `${assetId}:${sel}`;
  const lockInfo    = collab?.techniqueLocks?.get(lockKey);
  const statusInfo  = collab?.techniqueStatuses?.get(lockKey);
  const techStatus  = statusInfo?.technique_status || 'UNCLAIMED';

  // Decode current user initials from JWT to determine lock ownership
  const myInitials = (() => {
    try { return JSON.parse(localStorage.getItem('orca_user')).initials; } catch { return null; }
  })();
  const isAdmin = (() => {
    try { return JSON.parse(localStorage.getItem('orca_user')).role === 'admin'; } catch { return false; }
  })();
  const iAmLockHolder = lockInfo && lockInfo.locked_by_initials === myInitials;
  const isLockedByOther = lockInfo && !iAmLockHolder;
  const [showDeleteEvidence, setShowDeleteEvidence] = useState(false);
  const [deletingEvidence, setDeletingEvidence] = useState(false);

  const handleDeleteEvidence = async () => {
    if (!sel || !assetId) return;
    setDeletingEvidence(true);
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}`, {
        method: 'DELETE', headers: getAuth(),
      });
      if (resp.ok) {
        setShowDeleteEvidence(false);
        loadEvidence(sel);
        refreshTactics();
      } else {
        const e = await resp.json().catch(() => ({}));
        alert('DELETE_ERROR: ' + (e.detail || resp.statusText));
      }
    } catch {
      alert('CRITICAL: Cannot reach backend.');
    } finally {
      setDeletingEvidence(false);
    }
  };

  const runCollection = async () => {
    setIsCollecting(true);
    if (onCollectionStarted) onCollectionStarted('COLLECTION_RUNNING — Velociraptor executing...');
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/execute`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({ action: 'Surgical Collection', asset_id: assetId, tsource: drive }),
      });
      const d = await r.json();
      if (r.ok && d.status === 'initiated') {
        if (onCollectionStarted) onCollectionStarted(`COLLECTING — ${d.target_count || '?'} techniques queued`);
        refreshTactics();   // immediate refresh so OVERVIEW updates without waiting for first poll tick
        startPoll();
      } else {
        if (onCollectionStarted) onCollectionStarted(null);
        alert('EXECUTION_ERROR: ' + (d.detail || 'Failed to initiate.'));
      }
    } catch {
      if (onCollectionStarted) onCollectionStarted(null);
      alert('CRITICAL: Cannot reach backend.');
    } finally { setIsCollecting(false); }
  };

  const commitNote = async () => {
    if (!noteIn.trim() || !sel) return;
    if (collab && assetId) await collab.claimTechnique(assetId, sel);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/notes/v2`,
        { method: 'POST', headers: getAuth(), body: JSON.stringify({ text: noteIn, note_type: noteType }) });
      if (r.ok) {
        const d = await r.json();
        setNotes(prev => [...prev, {
          id: d.id, text: noteIn, type: noteType,
          time: d.time, author_initials: d.author_initials,
        }]);
        setNoteIn('');
      }
    } catch {}
  };

  const deleteNote = async (id) => {
    await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/notes/${id}`,
      { method: 'DELETE', headers: getAuth() });
    setNotes(prev => prev.filter(n => n.id !== id));
  };

  useEffect(() => {
    const close = () => setCtxMenu(p => ({ ...p, visible: false }));
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, []);

  const handleCtx = (e) => {
    const selected = window.getSelection().toString().trim();
    if (!selected) return;
    e.preventDefault();
    setCtxMenu({ visible: true, x: e.pageX, y: e.pageY, text: selected });
  };

  const promoteIOC = async () => {
    await fetch(`${import.meta.env.VITE_API_URL}/api/ioc/add`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: ctxMenu.text, ioc_type: 'Manual_Highlight', t_code: sel }),
    });
    setCtxMenu(p => ({ ...p, visible: false }));
  };

  const vtUrl  = v => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v) ? `https://www.virustotal.com/gui/ip-address/${v}` : `https://www.virustotal.com/gui/search/${v}`;
  const otxUrl = v => {
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v)) return `https://otx.alienvault.com/indicator/ip/${v}`;
    if (/^[a-fA-F0-9]{32,64}$/.test(v)) return `https://otx.alienvault.com/indicator/file/${v}`;
    if (v.includes('.') && !v.startsWith('http')) return `https://otx.alienvault.com/indicator/domain/${v}`;
    return `https://otx.alienvault.com/browse/indicators?q=${v}`;
  };

  const isGrouped  = !Array.isArray(evidenceRows) && typeof evidenceRows === 'object';
  const baseRows   = isGrouped ? (evidenceRows[activeSource] || []) : evidenceRows;
  const filteredRows = baseRows
    .filter(r => !starredOnly || r._orca_starred)
    .filter(r => Object.entries(r).filter(([k]) => k !== '_orca_row_id' && k !== '_orca_starred').some(([, v]) => String(v ?? '').toLowerCase().includes(filter.toLowerCase())));
  const dispRows   = filteredRows.slice(0, visibleCount);
  const curTactic  = tactics.find(t => t.t_code === sel);
  const curVerdict = (curTactic?.verdict || 'UNDETERMINED').toUpperCase();
  const vrdCol     = curVerdict === 'MALICIOUS' ? C.red : curVerdict === 'NON-MALICIOUS' ? C.green : C.greyDim;

  // Status badge color
  const statusColor = {
    UNCLAIMED:      C.greyDim,
    IN_PROGRESS:    '#ffffff',
    PENDING_REVIEW: C.amber,
    CLOSED:         C.green,
  };

  const fmtVal = (key, val) => {
    // Treat empty/null/undefined, empty objects, empty arrays, and '---' as missing
    if (val === null || val === undefined || val === '' || val === '---') return '---';
    if (typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length === 0) return '---';
    if (Array.isArray(val) && val.length === 0) return '---';

    // If val is a string that looks like a JSON object, try to parse and handle it
    if (typeof val === 'string' && val.startsWith('{')) {
      try {
        const parsed = JSON.parse(val);
        // Handle Velociraptor SystemTime: { "SystemTime": <unix_epoch_float> }
        if (parsed.SystemTime !== undefined) {
          const ms = parsed.SystemTime * 1000;
          const d = new Date(ms);
          return isNaN(d) ? val : d.toISOString().replace('T', ' ').slice(0, 23) + ' UTC';
        }
        // Empty object after parsing
        if (Object.keys(parsed).length === 0) return '---';
        // Otherwise show compact JSON
        return JSON.stringify(parsed);
      } catch {
        // Not valid JSON, fall through to string display
      }
    }

    const nk = key.toUpperCase().replace(/\s/g, '');
    if (['DIRECTORIES', 'FILESLOADED'].includes(nk) && typeof val === 'string') {
      return (
        <div style={{ maxHeight: 150, overflowY: 'auto', background: C.bg, padding: 5, border: `1px solid ${C.border}` }}>
          {val.split(',').map((s, i) => <div key={i} style={{ borderBottom: `1px solid #0a0a0a`, color: C.grey, fontSize: 10, paddingBottom: 2 }}>{i + 1}. {s.trim()}</div>)}
        </div>
      );
    }
    return typeof val === 'object' ? JSON.stringify(val) : val.toString();
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', height: '100%', overflow: 'hidden' }}>

      {/* ── Sidebar ── */}
      <aside style={{ borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>


        <div style={{ padding: '4px 12px', fontSize: 9, color: C.greyDim, borderBottom: `1px solid #0a0a0a`, letterSpacing: 1 }}>TECHNIQUE_INDEX</div>

        {/* Technique list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {tactics.map(t => {
            const active    = sel === t.t_code;
            const tKey      = `${assetId}:${t.t_code}`;
            const tStatus   = collab?.techniqueStatuses?.get(tKey)?.technique_status || 'UNCLAIMED';
            const tLock     = collab?.techniqueLocks?.get(tKey);
            const lockedByOther = tLock && tLock.locked_by_initials !== myInitials;

            const mal  = t.verdict?.toUpperCase() === 'MALICIOUS';
            const nmk  = t.verdict?.toUpperCase() === 'NON-MALICIOUS';
            const ev   = t.evidence_imported;

            // Border color priority: verdict > status
            const borderCol = mal ? C.red : nmk ? C.green : statusColor[tStatus] || C.greyDim;

            return (
              <div key={t.t_code}
                onClick={() => handleSelectTechnique(t.t_code)}
                style={{
                  padding: '9px 12px',
                  borderLeft: `3px solid ${borderCol}`,
                  borderBottom: `1px solid #0a0a0a`,
                  cursor: 'pointer',
                  background: active ? 'rgba(0,255,65,0.05)' : (t.has_notes && (t.verdict === 'Undetermined' || !t.verdict)) ? 'rgba(255,255,255,0.04)' : 'transparent',
                  opacity: lockedByOther ? 0.6 : 1,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, fontWeight: 'bold', color: borderCol }}>{t.t_code}</span>
                  <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                    {/* Status badge — only show if work has been done */}
                    {t.has_notes && (t.verdict === 'Undetermined' || !t.verdict) && (
                      <span style={{
                        fontSize: 7, color: '#ffffff',
                        border: '1px solid #ffffff',
                        padding: '1px 4px', letterSpacing: 0.5,
                      }}>WIP</span>
                    )}
                    {t.has_notes && t.last_note_author && (
                      <span style={{
                        fontSize: 7, background: C.green,
                        color: '#000', padding: '1px 4px', fontWeight: 'bold',
                      }}>{t.last_note_author}</span>
                    )}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: active ? C.grey : C.greyDim, marginTop: 1 }}>
                  {t.technique_name || t.name}
                </div>
                {ev && (
                  <div style={{ fontSize: 8, color: C.purple, marginTop: 2 }}>
                    ● EVIDENCE{t.has_fallback_evidence && <span style={{ color: C.amber }} title="Fallback evidence — primary query returned 0 hits, this is a broader collection for analyst review"> ⚠</span>}
                  </div>
                )}
                {lockedByOther && <div style={{ fontSize: 8, color: C.amber, marginTop: 2 }}>⚠ LOCKED — VIEW ONLY</div>}
              </div>
            );
          })}
          {tactics.length === 0 && <div style={{ color: C.greyDim, fontSize: 11, padding: 20, textAlign: 'center' }}>NO_TECHNIQUES</div>}
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#050505' }}>

        {/* Status bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '8px 15px', background: C.bg, borderBottom: `1px solid ${C.border}`, flexShrink: 0, gap: 10 }}>

          <div style={{ color: C.green, fontSize: 13, fontWeight: 'bold' }}>[ STATUS ]: {sel || 'IDLE'}</div>

          {/* Workflow action buttons */}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {/* Lock status indicator */}
            {sel && lockInfo && (
              <span style={{
                fontSize: 9, padding: '3px 8px', fontFamily: 'monospace',
                background: isLockedByOther ? 'rgba(255,170,0,0.1)' : 'rgba(0,255,65,0.1)',
                border: `1px solid ${isLockedByOther ? C.amber : C.green}`,
                color: isLockedByOther ? C.amber : C.green,
              }}>
                {isLockedByOther ? `⚠ LOCKED: ${lockInfo.locked_by_initials}` : '● YOUR_LOCK'}
              </span>
            )}

            {/* Submit for review — only if I hold the lock and status is IN_PROGRESS */}
            {sel && iAmLockHolder && techStatus === 'IN_PROGRESS' && (
              <button onClick={handleSubmit} disabled={submitting}
                style={{ ...Btn, background: C.amber, fontSize: 9, padding: '4px 10px', opacity: submitting ? 0.5 : 1 }}>
                {submitting ? 'SUBMITTING...' : '↑ SUBMIT_REVIEW'}
              </button>
            )}

            {/* Release lock */}
            {sel && iAmLockHolder && (
              <button onClick={handleRelease}
                style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.greyDim, fontSize: 9, padding: '4px 10px' }}>
                RELEASE_LOCK
              </button>
            )}

            {/* Flush evidence — admin only, only when this technique has evidence to remove */}
            {sel && isAdmin && curTactic?.evidence_imported && (
              <button onClick={() => setShowDeleteEvidence(true)}
                style={{ ...Btn, background: 'transparent', border: `1px solid ${C.red}`, color: C.red, fontSize: 9, padding: '4px 10px' }}>
                ⚠ FLUSH_EVIDENCE
              </button>
            )}

            {/* Verdict selector — read-only if locked by other */}
            <span style={{ color: C.grey, fontSize: 11 }}>VERDICT:</span>
            <select
              value={curVerdict}
              onChange={e => !isLockedByOther && updateVerdict(e.target.value)}
              disabled={isLockedByOther}
              style={{ background: C.bg, border: `1px solid ${vrdCol}`, color: vrdCol, padding: '4px 8px', fontSize: 11, fontFamily: 'monospace', outline: 'none', opacity: isLockedByOther ? 0.5 : 1 }}
            >
              <option value="UNDETERMINED">UNDETERMINED</option>
              <option value="MALICIOUS">MALICIOUS</option>
              <option value="NON-MALICIOUS">NON-MALICIOUS</option>
            </select>
          </div>
        </div>

        {/* Scrollable body */}
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12, padding: 14 }}>

          {/* ── Detection Guidance — collapsed by default ── */}
          {(protocol || analytics) && (
            <Card title="DETECTION_GUIDANCE">
              {/* Collapse toggle */}
              <div
                onClick={() => setGuidanceOpen(p => !p)}
                style={{ padding: '7px 14px', display: 'flex', justifyContent: 'space-between',
                  alignItems: 'center', cursor: 'pointer', userSelect: 'none',
                  background: guidanceOpen ? 'rgba(0,255,65,0.03)' : 'transparent' }}
              >
                {/* Inner tab pills — visible even when collapsed so analyst knows what's inside */}
                <div style={{ display: 'flex', gap: 6 }}>
                  {['CURATED', 'MITRE'].map(tab => {
                    const hasData = tab === 'CURATED' ? !!protocol : !!analytics;
                    if (!hasData) return null;
                    return (
                      <span key={tab} onClick={e => { e.stopPropagation(); setGuidanceTab(tab); if (!guidanceOpen) setGuidanceOpen(true); }}
                        style={{
                          fontSize: 9, padding: '2px 8px', letterSpacing: 1, cursor: 'pointer',
                          border: `1px solid ${guidanceTab === tab && guidanceOpen ? C.green : C.border}`,
                          color: guidanceTab === tab && guidanceOpen ? C.green : C.greyDim,
                          background: guidanceTab === tab && guidanceOpen ? 'rgba(0,255,65,0.08)' : 'transparent',
                        }}>
                        {tab}
                      </span>
                    );
                  })}
                </div>
                <span style={{ color: C.greyDim, fontSize: 10 }}>{guidanceOpen ? '▲ COLLAPSE' : '▼ EXPAND'}</span>
              </div>

              {guidanceOpen && (
                <div style={{ borderTop: `1px solid ${C.border}`, padding: 14 }}>

                  {/* CURATED tab */}
                  {guidanceTab === 'CURATED' && protocol && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      {[['LIVE_ANALYSIS', protocol.live_analysis],
                        ['DEAD_DISK_ANALYSIS', protocol.dead_disk_analysis],
                        ['COLLECTION_STRATEGY', protocol.bluf_text || protocol.collection_strategy]
                      ].map(([l, txt]) => (
                        <div key={l}>
                          <div style={{ color: C.green, fontSize: 10, fontWeight: 'bold', marginBottom: 3 }}>&gt; {l}</div>
                          <div style={{ color: C.grey, fontSize: 12, lineHeight: 1.5 }}>{txt || '---'}</div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* MITRE tab */}
                  {guidanceTab === 'MITRE' && analytics && (
                    <div>
                      <div style={{ fontSize: 9, color: C.greyDim, letterSpacing: 1, marginBottom: 10 }}>
                        {analytics.strategy_name || analytics.t_code}
                      </div>
                      {/* Platform tabs */}
                      <div style={{ display: 'flex', gap: 4, marginBottom: 12, borderBottom: `1px solid ${C.border}`, paddingBottom: 8 }}>
                        {analytics.platforms.map(plat => (
                          <button key={plat} onClick={() => setAnalyticsTab(plat)}
                            style={{
                              background: analyticsTab === plat ? 'rgba(0,255,65,0.1)' : 'transparent',
                              border: `1px solid ${analyticsTab === plat ? C.green : C.border}`,
                              color: analyticsTab === plat ? C.green : C.greyDim,
                              padding: '3px 10px', fontSize: 10, fontFamily: 'monospace',
                              cursor: 'pointer', letterSpacing: 1,
                            }}>
                            {plat.toUpperCase()}
                          </button>
                        ))}
                      </div>
                      {/* Analytics for selected platform */}
                      {analyticsTab && (analytics.analytics_by_platform[analyticsTab] || []).map((a, idx) => {
                        const list = analytics.analytics_by_platform[analyticsTab];
                        return (
                          <div key={a.analytic_code} style={{
                            borderLeft: `2px solid ${C.border}`, paddingLeft: 12, marginBottom: 16,
                            paddingBottom: idx < list.length - 1 ? 16 : 0,
                            borderBottom: idx < list.length - 1 ? `1px solid #0a0a0a` : 'none',
                          }}>
                            <div style={{ color: C.greyDim, fontSize: 9, marginBottom: 6, letterSpacing: 1 }}>{a.analytic_code}</div>
                            <div style={{ color: C.grey, fontSize: 12, lineHeight: 1.6, marginBottom: 10 }}>{a.detection_narrative}</div>
                            {a.log_sources?.length > 0 && (
                              <div style={{ marginBottom: 8 }}>
                                <div style={{ color: C.green, fontSize: 9, fontWeight: 'bold', marginBottom: 4, letterSpacing: 1 }}>&gt; LOG_SOURCES</div>
                                {a.log_sources.map((ls, i) => (
                                  <div key={i} style={{ display: 'flex', gap: 8, fontSize: 11, fontFamily: 'monospace', padding: '3px 0', borderBottom: `1px solid #0a0a0a` }}>
                                    <span style={{ color: C.green, minWidth: 180, flexShrink: 0 }}>{ls.name}</span>
                                    <span style={{ color: C.greyDim }}>{ls.channel}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                            {a.tuning_parameters?.length > 0 && (
                              <div>
                                <div style={{ color: C.amber, fontSize: 9, fontWeight: 'bold', marginBottom: 4, letterSpacing: 1 }}>&gt; TUNING_PARAMETERS</div>
                                {a.tuning_parameters.map((tp, i) => (
                                  <div key={i} style={{ marginBottom: 4, paddingLeft: 8 }}>
                                    <span style={{ color: C.amber, fontSize: 10, fontFamily: 'monospace' }}>{tp.field}</span>
                                    <span style={{ color: C.greyDim, fontSize: 11 }}> — {tp.description}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}

                  {/* Fallback: selected tab has no data */}
                  {guidanceTab === 'CURATED' && !protocol && (
                    <div style={{ color: C.greyDim, fontSize: 11 }}>NO_CURATED_DATA_FOR_THIS_TECHNIQUE</div>
                  )}
                  {guidanceTab === 'MITRE' && !analytics && (
                    <div style={{ color: C.greyDim, fontSize: 11 }}>NO_MITRE_ANALYTICS_FOR_THIS_TECHNIQUE</div>
                  )}

                </div>
              )}
            </Card>
          )}

          {/* Notes — v2, author-aware, NOTE/BLUF toggle */}
          <Card title="ANALYST_NOTES">
            <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'flex', gap: 6 }}>
                <input
                  value={noteIn}
                  onChange={e => setNoteIn(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && commitNote()}
                  placeholder={isLockedByOther ? 'READ_ONLY — technique locked by another analyst' : noteType === 'BLUF' ? 'BLUF_ASSESSMENT...' : 'ANALYST_OBSERVATION...'}
                  disabled={isLockedByOther}
                  style={{ ...Inp, flex: 1, opacity: isLockedByOther ? 0.5 : 1,
                    fontWeight: noteType === 'BLUF' ? 'bold' : 'normal',
                    color: noteType === 'BLUF' ? C.amber : C.white,
                    borderColor: noteType === 'BLUF' ? C.amber : C.border,
                  }}
                />
                <button
                  onClick={() => setNoteType(p => p === 'NOTE' ? 'BLUF' : 'NOTE')}
                  disabled={isLockedByOther}
                  title="Toggle between NOTE and BLUF"
                  style={{ ...Btn, background: 'transparent', border: `1px solid ${noteType === 'BLUF' ? C.amber : C.border}`,
                    color: noteType === 'BLUF' ? C.amber : C.greyDim, padding: '6px 10px', opacity: isLockedByOther ? 0.5 : 1 }}>
                  {noteType}
                </button>
                <button onClick={commitNote} disabled={isLockedByOther}
                  style={{ ...Btn, opacity: isLockedByOther ? 0.5 : 1 }}>
                  COMMIT
                </button>
              </div>
              {notes.length > 0 && (
                <div style={{ maxHeight: 160, overflowY: 'auto', marginTop: 3, display: 'flex', flexDirection: 'column', gap: 3 }}>
                  {notes.map((n, i) => {
                    const isBluf = (n.type || '').toUpperCase() === 'BLUF';
                    return (
                      <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 8px',
                        borderLeft: `2px solid ${isBluf ? C.amber : C.border}`,
                        background: isBluf ? 'rgba(255,170,0,0.04)' : '#020202', fontSize: 11 }}>
                        <span>
                          <span style={{ opacity: 0.4, marginRight: 6, color: C.greyDim }}>[{n.time}]</span>
                          {isBluf && (
                            <span style={{ background: C.amber, color: '#000', fontSize: 8, fontWeight: 'bold', padding: '1px 4px', marginRight: 6, letterSpacing: 0.5 }}>
                              BLUF
                            </span>
                          )}
                          {n.author_initials && (
                            <span style={{ background: '#1a1a1a', color: isBluf ? C.amber : C.greyDim, fontSize: 9, padding: '1px 4px', marginRight: 6 }}>
                              {n.author_initials}
                            </span>
                          )}
                          <span style={{ color: isBluf ? C.amber : C.white, fontWeight: isBluf ? 'bold' : 'normal' }}>{n.text}</span>
                        </span>
                        {!isLockedByOther && (
                          <span onClick={() => deleteNote(n.id)} style={{ color: C.red, cursor: 'pointer', marginLeft: 8 }}>×</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </Card>

          {/* Evidence records — unchanged from original */}
          {sel && (
            <Card title="EVIDENCE_RECORDS" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
              {REGISTRY_TCODES.has(sel) ? (
                evidenceRows.length > 0
                  ? <RegistryTreeViewer rows={evidenceRows} />
                  : <div style={{ color: C.greyDim, fontSize: 12, padding: 14 }}>NO_REGISTRY_DATA_COLLECTED</div>
              ) : (<>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 12px', borderBottom: `1px solid ${C.border}`, flexShrink: 0, gap: 8 }}>
                {PAGINATED_TCODES.has(sel) ? (
                  // Large categories (event logs, SRUM, etc.) are paginated
                  // server-side -- evidenceRows here is only the current
                  // ~100-row page, so the plain client-side FILTER box below
                  // would silently only ever search whatever page happens to
                  // be loaded instead of the full evTotal result set. This
                  // wires the same server-side search already implemented
                  // in loadEvidence(tCode, page, search) and already used by
                  // ArtifactTreeTab's identical evidence view below.
                  <>
                    <span style={{ color: C.greyDim, fontSize: 10 }}>{evTotal.toLocaleString()} RECORDS</span>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <input
                        placeholder="SEARCH..."
                        value={evSearchInput}
                        onChange={e => setEvSearchInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') { setEvSearch(evSearchInput); loadEvidence(sel, 0, evSearchInput, starredOnly); } }}
                        style={{ ...Inp, width: 200 }}
                      />
                      <button onClick={() => { setEvSearch(evSearchInput); loadEvidence(sel, 0, evSearchInput, starredOnly); }}
                        style={{ ...Btn, fontSize: 9, padding: '3px 8px' }}>GO</button>
                      {evSearch && <button onClick={() => { setEvSearch(''); setEvSearchInput(''); loadEvidence(sel, 0, '', starredOnly); }}
                        style={{ ...Btn, fontSize: 9, padding: '3px 8px', color: C.greyDim }}>CLR</button>}
                      <button onClick={() => { const next = !starredOnly; setStarredOnly(next); loadEvidence(sel, 0, evSearch, next); }}
                        title="Show only starred evidence"
                        style={{ padding: '3px 8px', background: starredOnly ? '#332900' : 'transparent', border: `1px solid ${starredOnly ? '#ffd700' : C.border}`, color: starredOnly ? '#ffd700' : C.greyDim, cursor: 'pointer', fontFamily: 'monospace', fontSize: 9, fontWeight: 'bold' }}>
                        ★ STARRED
                      </button>
                    </div>
                  </>
                ) : (
                  <>
                    <span style={{ color: C.greyDim, fontSize: 10 }}>{dispRows.length}/{filteredRows.length} RECORDS</span>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      <input placeholder="FILTER..." value={filter} onChange={e => { setFilter(e.target.value); setVisibleCount(50); }}
                        style={{ ...Inp, width: 180 }} />
                      <button onClick={() => setStarredOnly(v => !v)}
                        title="Show only starred evidence"
                        style={{ padding: '3px 8px', background: starredOnly ? '#332900' : 'transparent', border: `1px solid ${starredOnly ? '#ffd700' : C.border}`, color: starredOnly ? '#ffd700' : C.greyDim, cursor: 'pointer', fontFamily: 'monospace', fontSize: 9, fontWeight: 'bold' }}>
                        ★ STARRED
                      </button>
                    </div>
                  </>
                )}
              </div>
              {isGrouped && (
                <div style={{ display: 'flex', gap: 4, padding: '6px 12px', borderBottom: `1px solid #0a0a0a`, overflowX: 'auto', flexShrink: 0 }}>
                  {Object.keys(evidenceRows).map(src => (
                    <button key={src} onClick={() => setActiveSource(src)}
                      style={{ background: C.bg, border: `1px solid ${activeSource === src ? C.green : C.border}`,
                        color: activeSource === src ? C.green : C.greyDim, padding: '3px 10px', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer' }}>
                      {src.replace(/_/g, ' ').toUpperCase()}
                    </button>
                  ))}
                </div>
              )}
              {ctxMenu.visible && (
                <div style={{ position: 'fixed', zIndex: 9000, background: '#050505', border: `1px solid ${C.green}`, minWidth: 200,
                  top: ctxMenu.y, left: ctxMenu.x, boxShadow: `0 0 15px rgba(0,255,65,0.2)` }}>
                  <div style={{ padding: '6px 10px', fontSize: 10, color: C.greyDim, borderBottom: `1px solid ${C.border}`,
                    maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>"{ctxMenu.text}"</div>
                  <div style={CtxItem} onClick={() => window.open(otxUrl(ctxMenu.text))}>LOOKUP_ON_OTX</div>
                  <div style={CtxItem} onClick={() => window.open(vtUrl(ctxMenu.text))}>LOOKUP_ON_VIRUSTOTAL</div>
                  <div style={{ ...CtxItem, color: '#ffea00', borderTop: `1px solid ${C.border}` }} onClick={promoteIOC}>PROMOTE_TO_IOC</div>
                </div>
              )}
              <div style={{ flex: 1, overflowY: 'auto', padding: 12 }} onContextMenu={handleCtx}
                onScroll={e => {
                  if (PAGINATED_TCODES.has(sel)) return; // server-side, no scroll-load
                  const el = e.currentTarget;
                  if (el.scrollTop + el.clientHeight >= el.scrollHeight - 200)
                    setVisibleCount(c => Math.min(c + 50, filteredRows.length));
                }}>
                {loadingEv ? (
                  <div style={{ color: C.green, fontSize: 12 }}>DECRYPTING_STORAGE_BLOCKS...</div>
                ) : (PAGINATED_TCODES.has(sel) ? evidenceRows : dispRows).length === 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {curTactic?.evidence_imported ? (
                      <div style={{ color: C.greyDim, fontSize: 12 }}>NO_ROWS_MATCH_FILTER</div>
                    ) : (
                      <>
                        {isNetworkDevice && netConfigText ? (
                          <InlineConfigViewer configText={netConfigText} fileName={netConfigFile} />
                        ) : (
                        <div style={{ color: C.greyDim, fontSize: 12 }}>
                          {(curTactic?.verdict || '').toUpperCase() === 'NO_ARTIFACTS'
                            ? 'AUTOMATIC_COLLECTION_RETURNED_NO_ARTIFACTS_FOR_THIS_TECHNIQUE'
                            : 'NO_EVIDENCE_COLLECTED_FOR_THIS_TECHNIQUE'}
                        </div>
                        )}
                        <div style={{ background: '#0a0a0a', border: `1px solid #333`, padding: 12 }}>
                          <div style={{ color: '#ffaa00', fontSize: 10, marginBottom: 8 }}>
                            ⚠ No evidence associated with this technique — manually upload evidence?
                          </div>
                          <input
                              type="file"
                              accept=".json,.jsonl,.csv,.txt"
                              id={`upload-ev-${sel}`}
                              style={{ display: 'none' }}
                              onChange={async (e) => {
                                const file = e.target.files[0];
                                if (!file) return;
                                const text = await file.text();
                                let rows = [];
                                const ext = file.name.split('.').pop().toLowerCase();
                                try {
                                  if (ext === 'json') {
                                    const parsed = JSON.parse(text);
                                    rows = Array.isArray(parsed) ? parsed : [parsed];
                                  } else if (ext === 'jsonl') {
                                    rows = text.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));
                                  } else if (ext === 'csv') {
                                    const lines = text.split('\n').filter(l => l.trim());
                                    const headers = lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
                                    rows = lines.slice(1).map(line => {
                                      const vals = line.split(',').map(v => v.trim().replace(/^"|"$/g, ''));
                                      return Object.fromEntries(headers.map((h, i) => [h, vals[i] || '']));
                                    });
                                  } else {
                                    rows = text.split('\n').filter(l => l.trim()).map(l => ({ Line: l }));
                                  }
                                  rows = rows.map(r => ({ ...r, _orca_manual_upload: true, _orca_upload_file: file.name }));
                                } catch (err) {
                                  alert('PARSE_ERROR: ' + err.message); return;
                                }
                                if (!rows.length) { alert('NO_PARSEABLE_ROWS_FOUND'); return; }
                                const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/upload`, {
                                  method: 'POST',
                                  headers: { ...getAuth(), 'Content-Type': 'application/json' },
                                  body: JSON.stringify({ rows, filename: file.name })
                                });
                                if (resp.ok) { loadEvidence(sel); refreshTactics(); }
                                else { const e = await resp.json(); alert('UPLOAD_ERROR: ' + (e.detail || resp.statusText)); }
                                e.target.value = '';
                              }}
                            />
                            <label htmlFor={`upload-ev-${sel}`} style={{
                              display: 'inline-block', padding: '5px 14px', border: `1px solid #ffaa00`,
                              color: '#ffaa00', fontSize: 10, cursor: 'pointer', letterSpacing: 1
                            }}>
                              SELECT_FILE (JSON / JSONL / CSV / TXT)
                            </label>
                        </div>
                      </>
                    )}
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    {(PAGINATED_TCODES.has(sel) ? evidenceRows : dispRows).map((item, idx) => {
                      const isFallback = item._orca_fallback === true;
                      return (
                        <div key={idx} style={{ background: C.bgCard, border: `1px solid ${isFallback ? '#ffaa00' : C.border}`, padding: 12, position: 'relative' }}>
                          {item._orca_row_id != null && (
                            <button onClick={() => toggleStar(item)}
                              title={item._orca_starred ? 'Unstar this evidence' : 'Star this evidence'}
                              style={{ position: 'absolute', top: -9, left: 8, background: item._orca_starred ? '#ffd700' : '#111', color: item._orca_starred ? '#000' : '#666', border: `1px solid ${item._orca_starred ? '#ffd700' : C.border}`, fontSize: 11, lineHeight: 1, padding: '2px 6px', fontWeight: 'bold', cursor: 'pointer' }}>
                              {item._orca_starred ? '★' : '☆'}
                            </button>
                          )}
                          <div style={{ position: 'absolute', top: -9, right: 8, background: isFallback ? '#ffaa00' : C.green, color: '#000', fontSize: 9, padding: '1px 5px', fontWeight: 'bold' }}>
                            INDEX_{(PAGINATED_TCODES.has(sel) ? evPage * EV_PAGE_SIZE + idx : idx).toString().padStart(3, '0')}
                          </div>
                          {isFallback && (
                            <div style={{ marginBottom: 8, padding: '4px 8px', background: '#1a1200', border: '1px solid #ffaa00', color: '#ffaa00', fontSize: 10 }}>
                              ⚠ BROAD COLLECTION — Primary query returned 0 hits. EventID-only filter applied. Review for relevance.
                            </div>
                          )}
                          {Object.entries(item).map(([k, v]) => {
                            if (k === 'VQLSource' || k === '_Source' || k === '_orca_fallback' || k === '_orca_fallback_note' || k === '_orca_row_id' || k === '_orca_starred') return null;
                            return (
                              <div key={k} style={{ display: 'flex', marginBottom: 5, borderBottom: `1px solid #0d0d0d`, paddingBottom: 3 }}>
                                <div style={{ color: isFallback ? '#ffaa00' : C.green, minWidth: 155, fontSize: 11, fontWeight: 'bold', flexShrink: 0 }}>{k.toUpperCase()}:</div>
                                <div style={{ color: C.white, fontSize: 11, lineHeight: 1.4, wordBreak: 'break-word', width: '100%' }}>{fmtVal(k, v)}</div>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                    {!PAGINATED_TCODES.has(sel) && visibleCount < filteredRows.length && (
                      <div style={{ textAlign: 'center', padding: '10px 0', color: C.greyDim, fontSize: 10, letterSpacing: 1 }}>
                        ↓ SCROLL FOR MORE — {filteredRows.length - visibleCount} REMAINING
                      </div>
                    )}
                  </div>
                )}
                {PAGINATED_TCODES.has(sel) && evTotal > EV_PAGE_SIZE && (
                  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, padding: '6px 12px', borderTop: `1px solid ${C.border}`, flexShrink: 0 }}>
                    <button onClick={() => loadEvidence(sel, evPage - 1, evSearch)} disabled={evPage === 0}
                      style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: evPage === 0 ? C.greyDim : C.white }}>◀ PREV</button>
                    <span style={{ color: C.greyDim, fontSize: 10 }}>
                      PAGE {evPage + 1} / {Math.ceil(evTotal / EV_PAGE_SIZE)} · {evTotal.toLocaleString()} RECORDS
                    </span>
                    <button onClick={() => loadEvidence(sel, evPage + 1, evSearch)} disabled={evPage >= Math.ceil(evTotal / EV_PAGE_SIZE) - 1}
                      style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: evPage >= Math.ceil(evTotal / EV_PAGE_SIZE) - 1 ? C.greyDim : C.white }}>NEXT ▶</button>
                  </div>
                )}
              </div>
              </>)}
            </Card>
          )}
        </div>
      </main>

      {showDeleteEvidence && (
        <DeleteEvidenceModal
          tCode={sel}
          deleting={deletingEvidence}
          onCancel={() => setShowDeleteEvidence(false)}
          onConfirm={handleDeleteEvidence}
        />
      )}
    </div>
  );
};


// ── IR Artifact Guidance (ArtifactTreeTab only) ───────────────────────────────
const ARTIFACT_GUIDANCE = {
  EVENT_LOGS_SECURITY: {
    label: 'Security Event Log',
    tips: [
      'EID 4624/4625 — Successful/failed logons. Look for unusual hours, rare source IPs, or logon type 3 (network) from unexpected hosts.',
      'EID 4648 — Explicit credential use. Lateral movement often shows this before 4624 on a remote system.',
      'EID 4672 — Special privileges assigned. Flags admin-level logons; correlate with 4624 for the same LogonID.',
      'EID 4688 — Process creation (if audited). Look for cmd.exe, powershell.exe, wscript.exe spawned by Office apps or services.',
      'EID 4698/4702 — Scheduled task created/modified. Common persistence mechanism.',
      'EID 4720/4722/4732 — Account created, enabled, or added to group. Watch for new admin accounts.',
      'EID 4776 — NTLM credential validation. Failed attempts in bulk = password spray.',
      'EID 4768/4769/4771 — Kerberos TGT/service ticket requests and failures. Golden/silver ticket attacks leave anomalies here.',
      'EID 4778/4779 — RDP session reconnect/disconnect. Track lateral movement via RDP.',
      'EID 1102 — Audit log cleared. High confidence indicator of anti-forensics.',
    ],
  },
  EVENT_LOGS_SYSMON: {
    label: 'Sysmon Event Log',
    tips: [
      'EID 1 — Process Create. The gold standard for execution tracing. Check ParentImage for unusual spawn chains (e.g. Office → PowerShell, Explorer → cmd).',
      'EID 3 — Network Connection. Look for unusual outbound from system processes, or connections to non-standard ports/IPs.',
      'EID 7 — Image Loaded. DLL loads into processes — useful for detecting injection or hijacking.',
      'EID 8 — CreateRemoteThread. Strong indicator of process injection.',
      'EID 10 — ProcessAccess. LSASS being accessed by non-system processes = credential dumping attempt.',
      'EID 11 — FileCreate. Watch for files dropped in temp paths, startup folders, or System32.',
      'EID 12/13 — Registry create/set. Look for Run keys, services, COM hijack paths being written.',
      'EID 15 — FileCreateStreamHash. Alternate data stream creation — possible evasion.',
      'EID 17/18 — Pipe created/connected. Named pipes used by many C2 frameworks (Cobalt Strike, Meterpreter).',
      'EID 22 — DNS Query. Look for DGA-like domains, frequent lookups to the same IP, or lookups right before suspicious network connections.',
      'EID 25 — Process Tampering. Direct indicator of process ghosting or hollowing.',
    ],
  },
  EVENT_LOGS_POWERSHELL: {
    label: 'PowerShell Event Log',
    tips: [
      'EID 4103 — Module logging. Captures actual commands run — look for encoded commands, download cradles (IEX, DownloadString), AMSI bypass attempts.',
      'EID 4104 — Script block logging. Full script content captured. Search for Invoke-Expression, Base64 encoded blobs, Mimikatz keywords, or anything that deobfuscates at runtime.',
      'EID 400/403 — Engine start/stop. Short-lived sessions (start immediately followed by stop) suggest scripted one-liners rather than interactive use.',
      'Look for use of -EncodedCommand, -WindowStyle Hidden, -ExecutionPolicy Bypass flags.',
      'Common attack patterns: download cradles (IEX(New-Object Net.WebClient).DownloadString), AMSI bypass (using Add-Type or reflection), WMI abuse via PowerShell.',
      'PowerShell remoting (Enter-PSSession, Invoke-Command) leaves entries here — correlate with WinRM logs.',
    ],
  },
  EVENT_LOGS_SYSTEM: {
    label: 'System Event Log',
    tips: [
      'EID 7045 — New service installed. Common persistence mechanism; check ImagePath for unusual executables or UNC paths.',
      'EID 7034/7035/7036 — Service crashed, stopped/started. Repeated crashes may indicate a malformed malicious service.',
      'EID 6008 — Unexpected shutdown. May indicate system crash, power loss, or forced reboot by attacker.',
      'EID 104 — System log cleared. Anti-forensics indicator.',
      'EID 1 — Hardware error events can indicate disk issues relevant to timeline reconstruction.',
      'Driver load events — look for unsigned or unusual drivers loaded during the incident window.',
    ],
  },
  EVENT_LOGS_APPLICATION: {
    label: 'Application Event Log',
    tips: [
      'Application crashes (EID 1000/1001) — note the faulting module. Crashes in unusual processes or with exploit-related modules (e.g. ntdll.dll) can indicate exploitation attempts.',
      'Windows Error Reporting (EID 1001) — records crash details including which process, which module, and offset. Can help identify exploitation.',
      'MSI install events — track software installations during the incident window.',
      'Look for application-specific security events from AV, backup, or database software that may have logged relevant activity.',
    ],
  },
  EVENT_LOGS_WMI: {
    label: 'WMI Activity Log',
    tips: [
      'EID 5857/5858 — WMI provider load/error. Track which providers are being invoked.',
      'EID 5860/5861 — Temporary/permanent WMI event subscription. EID 5861 is a high-confidence persistence indicator — a permanent subscription was registered.',
      'Look for subscriptions with unusual consumer paths (scripts, executables) or filter queries that match process names or file paths.',
      'Correlate with WMI_PERSISTENCE artifact which shows the actual subscription content.',
    ],
  },
  EVENT_LOGS_WINRM: {
    label: 'WinRM Event Log',
    tips: [
      'WinRM is the transport layer for PowerShell remoting and many C2 frameworks.',
      'Look for authentication events, especially from unexpected source hosts or at unusual times.',
      'EID 91 — Session created. Track which remote hosts are connecting.',
      'EID 168 — Authenticating user. Failed attempts in bulk indicate brute force or credential stuffing.',
      'Correlate source IPs with Security log EID 4624 logon type 3 events.',
    ],
  },
  EVENT_LOGS_TASKSCHEDULER: {
    label: 'Task Scheduler Log',
    tips: [
      'EID 106 — Task registered. New task creation during incident window is high priority.',
      'EID 200/201 — Task executed/completed. Track what ran and when.',
      'EID 141 — Task deleted. Attackers sometimes clean up tasks after execution.',
      'Look for tasks with actions pointing to temp directories, AppData, or using cmd/PowerShell with encoded commands.',
      'Correlate with SCHEDULED_TASKS artifact for the actual task configuration.',
    ],
  },
  PREFETCH: {
    label: 'Prefetch',
    tips: [
      'Prefetch proves execution — if it has a .pf file, it ran. This is true even if the executable was subsequently deleted.',
      'Check RunCount and LastRunTimes — high run counts or repeated execution at regular intervals suggest scripted or scheduled activity.',
      'Look for executables running from unusual paths: temp directories, AppData, user profile roots, or removable media (\Device\HarddiskVolume path changes).',
      'Tool names to flag: mimikatz, psexec, wce, fgdump, procdump, cobalt*, beacon*, meterpreter*, nc.exe, nmap, any packer names.',
      'FilesAccessed field shows DLLs and data files loaded — can reveal C2 config files or staging directories even if the file is gone.',
      'Note: Prefetch is disabled by default on Windows Server. Absence of prefetch on a server does not mean tools were not run.',
      'Multiple prefetch files for the same executable name with different hashes indicate the file was run from different paths.',
    ],
  },
  MFT: {
    label: 'Master File Table ($MFT)',
    tips: [
      'The MFT records every file and directory on the NTFS volume, including deleted files (until the entry is reused).',
      'SUSPICIOUS view highlights files in high-risk locations (temp, AppData, Recycle Bin, root of drive) and all deleted files.',
      'TIMESTOMP detection: when $STANDARD_INFORMATION (SI) timestamps are earlier than $FILE_NAME (FN) timestamps, the attacker likely backdated the file using a tool like Timestomp or Metasploit.',
      'Look for executables (.exe, .dll, .ps1, .bat) created or modified during the incident window in non-standard locations.',
      'Files with HasADS=true have alternate data streams — data can be hidden inside ADS without changing the visible file size.',
      'Deleted files (InUse=false) are still recoverable and often contain attacker tools or staging files.',
      'SI_Lt_FN=true is a direct timestomping indicator — the $SI timestamps were modified after creation.',
      'Use TIMELINE view bounded to the incident window to see all file system activity during the attack.',
      'Compare Created0x10 vs Created0x30: legitimate files created by the OS/installer will have matching or close timestamps. Timestomped files will show anomalies.',
    ],
  },
  REGISTRY: {
    label: 'Registry',
    tips: [
      'Focus on persistence locations: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|RunOnce, HKCU\...\Run|RunOnce.',
      'Services: HKLM\SYSTEM\CurrentControlSet\Services — look for recently modified service entries with unusual ImagePath values (UNC paths, temp directories, encoded commands).',
      'COM hijacking: HKCU\SOFTWARE\Classes\CLSID — user-writable COM registrations that override HKLM entries.',
      'AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs) — DLLs loaded into every user-mode process.',
      'Image File Execution Options (IFEO): HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options — used for debugger hijacking and persistence.',
      'Shimming: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom — application shim database entries.',
      'Use search to look for IOC values (file paths, IP addresses, domain names) written into registry keys.',
      'Modified timestamps on keys can help establish a timeline of persistence installation.',
    ],
  },
  BROWSER_CHROME: {
    label: 'Chrome Browser History',
    tips: [
      'Look for visits to file-sharing sites (mega.nz, anonfiles, gofile.io), paste sites (pastebin, ghostbin), or C2 infrastructure.',
      'Check for downloads — what was pulled down and from where, and when relative to the incident window.',
      'Searches can reveal attacker reconnaissance ("how to disable windows defender", "mimikatz", target company names).',
      'Look for OAuth or credential-related URLs that may indicate account takeover or phishing.',
      'Visit timestamps help establish the attacker timeline if the browser was used during the intrusion.',
    ],
  },
  BROWSER_EDGE: {
    label: 'Edge Browser History',
    tips: [
      'Same analytical approach as Chrome — Edge is Chromium-based so artifacts are structurally identical.',
      'Edge is the default browser on modern Windows and may have been used even if Chrome is installed.',
      'Look for the same IOC patterns: file sharing, paste sites, suspicious searches, download activity.',
      'Check for InPrivate browsing gaps (periods with no history) that coincide with the incident window.',
    ],
  },
  BROWSER_FIREFOX: {
    label: 'Firefox Browser History',
    tips: [
      'Firefox history format differs from Chromium but contains the same investigative value.',
      'Look for the same patterns: file sharing, paste sites, suspicious searches, downloads.',
      'Firefox may retain more history than Chrome depending on settings.',
    ],
  },
  LNK_JUMPLISTS: {
    label: 'LNK Files / Jump Lists',
    tips: [
      'LNK files prove a file was opened by a user — the shortcut is created automatically by Windows.',
      'They survive even after the target file is deleted, providing evidence of execution or access.',
      'Check the target path, creation time, and modification time. Target paths pointing to USB drives, network shares, or temp directories are notable.',
      'Jump lists show recently accessed files per application — useful for identifying what documents or tools were accessed.',
      'The MAC timestamps on the LNK file reflect when the target was last accessed, not when the LNK was created.',
      'Look for LNKs pointing to executables in unusual locations — this is common when attackers stage tools and run them manually.',
    ],
  },
  SCHEDULED_TASKS: {
    label: 'Scheduled Tasks',
    tips: [
      'Review the Actions field — what executable or script does the task run? Paths in temp, AppData, or using encoded PowerShell are red flags.',
      'Check Triggers — how often does it run? Tasks that run at logon, at system start, or on a short interval are common persistence mechanisms.',
      'Look at the task Author and URI (path in Task Scheduler). Legitimate tasks are typically under \Microsoft\ subtrees; attacker tasks often appear at the root or under suspicious names.',
      'ModTime on the registry key backing the task can help establish when persistence was installed.',
      'Cross-reference with Task Scheduler event log (EID 106) for when the task was registered.',
    ],
  },
  WMI_PERSISTENCE: {
    label: 'WMI Persistence',
    tips: [
      'WMI subscriptions consist of three parts: EventFilter (trigger), EventConsumer (action), and FilterToConsumerBinding (links them).',
      'Check the consumer type — CommandLineEventConsumer and ActiveScriptEventConsumer are the most dangerous as they execute code.',
      'Examine the consumer CommandLineTemplate or ScriptText — this is the actual payload.',
      'Filter queries define the trigger — look for __InstanceCreationEvent (process creation), timer events, or login events.',
      'WMI subscriptions survive reboots and are stored in the WMI repository, not the registry or file system.',
      'Correlate with WMI Activity event log (EID 5861) for when the subscription was created.',
    ],
  },
  SRUM: {
    label: 'System Resource Usage Monitor (SRUM)',
    tips: [
      'SRUM records application resource usage (CPU, network, memory) for up to 30 days even after the application is deleted.',
      'Look for applications with high network bytes sent — potential data exfiltration.',
      'Check for applications running during the incident window that no longer exist on disk.',
      'Network usage by process is particularly valuable — an unusual process sending large amounts of data is a strong exfiltration indicator.',
      'SRUM data is timestamped and can fill gaps in the event log timeline.',
      'Useful for proving execution when prefetch is disabled (common on servers).',
    ],
  },
  AMCACHE: {
    label: 'Amcache',
    tips: [
      'Amcache records metadata about executables that ran on the system, including SHA1 hash, path, and first execution time.',
      'This is one of the most reliable execution artifacts — it persists even after the executable is deleted.',
      'The FileId field contains a SHA1 hash of the executable — submit to VirusTotal directly.',
      'First execution timestamps help establish when a tool was first introduced to the system.',
      'Look for executables with paths in temp directories, user profiles, or removable media.',
      'ProgramId links to associated program entries for installed software — unusual or unsigned programs stand out.',
      'Amcache entries are created when a file is first executed or installed, making it a reliable first-seen indicator.',
    ],
  },
  RECYCLE_BIN: {
    label: 'Recycle Bin',
    tips: [
      'Files in the Recycle Bin have two components: $I (metadata — original path, deletion time, file size) and $R (the actual file content).',
      'The original path tells you where the file came from — deleted tools from temp or staging directories are significant.',
      'DeletedTime is when it was moved to the Recycle Bin, not when the file was created.',
      'Attackers sometimes delete tools via Recycle Bin rather than permanent deletion, leaving recoverable artifacts.',
      'If $R files are present, the actual content can be recovered — check file extensions and consider submitting hashes to VT.',
      'Multiple items deleted at the same time often indicate a cleanup script ran.',
    ],
  },
  USB_ARTIFACTS: {
    label: 'USB Artifacts',
    tips: [
      'The SetupAPI log records every USB device connection with timestamps, device class, and hardware ID.',
      'Look for USB storage devices (DiskDrive class) connected during the incident window.',
      'Hardware IDs can sometimes be traced to specific device models or manufacturers.',
      'First install time vs last connection time helps establish device usage patterns.',
      'Correlate with MFT TIMELINE view to see files created/modified at the same time a USB device was connected.',
      'Also check HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR in the Registry artifact for additional device details.',
    ],
  },
};
// ── End IR Artifact Guidance ──────────────────────────────────────────────────
const ArtifactTreeTab = ({ assetId, assetName }) => {
  const [availableCategories, setAvailableCategories] = useState(new Set());
  const [expandedNodes, setExpandedNodes]             = useState(new Set(['EVENT_LOGS', 'REGISTRY', 'BROWSER']));
  const [sel, setSel]                                 = useState(null);
  const [evidenceRows, setEvidenceRows]               = useState([]);
  const [loadingEv, setLoadingEv]                     = useState(false);
  const [filter, setFilter]                           = useState('');
  const [starredOnly, setStarredOnly]                 = useState(false);
  const [visibleCount, setVisibleCount]               = useState(50);
  const [ctxMenu, setCtxMenu]                         = useState({ visible: false, x: 0, y: 0, text: '' });
  const [notes, setNotes]                             = useState([]);
  const [noteIn, setNoteIn]                           = useState('');
  const [noteType, setNoteType]                       = useState('NOTE');
  const [showGuidance, setShowGuidance]               = useState(false);
  const [evPage, setEvPage]                           = useState(0);
  const [evTotal, setEvTotal]                         = useState(0);
  const [evSearch, setEvSearch]                       = useState('');
  const [evSearchInput, setEvSearchInput]             = useState('');

  const loadCategories = async () => {
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/triage/categories`, { headers: getAuth() });
      if (r.ok) {
        const d = await r.json();
        setAvailableCategories(new Set(d.categories || []));
        if (d.categories?.length > 0 && !sel) setSel(d.categories[0]);
      }
    } catch {}
  };

  useEffect(() => { loadCategories(); }, [assetId]);

  const loadEvidence = async (tCode, page = 0, search = '', starredOnlyArg = false) => {
    setLoadingEv(true); setEvidenceRows([]); setVisibleCount(50); setFilter('');
    try {
      if (PAGINATED_TCODES.has(tCode)) {
        const params = new URLSearchParams({ page, page_size: EV_PAGE_SIZE });
        if (search) params.set('search', search);
        if (starredOnlyArg) params.set('starred_only', 'true');
        const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${tCode}/rows?${params}`, { headers: getAuth() });
        const d = await r.json();
        setEvidenceRows(d.rows || []);
        setEvTotal(d.total || 0);
        setEvPage(page);
      } else {
        const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${tCode}`, { headers: getAuth() });
        const d = await r.json();
        setEvidenceRows(d.rows || (Array.isArray(d) ? d : []));
        setEvTotal(0);
        setEvPage(0);
      }
    } catch { setEvidenceRows([]); }
    finally { setLoadingEv(false); }
  };

  const updateRowStarred = (rowId, starred) => {
    setEvidenceRows(prev => prev.map(r => r._orca_row_id === rowId ? { ...r, _orca_starred: starred } : r));
  };

  const toggleStar = async (row) => {
    if (!row._orca_row_id || !sel) return;
    const next = !row._orca_starred;
    updateRowStarred(row._orca_row_id, next);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/row/${row._orca_row_id}/star`,
        { method: 'POST', headers: getAuth(), body: JSON.stringify({ starred: next }) });
      if (!r.ok) updateRowStarred(row._orca_row_id, !next);
    } catch { updateRowStarred(row._orca_row_id, !next); }
  };

  useEffect(() => {
    if (!sel) return;
    setEvPage(0); setEvTotal(0); setEvSearch(''); setEvSearchInput(''); setStarredOnly(false);
    loadEvidence(sel);
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/notes/v2`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : []).then(setNotes).catch(() => setNotes([]));
  }, [sel, assetId]);

  const toggleExpand = (id) => setExpandedNodes(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  const commitNote = async () => {
    if (!noteIn.trim() || !sel) return;
    const r = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/notes/v2`,
      { method: 'POST', headers: getAuth(), body: JSON.stringify({ text: noteIn, note_type: noteType }) });
    if (r.ok) {
      const d = await r.json();
      setNotes(prev => [...prev, { id: d.id, text: noteIn, type: noteType, time: d.time, author_initials: d.author_initials }]);
      setNoteIn('');
    }
  };

  const deleteNote = async (id) => {
    await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/${sel}/notes/${id}`, { method: 'DELETE', headers: getAuth() });
    setNotes(prev => prev.filter(n => n.id !== id));
  };

  useEffect(() => {
    const close = () => setCtxMenu(p => ({ ...p, visible: false }));
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, []);

  const handleCtx = (e) => {
    const selected = window.getSelection().toString().trim();
    if (!selected) return;
    e.preventDefault();
    setCtxMenu({ visible: true, x: e.pageX, y: e.pageY, text: selected });
  };

  const promoteIOC = async () => {
    await fetch(`${import.meta.env.VITE_API_URL}/api/ioc/add`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: ctxMenu.text, ioc_type: 'Manual_Highlight', t_code: sel }),
    });
    setCtxMenu(p => ({ ...p, visible: false }));
  };

  const vtUrl  = v => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v) ? `https://www.virustotal.com/gui/ip-address/${v}` : `https://www.virustotal.com/gui/search/${v}`;
  const otxUrl = v => {
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v)) return `https://otx.alienvault.com/indicator/ip/${v}`;
    if (/^[a-fA-F0-9]{32,64}$/.test(v)) return `https://otx.alienvault.com/indicator/file/${v}`;
    if (v.includes('.') && !v.startsWith('http')) return `https://otx.alienvault.com/indicator/domain/${v}`;
    return `https://otx.alienvault.com/browse/indicators?q=${v}`;
  };

  const isRegistryView = REGISTRY_TCODES.has(sel);
  const filteredRows = isRegistryView ? [] : evidenceRows
    .filter(r => !starredOnly || r._orca_starred)
    .filter(r => Object.entries(r).filter(([k]) => k !== '_orca_row_id' && k !== '_orca_starred').some(([, v]) => String(v ?? '').toLowerCase().includes(filter.toLowerCase())));
  const dispRows     = filteredRows.slice(0, visibleCount);

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', height: '100%', overflow: 'hidden' }}>
      <aside style={{ borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '6px 12px', fontSize: 9, color: C.red, borderBottom: `1px solid #0a0a0a`, letterSpacing: 1, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
          <span>⚡</span> ARTIFACT_INDEX
          {availableCategories.size > 0 && <span style={{ marginLeft: 'auto', fontSize: 8, color: C.greyDim }}>{availableCategories.size} categories</span>}
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {TRIAGE_TREE.map(node => {
            const nodeHasData    = availableCategories.has(node.id) || node.children.some(c => availableCategories.has(c.id));
            const isExpanded     = expandedNodes.has(node.id);
            const hasChildren    = node.children.length > 0;
            const activeChildren = node.children.filter(c => availableCategories.has(c.id));

            if (hasChildren) {
              return (
                <div key={node.id}>
                  <div onClick={() => toggleExpand(node.id)}
                    style={{ padding: '8px 12px', borderBottom: `1px solid #0a0a0a`, cursor: 'pointer',
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                      background: nodeHasData ? 'rgba(255,65,65,0.03)' : 'transparent' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: C.greyDim, fontSize: 10 }}>{isExpanded ? '▼' : '▶'}</span>
                      <span style={{ color: nodeHasData ? C.white : C.greyDim, fontSize: 11, fontWeight: nodeHasData ? 'bold' : 'normal' }}>{node.label}</span>
                    </div>
                    {activeChildren.length > 0 && (
                      <span style={{ fontSize: 9, color: C.red, background: 'rgba(255,65,65,0.1)', padding: '1px 5px', border: '1px solid #660000' }}>{activeChildren.length}</span>
                    )}
                  </div>
                  {isExpanded && node.children.map(child => {
                    const childHasData = availableCategories.has(child.id);
                    const isActive = sel === child.id;
                    return (
                      <div key={child.id} onClick={() => childHasData && setSel(child.id)}
                        style={{ padding: '6px 12px 6px 26px', borderBottom: `1px solid #080808`,
                          cursor: childHasData ? 'pointer' : 'default',
                          background: isActive ? 'rgba(255,65,65,0.08)' : 'transparent',
                          borderLeft: `3px solid ${isActive ? C.red : childHasData ? '#660000' : 'transparent'}`,
                          opacity: childHasData ? 1 : 0.3 }}>
                        <span style={{ fontSize: 11, color: isActive ? '#ff8888' : childHasData ? C.white : C.greyDim }}>{child.label}</span>
                        {childHasData && !isActive && <span style={{ color: C.red, fontSize: 9, marginLeft: 6 }}>●</span>}
                      </div>
                    );
                  })}
                </div>
              );
            } else {
              const isActive = sel === node.id;
              return (
                <div key={node.id} onClick={() => nodeHasData && setSel(node.id)}
                  style={{ padding: '8px 12px', borderBottom: `1px solid #0a0a0a`,
                    cursor: nodeHasData ? 'pointer' : 'default',
                    background: isActive ? 'rgba(255,65,65,0.08)' : 'transparent',
                    borderLeft: `3px solid ${isActive ? C.red : nodeHasData ? '#660000' : 'transparent'}`,
                    opacity: nodeHasData ? 1 : 0.3 }}>
                  <span style={{ fontSize: 11, fontWeight: nodeHasData ? 'bold' : 'normal', color: isActive ? '#ff8888' : nodeHasData ? C.white : C.greyDim }}>{node.label}</span>
                  {nodeHasData && !isActive && <span style={{ color: C.red, fontSize: 9, marginLeft: 6 }}>●</span>}
                </div>
              );
            }
          })}
          {availableCategories.size === 0 && (
            <div style={{ color: C.greyDim, fontSize: 11, padding: 16, textAlign: 'center', lineHeight: 1.8 }}>
              NO_ARTIFACTS_COLLECTED<br/><span style={{ fontSize: 9 }}>Use bulk deploy on the ASSETS tab</span>
            </div>
          )}
        </div>
      </aside>

      <main style={{ display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#050505' }}>
        {/* Guidance Modal */}
        {showGuidance && sel && ARTIFACT_GUIDANCE[sel] && (
          <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(0,0,0,0.85)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            onClick={() => setShowGuidance(false)}>
            <div onClick={e => e.stopPropagation()}
              style={{ background: '#080808', border: `1px solid ${C.red}`, width: 620, maxHeight: '75vh', display: 'flex', flexDirection: 'column', fontFamily: 'monospace' }}>
              <div style={{ padding: '10px 16px', borderBottom: `1px solid #330000`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
                <span style={{ color: C.red, fontWeight: 'bold', fontSize: 12 }}>[ ANALYST_GUIDANCE ]: {ARTIFACT_GUIDANCE[sel].label.toUpperCase()}</span>
                <button onClick={() => setShowGuidance(false)} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontSize: 16, fontFamily: 'monospace' }}>×</button>
              </div>
              <div style={{ overflowY: 'auto', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                {ARTIFACT_GUIDANCE[sel].tips.map((tip, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10, fontSize: 11, lineHeight: 1.6 }}>
                    <span style={{ color: C.red, flexShrink: 0, marginTop: 1 }}>▸</span>
                    <span style={{ color: C.white }}>{tip}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '8px 15px', background: C.bg, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ color: C.red, fontSize: 13, fontWeight: 'bold' }}>[ ARTIFACT ]: {sel || 'SELECT_CATEGORY'}</div>
            {sel && ARTIFACT_GUIDANCE[sel] && (
              <button onClick={() => setShowGuidance(g => !g)}
                style={{ background: 'transparent', border: `1px solid #660000`, color: showGuidance ? C.red : C.greyDim,
                  cursor: 'pointer', fontSize: 9, padding: '2px 8px', fontFamily: 'monospace', letterSpacing: 1 }}>
                ? GUIDANCE
              </button>
            )}
          </div>
          <span style={{ fontSize: 9, padding: '2px 8px', border: '1px solid #660000', color: C.red, letterSpacing: 1 }}>⚡ INCIDENT_RESPONSE</span>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12, padding: 14 }}>
          {sel && (
            <Card title="ANALYST_NOTES">
              <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input value={noteIn} onChange={e => setNoteIn(e.target.value)} onKeyDown={e => e.key === 'Enter' && commitNote()}
                    placeholder={noteType === 'BLUF' ? 'BLUF_ASSESSMENT...' : 'ANALYST_OBSERVATION...'}
                    style={{ ...Inp, flex: 1, fontWeight: noteType === 'BLUF' ? 'bold' : 'normal',
                      color: noteType === 'BLUF' ? C.amber : C.white, borderColor: noteType === 'BLUF' ? C.amber : C.border }} />
                  <button onClick={() => setNoteType(p => p === 'NOTE' ? 'BLUF' : 'NOTE')}
                    style={{ ...Btn, background: 'transparent', border: `1px solid ${noteType === 'BLUF' ? C.amber : C.border}`,
                      color: noteType === 'BLUF' ? C.amber : C.greyDim, padding: '6px 10px' }}>{noteType}</button>
                  <button onClick={commitNote} style={Btn}>COMMIT</button>
                </div>
                {notes.length > 0 && (
                  <div style={{ maxHeight: 130, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {notes.map((n, i) => {
                      const isBluf = (n.type || '').toUpperCase() === 'BLUF';
                      return (
                        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 8px',
                          borderLeft: `2px solid ${isBluf ? C.amber : C.border}`, background: isBluf ? 'rgba(255,170,0,0.04)' : '#020202', fontSize: 11 }}>
                          <span>
                            <span style={{ opacity: 0.4, marginRight: 6, color: C.greyDim }}>[{n.time}]</span>
                            {isBluf && <span style={{ background: C.amber, color: '#000', fontSize: 8, fontWeight: 'bold', padding: '1px 4px', marginRight: 6 }}>BLUF</span>}
                            {n.author_initials && <span style={{ background: '#1a1a1a', color: isBluf ? C.amber : C.greyDim, fontSize: 9, padding: '1px 4px', marginRight: 6 }}>{n.author_initials}</span>}
                            <span style={{ color: isBluf ? C.amber : C.white, fontWeight: isBluf ? 'bold' : 'normal' }}>{n.text}</span>
                          </span>
                          <span onClick={() => deleteNote(n.id)} style={{ color: C.red, cursor: 'pointer', marginLeft: 8 }}>×</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </Card>
          )}

          {sel && (
            <Card title={`EVIDENCE_RECORDS — ${sel}`} style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
              {loadingEv ? (
                <div style={{ color: C.green, fontSize: 12, padding: 14 }}>LOADING_ARTIFACTS...</div>
              ) : sel === 'MFT' ? (
                /* ── MFT: multi-view analyst tool ── */
                <MftViewer assetId={assetId} />
              ) : REGISTRY_TCODES.has(sel) ? (
                /* ── Registry: tree viewer ── */
                evidenceRows.length > 0
                  ? <RegistryTreeViewer rows={evidenceRows} />
                  : <div style={{ color: C.greyDim, fontSize: 12, padding: 14 }}>NO_REGISTRY_DATA_COLLECTED</div>
              ) : (
                /* ── All other artifacts: flat record list ── */
                <>
                  {/* Header: count + search/filter */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 12px', borderBottom: `1px solid ${C.border}`, flexShrink: 0, gap: 8 }}>
                    {PAGINATED_TCODES.has(sel) ? (
                      <>
                        <span style={{ color: C.greyDim, fontSize: 10 }}>{evTotal.toLocaleString()} RECORDS</span>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <input
                            placeholder="SEARCH..."
                            value={evSearchInput}
                            onChange={e => setEvSearchInput(e.target.value)}
                            onKeyDown={e => { if (e.key === 'Enter') { setEvSearch(evSearchInput); loadEvidence(sel, 0, evSearchInput, starredOnly); } }}
                            style={{ ...Inp, width: 200 }}
                          />
                          <button onClick={() => { setEvSearch(evSearchInput); loadEvidence(sel, 0, evSearchInput, starredOnly); }}
                            style={{ ...Btn, fontSize: 9, padding: '3px 8px' }}>GO</button>
                          {evSearch && <button onClick={() => { setEvSearch(''); setEvSearchInput(''); loadEvidence(sel, 0, '', starredOnly); }}
                            style={{ ...Btn, fontSize: 9, padding: '3px 8px', color: C.greyDim }}>CLR</button>}
                          <button onClick={() => { const next = !starredOnly; setStarredOnly(next); loadEvidence(sel, 0, evSearch, next); }}
                            title="Show only starred evidence"
                            style={{ padding: '3px 8px', background: starredOnly ? '#332900' : 'transparent', border: `1px solid ${starredOnly ? '#ffd700' : C.border}`, color: starredOnly ? '#ffd700' : C.greyDim, cursor: 'pointer', fontFamily: 'monospace', fontSize: 9, fontWeight: 'bold' }}>
                            ★ STARRED
                          </button>
                        </div>
                      </>
                    ) : (
                      <>
                        <span style={{ color: C.greyDim, fontSize: 10 }}>{dispRows.length}/{filteredRows.length} RECORDS</span>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <input placeholder="FILTER..." value={filter} onChange={e => { setFilter(e.target.value); setVisibleCount(50); }} style={{ ...Inp, width: 180 }} />
                          <button onClick={() => setStarredOnly(v => !v)}
                            title="Show only starred evidence"
                            style={{ padding: '3px 8px', background: starredOnly ? '#332900' : 'transparent', border: `1px solid ${starredOnly ? '#ffd700' : C.border}`, color: starredOnly ? '#ffd700' : C.greyDim, cursor: 'pointer', fontFamily: 'monospace', fontSize: 9, fontWeight: 'bold' }}>
                            ★ STARRED
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                  {ctxMenu.visible && (
                    <div style={{ position: 'fixed', zIndex: 9000, background: '#050505', border: `1px solid ${C.green}`, minWidth: 200, top: ctxMenu.y, left: ctxMenu.x }}>
                      <div style={{ padding: '6px 10px', fontSize: 10, color: C.greyDim, borderBottom: `1px solid ${C.border}`, maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>"{ctxMenu.text}"</div>
                      <div style={CtxItem} onClick={() => window.open(otxUrl(ctxMenu.text))}>LOOKUP_ON_OTX</div>
                      <div style={CtxItem} onClick={() => window.open(vtUrl(ctxMenu.text))}>LOOKUP_ON_VIRUSTOTAL</div>
                      <div style={{ ...CtxItem, color: '#ffea00', borderTop: `1px solid ${C.border}` }} onClick={promoteIOC}>PROMOTE_TO_IOC</div>
                    </div>
                  )}
                  <div style={{ flex: 1, overflowY: 'auto', padding: 12 }} onContextMenu={handleCtx}
                    onScroll={e => {
                      if (PAGINATED_TCODES.has(sel)) return; // server-side, no scroll-load
                      const el = e.currentTarget;
                      if (el.scrollTop + el.clientHeight >= el.scrollHeight - 200)
                        setVisibleCount(c => Math.min(c + 50, filteredRows.length));
                    }}>
                    {(PAGINATED_TCODES.has(sel) ? evidenceRows : dispRows).length === 0 ? (
                      <div style={{ color: C.greyDim, fontSize: 12 }}>NO_RECORDS_FOR_THIS_CATEGORY</div>
                    ) : (
                      <>
                        {(PAGINATED_TCODES.has(sel) ? evidenceRows : dispRows).map((item, idx) => (
                          <div key={idx} style={{ background: C.bgCard, border: `1px solid ${C.border}`, padding: 12, position: 'relative', marginBottom: 14 }}>
                            {item._orca_row_id != null && (
                              <button onClick={() => toggleStar(item)}
                                title={item._orca_starred ? 'Unstar this evidence' : 'Star this evidence'}
                                style={{ position: 'absolute', top: -9, left: 8, background: item._orca_starred ? '#ffd700' : '#111', color: item._orca_starred ? '#000' : '#666', border: `1px solid ${item._orca_starred ? '#ffd700' : C.border}`, fontSize: 11, lineHeight: 1, padding: '2px 6px', fontWeight: 'bold', cursor: 'pointer' }}>
                                {item._orca_starred ? '★' : '☆'}
                              </button>
                            )}
                            <div style={{ position: 'absolute', top: -9, right: 8, background: C.red, color: '#fff', fontSize: 9, padding: '1px 5px', fontWeight: 'bold' }}>
                              INDEX_{(PAGINATED_TCODES.has(sel) ? evPage * EV_PAGE_SIZE + idx : idx).toString().padStart(3, '0')}
                            </div>
                            {Object.entries(item).map(([k, v]) => {
                              if (['VQLSource','_Source','_orca_fallback','_orca_fallback_note','_orca_row_id','_orca_starred'].includes(k)) return null;
                              const display = v === null || v === undefined || v === '' || v === '---' ? '---' : typeof v === 'object' ? JSON.stringify(v) : v.toString();
                              return (
                                <div key={k} style={{ display: 'flex', marginBottom: 5, borderBottom: `1px solid #0d0d0d`, paddingBottom: 3 }}>
                                  <div style={{ color: C.red, minWidth: 155, fontSize: 11, fontWeight: 'bold', flexShrink: 0 }}>{k.toUpperCase()}:</div>
                                  <div style={{ color: C.white, fontSize: 11, lineHeight: 1.4, wordBreak: 'break-word', width: '100%' }}>{display}</div>
                                </div>
                              );
                            })}
                          </div>
                        ))}
                        {/* Client-side scroll hint */}
                        {!PAGINATED_TCODES.has(sel) && visibleCount < filteredRows.length && (
                          <div style={{ textAlign: 'center', padding: '10px 0', color: C.greyDim, fontSize: 10, letterSpacing: 1 }}>
                            ↓ SCROLL FOR MORE — {filteredRows.length - visibleCount} REMAINING
                          </div>
                        )}
                      </>
                    )}
                  </div>
                  {/* Server-side pagination footer */}
                  {PAGINATED_TCODES.has(sel) && evTotal > EV_PAGE_SIZE && (
                    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, padding: '6px 12px', borderTop: `1px solid ${C.border}`, flexShrink: 0 }}>
                      <button onClick={() => loadEvidence(sel, evPage - 1, evSearch)} disabled={evPage === 0}
                        style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: evPage === 0 ? C.greyDim : C.white }}>◀ PREV</button>
                      <span style={{ color: C.greyDim, fontSize: 10 }}>
                        PAGE {evPage + 1} / {Math.ceil(evTotal / EV_PAGE_SIZE)} · {evTotal.toLocaleString()} RECORDS
                      </span>
                      <button onClick={() => loadEvidence(sel, evPage + 1, evSearch)} disabled={evPage >= Math.ceil(evTotal / EV_PAGE_SIZE) - 1}
                        style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: evPage >= Math.ceil(evTotal / EV_PAGE_SIZE) - 1 ? C.greyDim : C.white }}>NEXT ▶</button>
                    </div>
                  )}
                </>
              )}
            </Card>
          )}

          {!sel && availableCategories.size === 0 && (
            <div style={{ color: C.greyDim, fontSize: 12, padding: 20, textAlign: 'center', lineHeight: 2 }}>
              NO_ARTIFACT_DATA_FOR_THIS_ASSET<br/><span style={{ fontSize: 10 }}>Use bulk deploy on the ASSETS tab to collect</span>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// MFT VIEWER
// ══════════════════════════════════════════════════════════════════════════════

const MFT_VIEWS = ['SUSPICIOUS', 'TIMELINE', 'SEARCH', 'TREE'];

const fmt = {
  size: (b) => {
    if (!b) return '0 B';
    const units = ['B','KB','MB','GB','TB'];
    let i = 0, n = b;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
  },
  ts: (s) => s ? s.slice(0, 19).replace('T', ' ') : '—',
  path: (f) => f.p ? `${f.p}\\${f.n}` : f.n,
};

// Detect timestomping: $SI created < $FN created (attacker backdated $SI)
const isTimestomped = (f) => {
  if (!f.c || !f.c3) return false;
  return new Date(f.c) < new Date(f.c3);
};

const MftRow = ({ f, onPathClick }) => {
  const [expanded, setExpanded] = useState(false);
  const deleted    = !f.u;
  const stomped    = isTimestomped(f) || !!f.si_lt_fn;
  const isDir      = !!f.d;
  const fullPath   = f.p || f.n;
  const hasADS     = !!f.ads;
  const copied     = !!f.cp;

  const rowBg = deleted ? 'rgba(255,68,68,0.04)'
    : stomped  ? 'rgba(255,170,0,0.04)'
    : hasADS   ? 'rgba(155,89,255,0.04)'
    : 'transparent';

  const pathColor = deleted ? C.red : stomped ? C.amber : hasADS ? C.purple : C.white;

  return (
    <div style={{ borderBottom: `1px solid #0a0a0a`, background: expanded ? '#0d0d0d' : 'transparent' }}>
      <div onClick={() => setExpanded(o => !o)} style={{
        display: 'flex', alignItems: 'center', gap: 8, padding: '4px 10px',
        cursor: 'pointer', userSelect: 'none', background: rowBg,
      }}>
        <span style={{ width: 14, flexShrink: 0, fontSize: 9, textAlign: 'center' }}>
          {deleted ? <span style={{ color: C.red }}>✗</span>
            : stomped ? <span style={{ color: C.amber }}>⚠</span>
            : hasADS  ? <span style={{ color: C.purple }}>ADS</span>
            : <span style={{ color: C.greyDim, opacity: 0.3 }}>·</span>}
        </span>
        <span style={{ fontSize: 11, flexShrink: 0 }}>{isDir ? '📁' : '📄'}</span>
        <span
          onClick={e => { e.stopPropagation(); if (isDir && onPathClick) onPathClick(fullPath); }}
          style={{ flex: 1, fontSize: 11, color: pathColor, wordBreak: 'break-all',
            cursor: isDir ? 'pointer' : 'default',
            textDecoration: isDir ? 'underline' : 'none', textDecorationColor: C.greyDim }}
          title={isDir ? 'Browse this directory' : undefined}
        >
          {fullPath}
        </span>
        <span style={{ fontSize: 10, color: C.greyDim, width: 80, textAlign: 'right', flexShrink: 0 }}>
          {fmt.size(f.sz)}
        </span>
        <span style={{ fontSize: 10, color: C.greyDim, width: 140, textAlign: 'right', flexShrink: 0 }}>
          {fmt.ts(f.c)}
        </span>
      </div>

      {expanded && (
        <div style={{ padding: '6px 10px 8px 32px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '3px 20px' }}>
          {[
            ['$SI Created',      f.c,  false],
            ['$FN Created',      f.c3, stomped],
            ['$SI Modified',     f.m,  false],
            ['$FN Modified',     f.m3, false],
            ['$SI Accessed',     f.a,  false],
            ['$FN Accessed',     f.a3, false],
            ['$SI Rec.Change',   f.rc, false],
          ].map(([label, val, warn]) => (
            <div key={label} style={{ display: 'flex', gap: 8, fontSize: 10 }}>
              <span style={{ color: C.greyDim, minWidth: 110, flexShrink: 0 }}>{label}:</span>
              <span style={{ color: warn ? C.amber : C.grey }}>{fmt.ts(val)}</span>
            </div>
          ))}
          <div style={{ display: 'flex', gap: 8, fontSize: 10 }}>
            <span style={{ color: C.greyDim, minWidth: 110, flexShrink: 0 }}>Entry #:</span>
            <span style={{ color: C.grey }}>{f.e ?? '—'} {f.pe != null ? `(parent: ${f.pe})` : ''}</span>
          </div>
          <div style={{ display: 'flex', gap: 8, fontSize: 10 }}>
            <span style={{ color: C.greyDim, minWidth: 110, flexShrink: 0 }}>Status:</span>
            <span style={{ color: deleted ? C.red : C.green }}>{deleted ? 'DELETED' : 'IN_USE'}</span>
          </div>
          {(f.fn && f.fn.length > 1) && (
            <div style={{ display: 'flex', gap: 8, fontSize: 10 }}>
              <span style={{ color: C.greyDim, minWidth: 110, flexShrink: 0 }}>Alt Names:</span>
              <span style={{ color: C.grey }}>{f.fn.join(', ')}</span>
            </div>
          )}
          <div style={{ display: 'flex', gap: 16, fontSize: 10, gridColumn: '1/-1', marginTop: 2 }}>
            {hasADS && <span style={{ color: C.purple }}>⚑ HAS_ADS</span>}
            {copied  && <span style={{ color: C.greyDim }}>COPIED</span>}
          </div>
          {stomped && (
            <div style={{ gridColumn: '1/-1', marginTop: 4, padding: '4px 8px',
              background: 'rgba(255,170,0,0.08)', border: `1px solid ${C.amber}`,
              color: C.amber, fontSize: 10 }}>
              ⚠ TIMESTOMP DETECTED — $SI timestamps inconsistent with $FN
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const MftViewer = ({ assetId }) => {
  const [view, setView]           = useState('SUSPICIOUS');
  const [results, setResults]     = useState([]);
  const [total, setTotal]         = useState(0);
  const [fileCount, setFileCount] = useState(0);
  const [page, setPage]           = useState(0);
  const [loading, setLoading]     = useState(false);
  const [search, setSearch]       = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [pathPrefix, setPathPrefix]   = useState('');
  const [pathHistory, setPathHistory] = useState([]);
  const [deletedOnly, setDeletedOnly]     = useState(false);
  const [timestompOnly, setTimestompOnly] = useState(false);
  const [adsOnly, setAdsOnly]             = useState(false);
  const [dateFrom, setDateFrom]   = useState('');
  const [dateTo, setDateTo]       = useState('');
  const PAGE_SIZE = 200;

  const fetchResults = async (v, p, s, prefix, df, dt, del, ts, ads) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        view: v.toLowerCase(), page: p, page_size: PAGE_SIZE,
        search: s, path_prefix: prefix,
        date_from: df, date_to: dt,
        deleted_only: del, include_dirs: v === 'TREE',
        timestomp_only: ts || false,
        ads_only: ads || false,
      });
      const r = await fetch(
        `${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/mft/query?${params}`,
        { headers: getAuth() }
      );
      const d = await r.json();
      setResults(d.results || []);
      setTotal(d.total || 0);
      setFileCount(d.file_count || 0);
    } catch { setResults([]); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchResults(view, page, search, pathPrefix, dateFrom, dateTo, deletedOnly, timestompOnly, adsOnly);
  }, [view, page, search, pathPrefix, dateFrom, dateTo, deletedOnly, timestompOnly, adsOnly]);

  const switchView = (v) => {
    setView(v); setPage(0); setSearch(''); setSearchInput('');
    setPathPrefix(''); setPathHistory([]); setDeletedOnly(false);
    setTimestompOnly(false); setAdsOnly(false);
  };

  const browseDir = (path) => {
    if (view !== 'TREE') { setView('TREE'); }
    setPathHistory(h => [...h, pathPrefix]);
    setPathPrefix(path);
    setPage(0);
  };

  const navigateUp = () => {
    const prev = pathHistory[pathHistory.length - 1] ?? '';
    setPathHistory(h => h.slice(0, -1));
    setPathPrefix(prev);
    setPage(0);
  };

  const commitSearch = () => { setSearch(searchInput); setPage(0); };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: C.bgHeader, flexWrap: 'wrap' }}>

        {/* View tabs */}
        <div style={{ display: 'flex', gap: 3 }}>
          {MFT_VIEWS.map(v => (
            <button key={v} onClick={() => switchView(v)} style={{
              ...Btn, padding: '3px 10px', fontSize: 10,
              background: view === v ? C.red : 'transparent',
              color: view === v ? '#000' : C.greyDim,
              border: `1px solid ${view === v ? C.red : C.border}`,
            }}>{v}</button>
          ))}
        </div>

        <span style={{ color: C.greyDim, fontSize: 9 }}>·</span>
        <span style={{ color: C.greyDim, fontSize: 9 }}>{fileCount.toLocaleString()} FILES</span>
        {total > 0 && <span style={{ color: C.red, fontSize: 9 }}>{total.toLocaleString()} MATCHING</span>}

        {/* Filter buttons */}
        <div style={{ display: 'flex', gap: 3, marginLeft: 4 }}>
          {[
            { key: 'del',  label: '✗ DELETED',    active: deletedOnly,    color: C.red,    toggle: () => { setDeletedOnly(d => !d); setTimestompOnly(false); setAdsOnly(false); setPage(0); } },
            { key: 'ts',   label: '⚠ TIMESTOMP',  active: timestompOnly,  color: C.amber,  toggle: () => { setTimestompOnly(t => !t); setDeletedOnly(false); setAdsOnly(false); setPage(0); } },
            { key: 'ads',  label: '⚑ ADS',         active: adsOnly,        color: '#9b59ff', toggle: () => { setAdsOnly(a => !a); setDeletedOnly(false); setTimestompOnly(false); setPage(0); } },
            { key: 'norm', label: '· NORMAL',      active: !deletedOnly && !timestompOnly && !adsOnly, color: C.greyDim,
              toggle: () => { setDeletedOnly(false); setTimestompOnly(false); setAdsOnly(false); setPage(0); } },
          ].map(({ key, label, active, color, toggle }) => (
            <button key={key} onClick={toggle} style={{
              ...Btn, padding: '3px 10px', fontSize: 10,
              background: active ? color : 'transparent',
              color: active ? (color === C.amber || color === '#9b59ff' ? '#000' : '#000') : color,
              border: `1px solid ${active ? color : C.border}`,
            }}>{label}</button>
          ))}
        </div>

        {/* Date range — timeline only */}
        {view === 'TIMELINE' && (
          <>
            <input placeholder="FROM (YYYY-MM-DD)" value={dateFrom}
              onChange={e => { setDateFrom(e.target.value); setPage(0); }}
              style={{ ...Inp, width: 130, fontSize: 10 }} />
            <input placeholder="TO (YYYY-MM-DD)" value={dateTo}
              onChange={e => { setDateTo(e.target.value); setPage(0); }}
              style={{ ...Inp, width: 130, fontSize: 10 }} />
          </>
        )}

        {/* Search — search view */}
        {view === 'SEARCH' && (
          <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
            <input placeholder="FILENAME / PATH..." value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && commitSearch()}
              style={{ ...Inp, width: 240 }} />
            <button onClick={commitSearch} style={Btn}>SEARCH</button>
          </div>
        )}

        {/* Tree breadcrumb */}
        {view === 'TREE' && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
            {pathHistory.length > 0 && (
              <button onClick={navigateUp} style={{ ...Btn, background: 'transparent',
                border: `1px solid ${C.border}`, color: C.greyDim, padding: '3px 8px', fontSize: 10 }}>
                ↑ UP
              </button>
            )}
            <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>
              {pathPrefix ? `C:\\${pathPrefix}` : 'C:\\'}
            </span>
          </div>
        )}
      </div>

      {/* Column headers */}
      <div style={{ display: 'flex', padding: '3px 10px', background: '#0a0a0a',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, fontSize: 9, color: C.greyDim, letterSpacing: 1 }}>
        <span style={{ width: 14, flexShrink: 0 }} />
        <span style={{ width: 20, flexShrink: 0 }} />
        <span style={{ flex: 1 }}>PATH</span>
        <span style={{ width: 80, textAlign: 'right', flexShrink: 0 }}>SIZE</span>
        <span style={{ width: 140, textAlign: 'right', flexShrink: 0 }}>CREATED ($SI)</span>
      </div>

      {/* Legend hint */}
      <div style={{ display: 'flex', padding: '3px 10px', background: '#050505',
        borderBottom: `1px solid #0a0a0a`, flexShrink: 0, fontSize: 9 }}>
        <span style={{ color: C.greyDim, marginLeft: 'auto' }}>CLICK ROW FOR TIMESTAMPS · CLICK 📁 TO BROWSE</span>
      </div>

      {/* Results */}
      <div style={{ flex: 1, overflowY: 'auto', fontFamily: 'monospace' }}>
        {loading ? (
          <div style={{ color: C.green, fontSize: 12, padding: 16 }}>QUERYING_MFT...</div>
        ) : results.length === 0 ? (
          <div style={{ color: C.greyDim, fontSize: 12, padding: 16 }}>
            {view === 'SEARCH' && !search ? 'ENTER_SEARCH_TERM_ABOVE' : 'NO_RESULTS'}
          </div>
        ) : (
          results.map((f, i) => (
            <MftRow key={`${f.e}-${f.n}-${i}`} f={f} onPathClick={browseDir} />
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px',
          borderTop: `1px solid ${C.border}`, flexShrink: 0, background: C.bgHeader }}>
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
            style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`,
              color: page === 0 ? C.greyDim : C.white, padding: '3px 10px', fontSize: 10 }}>◀ PREV</button>
          <span style={{ color: C.greyDim, fontSize: 10 }}>
            PAGE {page + 1} / {totalPages} &nbsp;·&nbsp; {total.toLocaleString()} RESULTS
          </span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`,
              color: page >= totalPages - 1 ? C.greyDim : C.white, padding: '3px 10px', fontSize: 10 }}>NEXT ▶</button>
        </div>
      )}
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// REGISTRY TREE VIEWER
// ══════════════════════════════════════════════════════════════════════════════

const REGISTRY_TCODES = new Set([
  'REGISTRY',
  'REGISTRY_CLASSES_ROOT', 'REGISTRY_CURRENT_CONFIG',
  'REGISTRY_NTUSER', 'REGISTRY_SAM', 'REGISTRY_SECURITY',
  'REGISTRY_SOFTWARE', 'REGISTRY_SYSTEM', 'REGISTRY_USRCLASS',
]);

const HIVE_ORDER = ['HKEY_CLASSES_ROOT','HKEY_CURRENT_USER','HKEY_LOCAL_MACHINE','HKEY_USERS','HKEY_CURRENT_CONFIG'];

// Pre-compute which paths contain a search match — runs once per search change at top level.
// Returns a Set of path strings (e.g. "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft") that either
// match directly or have a descendant that matches. O(n) single pass, no per-node stringify.
function buildMatchSet(node, term, path = '', result = new Set()) {
  if (!term) return result;
  const nameLower = path.split('\\').pop().toLowerCase();
  let selfMatch = nameLower.includes(term);

  // Check values at this node
  const values = node._values || [];
  for (const val of values) {
    const vn = (val.Name || val.name || '').toLowerCase();
    const vd = String(val.Data ?? val.data ?? '').toLowerCase();
    if (vn.includes(term) || vd.includes(term)) { selfMatch = true; break; }
  }

  let childMatch = false;
  for (const k of Object.keys(node)) {
    if (k === '_values' || k === '_meta') continue;
    const childPath = path ? `${path}\\${k}` : k;
    buildMatchSet(node[k], term, childPath, result);
    if (result.has(childPath)) childMatch = true;
  }

  if (selfMatch || childMatch) result.add(path);
  return result;
}

const RegTreeNode = ({ name, node, depth, path, matchSet, searching }) => {
  const childKeys  = Object.keys(node).filter(k => k !== '_values' && k !== '_meta');
  const values     = node._values || [];
  const modtime    = node._meta?.modtime || '';
  const hasChildren = childKeys.length > 0;
  const hasValues   = values.length > 0;

  // When searching: open if this path is in matchSet. When not searching: everything collapsed.
  const shouldOpen  = searching ? matchSet.has(path) : false;
  const [open, setOpen] = useState(shouldOpen);

  // Sync open state when search changes without re-mounting
  useEffect(() => { setOpen(shouldOpen); }, [shouldOpen]);

  const indent     = depth * 14;
  const nameMatch  = searching && matchSet.has(path) && name.toLowerCase().includes(
    /* only highlight if name itself matches, not just a descendant */ ''
  );
  const directMatch = searching && (() => {
    const nl = name.toLowerCase();
    // extract term from matchSet path isn't available here; just highlight if in set and is leaf or has values
    return matchSet.has(path);
  })();

  return (
    <div>
      <div
        onClick={() => (hasChildren || hasValues) && setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 5,
          paddingLeft: indent + 6, paddingTop: 3, paddingBottom: 3, paddingRight: 6,
          cursor: (hasChildren || hasValues) ? 'pointer' : 'default',
          background: searching && matchSet.has(path) ? 'rgba(255,170,0,0.07)' : 'transparent',
          borderBottom: '1px solid #080808',
          userSelect: 'none',
        }}
        title={modtime ? `Modified: ${modtime}` : undefined}
      >
        <span style={{ color: C.greyDim, fontSize: 10, width: 10, flexShrink: 0, textAlign: 'center' }}>
          {hasChildren ? (open ? '▼' : '▶') : ' '}
        </span>
        <span style={{ fontSize: 11, marginRight: 2 }}>
          {hasChildren ? (open ? '📂' : '📁') : '🔑'}
        </span>
        <span style={{ fontSize: 11, color: searching && matchSet.has(path) ? C.amber : C.white,
          fontWeight: depth === 0 ? 'bold' : 'normal', wordBreak: 'break-all' }}>
          {name}
        </span>
        {hasValues && <span style={{ fontSize: 9, color: C.purple, marginLeft: 4 }}>[{values.length}]</span>}
        {modtime && (
          <span style={{ fontSize: 9, color: C.greyDim, marginLeft: 'auto', flexShrink: 0, paddingLeft: 8 }}>
            {modtime.slice(0, 10)}
          </span>
        )}
      </div>

      {open && (
        <div>
          {hasValues && values.map((val, i) => {
            const valName = val.Name || val.name || '(Default)';
            const valType = val.Type || val.type || '';
            const valData = val.Data !== undefined ? val.Data : (val.data !== undefined ? val.data : '');
            const valStr  = typeof valData === 'object' ? JSON.stringify(valData) : String(valData ?? '');
            return (
              <div key={i} style={{
                display: 'flex', alignItems: 'baseline', gap: 8,
                paddingLeft: indent + 32, paddingTop: 2, paddingBottom: 2, paddingRight: 8,
                borderBottom: '1px solid #060606', background: '#020202',
              }}>
                <span style={{ fontSize: 10, color: C.amber, minWidth: 160, flexShrink: 0, wordBreak: 'break-all' }}>{valName}</span>
                <span style={{ fontSize: 9, color: C.purple, minWidth: 80, flexShrink: 0 }}>{valType}</span>
                <span style={{ fontSize: 10, color: C.grey, wordBreak: 'break-all' }}>{valStr || '(empty)'}</span>
              </div>
            );
          })}
          {childKeys.sort((a, b) => a.localeCompare(b)).map(k => (
            <RegTreeNode key={k} name={k} node={node[k]}
              depth={depth + 1} path={path ? `${path}\\${k}` : k}
              matchSet={matchSet} searching={searching} />
          ))}
        </div>
      )}
    </div>
  );
};

const RegistryTreeViewer = ({ rows }) => {
  const [search, setSearch]     = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const debounceRef = useRef(null);

  // Debounce search input — don't recompute matchSet on every keystroke
  const handleSearch = (val) => {
    setSearch(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setDebouncedSearch(val.toLowerCase().trim()), 400);
  };

  const treeDoc  = rows[0] || {};
  const hives    = treeDoc.hives || [];
  const tree     = treeDoc.tree || {};
  const keyCount = treeDoc.key_count || 0;

  const rootKeys = Object.keys(tree).sort((a, b) => {
    const ai = HIVE_ORDER.indexOf(a), bi = HIVE_ORDER.indexOf(b);
    if (ai === -1 && bi === -1) return a.localeCompare(b);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  // Pre-compute match set once per debounced search — not on every render
  const matchSet = useMemo(() => {
    if (!debouncedSearch) return new Set();
    const result = new Set();
    for (const k of rootKeys) buildMatchSet(tree[k], debouncedSearch, k, result);
    return result;
  }, [debouncedSearch, tree]);

  const searching = !!debouncedSearch;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, background: C.bgHeader }}>
        <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>
          HIVES: <span style={{ color: C.white }}>{hives.length > 0 ? hives.join(', ') : '—'}</span>
        </span>
        <span style={{ color: C.greyDim, fontSize: 9 }}>· {keyCount.toLocaleString()} KEYS</span>
        {searching && <span style={{ fontSize: 9, color: C.amber }}>{matchSet.size} MATCHES</span>}
        <input placeholder="SEARCH KEYS / VALUES..." value={search}
          onChange={e => handleSearch(e.target.value)}
          style={{ ...Inp, marginLeft: 'auto', width: 240 }} />
        {search && (
          <button onClick={() => { setSearch(''); setDebouncedSearch(''); }}
            style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.greyDim, padding: '4px 8px' }}>
            CLR
          </button>
        )}
      </div>

      <div style={{ display: 'flex', padding: '3px 6px', background: '#0a0a0a',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, fontSize: 9, color: C.greyDim, letterSpacing: 1 }}>
        <span style={{ flex: 1 }}>KEY / VALUE_NAME</span>
        <span style={{ width: 80, flexShrink: 0 }}>TYPE</span>
        <span style={{ width: 200, flexShrink: 0 }}>DATA</span>
        <span style={{ width: 80, flexShrink: 0, textAlign: 'right' }}>MODIFIED</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', fontFamily: 'monospace' }}>
        {rootKeys.length === 0
          ? <div style={{ color: C.greyDim, fontSize: 11, padding: 20 }}>NO_TREE_DATA</div>
          : rootKeys.map(k => (
              <RegTreeNode key={k} name={k} node={tree[k]}
                depth={0} path={k} matchSet={matchSet} searching={searching} />
            ))
        }
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// MEMORY ANALYSIS TAB
// ══════════════════════════════════════════════════════════════════════════════
const MemoryAnalysisTab = ({ assetId, onSummaryUpdate, collab, analysisMode = 'UNKNOWN', localDir = null }) => {
  const [mode, setMode]                     = useState('single');
  const [os, setOs]                         = useState('windows');
  const [imgPath, setImgPath]               = useState('');
  const [symPaths, setSymPaths]             = useState('');
  const [selectedPlugins, setSelectedPlugins] = useState(new Set(['windows.pslist']));
  const [pluginArgs, setPluginArgs]         = useState('');
  const [actor, setActor]                   = useState(THREAT_ACTORS[0]);
  const [openGroup, setOpenGroup]           = useState('Process Analysis');
  const [yaraPath, setYaraPath]             = useState('');
  const [isRunning, setIsRunning]           = useState(false);
  const [columns, setColumns]               = useState([]);
  const [rows, setRows]                     = useState([]);
  const [sections, setSections]             = useState({});   // multi-plugin results
  const [activeSection, setActiveSection]   = useState(null);
  const [logs, setLogs]                     = useState([]);
  const [filter, setFilter]                 = useState('');
  const [expandedT, setExpandedT]           = useState(null);
  // Acquire
  const [acquireDest, setAcquireDest]       = useState('C:\\memory_dump.raw');
  const [isAcquiring, setIsAcquiring]       = useState(false);
  const [acquireLogs, setAcquireLogs]       = useState([]);
  // Dump
  const [dumpPid, setDumpPid]               = useState('');
  const [dumpDest, setDumpDest]             = useState('C:\\dumps\\');
  const [isDumping, setIsDumping]           = useState(false);
  const readerRef = useRef(null);
  const evtSourceRef = useRef(null);
  const [agents, setAgents]               = useState([]);
  const [selectedAgent, setSelectedAgent] = useState(null);
  const [browseOpen, setBrowseOpen]       = useState(false);
  const [browseFiles, setBrowseFiles]     = useState([]);
  const [browseLoading, setBrowseLoading] = useState(false);

  // Load persisted results on mount
  useEffect(() => {
    if (!assetId) return;
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/results/${assetId}`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(data => {
        if (!data || !data.length) return;
        const rebuilt = {};
        let totalRows = 0, lastPlugin = null;
        data.forEach(p => {
          rebuilt[p.plugin] = { columns: p.columns || [], rows: p.rows || [] };
          totalRows += p.row_count || 0;
          lastPlugin = p.plugin;
        });
        setSections(rebuilt);
        setActiveSection(data[0]?.plugin || null);
        if (onSummaryUpdate) onSummaryUpdate('memory', { pluginsRun: data.length, totalRows, lastPlugin });
        addLog(`Restored ${data.length} plugin result(s) from database.`, 'success');
      }).catch(() => {});
  }, [assetId]);

  // Auto-populate image path from the asset's local working directory
  useEffect(() => {
    if (!localDir || imgPath) return;
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/list-images?dir=${encodeURIComponent(localDir)}`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(files => {
        const inDir = files.filter(f => f.dir === localDir);
        if (inDir.length === 1) setImgPath(inDir[0].path);   // exactly one image — fill it in
        else if (inDir.length > 1) setImgPath(localDir);     // multiple — set dir as hint, user picks via BROWSE
        else setImgPath(localDir);                            // none yet — set dir as hint
      })
      .catch(() => setImgPath(localDir));
  }, [localDir]);

  useEffect(() => {
    if (analysisMode !== 'DEAD_DISK_LOCAL') return;
    fetch(`${import.meta.env.VITE_API_URL}/api/agent/list`, { headers: getAuth() })
      .then(r => r.json())
      .then(data => setAgents(data.filter(a => a.status === 'ONLINE')))
      .catch(() => {});
  }, [analysisMode]);

  const VOL3 = 'C:\\Users\\Sentinel\\Desktop\\Tests\\ORCAWEB\\backend\\bin\\remora\\volatility3';
  const addLog = (m, type = 'info') => setLogs(p => [{ t: ts(), m, type }, ...p].slice(0, 400));
  const stopStream = () => {
    try { readerRef.current?.cancel(); } catch {} readerRef.current = null;
    // The dispatch-to-agent path's EventSource was never stored anywhere,
    // so STOP had no way to actually close it -- results kept streaming in
    // and mutating state after the UI had already reverted to idle.
    try { evtSourceRef.current?.close(); } catch {} evtSourceRef.current = null;
    setIsRunning(false);
  };

  const handleDispatchToAgent = async () => {
    if (!imgPath.trim()) { addLog('MEMORY_IMAGE path required.', 'error'); return; }
    if (selectedPlugins.size === 0) { addLog('Select at least one plugin.', 'error'); return; }
    setIsRunning(true); setLogs([]); setSections({}); setActiveSection(null);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/agent/dispatch`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({
          agent_id: selectedAgent,
          job_type: 'memory',
          params: { image_path: imgPath, profile: os, plugins: [...selectedPlugins], asset_id: Number(assetId) }
        })
      });
      const { job_id } = await r.json();
      addLog(`Job dispatched to agent: ${job_id}`);
      const evtSource = new EventSource(
        `${import.meta.env.VITE_API_URL}/api/agent/jobs/${job_id}/stream`
      );
      evtSourceRef.current = evtSource;
      let pluginsRun = 0, totalRows = 0, curPlugin = null;
      evtSource.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.type === 'log') addLog(evt.data.message || String(evt.data));
          else if (evt.type === 'row') {
            try {
              const row = typeof evt.data.row === 'string' ? JSON.parse(evt.data.row) : evt.data.row;
              const plugin = evt.data.plugin || curPlugin;
              totalRows++;
              setSections(p => ({ ...p, [plugin]: { columns: Object.keys(row), rows: [...(p[plugin]?.rows || []), row] } }));
              setActiveSection(plugin);
            } catch {}
          }
          else if (evt.type === 'plugin_done') {
            curPlugin = evt.data.plugin; pluginsRun++;
            addLog(`✓ ${evt.data.plugin} — ${evt.data.rows} rows`, 'success');
          }
          else if (evt.type === 'error') addLog(evt.data.message || String(evt.data), 'error');
          else if (evt.type === 'done') {
            addLog('AGENT SCAN COMPLETE', 'success'); setIsRunning(false);
            if (onSummaryUpdate) onSummaryUpdate('memory', { pluginsRun, totalRows, lastPlugin: curPlugin });
            evtSource.close(); evtSourceRef.current = null;
          }
        } catch {}
      };
      evtSource.onerror = () => { addLog('Agent connection lost.', 'error'); setIsRunning(false); evtSource.close(); evtSourceRef.current = null; };
    } catch (e) { addLog('DISPATCH_ERROR: ' + e.message, 'error'); setIsRunning(false); }
  };

  const togglePlugin = (p) => setSelectedPlugins(prev => {
    const n = new Set(prev); n.has(p) ? n.delete(p) : n.add(p); return n;
  });
  const selectGroup = (grp) => {
    const ps = (VOL_PLUGINS[os] || {})[grp] || [];
    setSelectedPlugins(prev => { const n = new Set(prev); ps.forEach(p => n.add(p)); return n; });
  };
  const clearGroup = (grp) => {
    const ps = (VOL_PLUGINS[os] || {})[grp] || [];
    setSelectedPlugins(prev => { const n = new Set(prev); ps.forEach(p => n.delete(p)); return n; });
  };

  const handleRun = async () => {
    if (!imgPath.trim()) { addLog('CRITICAL: Memory image path required.', 'error'); return; }
    if (mode === 'single' && selectedPlugins.size === 0) { addLog('CRITICAL: Select at least one plugin.', 'error'); return; }

    // ── TOOL LOCK CHECK ──
    if (collab) {
      const lockResult = await collab.acquireToolLock(assetId, 'volatility');
      if (lockResult.status === 'LOCKED') {
        addLog(`BLOCKED: Volatility is running for this asset by ${lockResult.locked_by} — wait for completion.`, 'error');
        return;
      }
    }
    // ── END TOOL LOCK ──

    stopStream();
    setIsRunning(true); setColumns([]); setRows([]); setSections({}); setActiveSection(null); setLogs([]);

    const args = [];
    if (yaraPath && mode === 'single') args.push('--yara-file', yaraPath);
    if (pluginArgs) args.push(...pluginArgs.split(' ').filter(Boolean));

    let endpoint, body;
    if (mode === 'single') {
      endpoint = '/api/mitre/memory/run';
      body = { asset_id: String(assetId), image_path: imgPath, plugins: [...selectedPlugins], os_profile: os, symbol_paths: symPaths || null, args, vol3_base: VOL3 };
    } else if (mode === 'full') {
      endpoint = '/api/mitre/memory/fullscan';
      body = { asset_id: String(assetId), image_path: imgPath, os_profile: os, symbol_paths: symPaths || null, vol3_base: VOL3 };
    } else {
      endpoint = '/api/mitre/memory/actorscan';
      body = { asset_id: String(assetId), image_path: imgPath, actor_name: actor, os_profile: os, symbol_paths: symPaths || null, vol3_base: VOL3 };
    }

    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}${endpoint}`, { method: 'POST', headers: getAuth(), body: JSON.stringify(body) });
      if (!resp.ok) { const e = await resp.json(); addLog('BACKEND: ' + (e.detail || resp.statusText), 'error'); setIsRunning(false); return; }
      const reader = resp.body.getReader(); readerRef.current = reader;
      const dec = new TextDecoder();
      let buf = '', curPlugin = null, curCols = [], curRows = [], totalRows = 0, pluginsRun = 0;

      const flush = (plugin, cols, rows) => { if (!plugin) return; setSections(p => ({ ...p, [plugin]: { columns: cols, rows: [...rows] } })); };
      const handle = (line) => {
        if (!line.startsWith('data: ')) return;
        try {
          const evt = JSON.parse(line.slice(6));
          if (evt.type === 'log') addLog(evt.data);
          else if (evt.type === 'error') addLog(evt.data, 'error');
          else if (evt.type === 'columns') { curCols = evt.data; }
          else if (evt.type === 'row') { totalRows++; curRows.push(evt.data); }
          else if (evt.type === 'plugin_start') { flush(curPlugin, curCols, curRows); curPlugin = evt.data; curCols = []; curRows = []; pluginsRun++; addLog(`Running: ${evt.data}`); setActiveSection(evt.data); }
          else if (evt.type === 'plugin_done') { flush(curPlugin, curCols, curRows); addLog(`✓ ${evt.data.plugin} — ${evt.data.rows} rows`, 'success'); }
          else if (evt.type === 'plugin_error') addLog(`✗ ${evt.data.plugin}: ${evt.data.error}`, 'error');
          else if (evt.type === 'done') {
            flush(curPlugin, curCols, curRows); addLog('SCAN COMPLETE', 'success'); setIsRunning(false);
            if (onSummaryUpdate) onSummaryUpdate('memory', { pluginsRun, totalRows, lastPlugin: curPlugin });
            setTimeout(() => {
              setSections(s => {
                const plugins = Object.entries(s).map(([plugin, data]) => ({ plugin, columns: data.columns || [], rows: (data.rows || []).slice(0, 5000) }));
                if (plugins.length) fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/results/save`, { method: 'POST', headers: getAuth(), body: JSON.stringify({ asset_id: Number(assetId), image_path: imgPath, plugins }) }).catch(() => {});
                return s;
              });
            }, 500);
          }
        } catch {}
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) { setIsRunning(false); break; }
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(handle);
      }
    } catch (e) { addLog('STREAM_ERROR: ' + e.message, 'error'); setIsRunning(false); }
    finally { if (collab) collab.releaseToolLock(assetId, 'volatility'); }
  };

  const handleAcquire = async () => {
    if (!acquireDest.trim()) return;
    setIsAcquiring(true); setAcquireLogs([]);
    const aLog = (m, type = 'info') => setAcquireLogs(p => [{ t: ts(), m, type }, ...p]);
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/acquire`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({ asset_id: String(assetId), destination_path: acquireDest, winpmem_base: VOL3 })
      });
      if (!resp.ok) { const e = await resp.json(); aLog('ERROR: ' + (e.detail || resp.statusText), 'error'); setIsAcquiring(false); return; }
      const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) { setIsAcquiring(false); break; }
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(line => {
          if (!line.startsWith('data: ')) return;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'log') aLog(evt.data);
            else if (evt.type === 'done') { aLog(`✓ Acquired: ${evt.data.path} (${evt.data.size_mb} MB)`, 'success'); setImgPath(evt.data.path); setIsAcquiring(false); }
            else if (evt.type === 'error') { aLog(evt.data, 'error'); setIsAcquiring(false); }
          } catch {}
        });
      }
    } catch (e) { aLog('STREAM_ERROR: ' + e.message, 'error'); setIsAcquiring(false); }
  };

  const handleDump = async () => {
    if (!imgPath || !dumpPid) { addLog('Need image path and PID to dump.', 'error'); return; }
    setIsDumping(true);
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/dump`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({ asset_id: String(assetId), image_path: imgPath, pid: parseInt(dumpPid), destination_path: dumpDest, vol3_base: VOL3 })
      });
      if (!resp.ok) { const e = await resp.json(); addLog('DUMP_ERROR: ' + (e.detail || resp.statusText), 'error'); setIsDumping(false); return; }
      const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) { setIsDumping(false); break; }
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(line => {
          if (!line.startsWith('data: ')) return;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'log') addLog(evt.data);
            else if (evt.type === 'done') { addLog(`✓ PID ${evt.data.pid} dumped → ${evt.data.dest}`, 'success'); setIsDumping(false); }
            else if (evt.type === 'error') { addLog(evt.data, 'error'); setIsDumping(false); }
          } catch {}
        });
      }
    } catch (e) { addLog('DUMP_ERROR: ' + e.message, 'error'); setIsDumping(false); }
  };

  const openBrowse = () => {
    setBrowseOpen(true);
    setBrowseLoading(true);
    setBrowseFiles([]);
    const dirParam = localDir ? `?dir=${encodeURIComponent(localDir)}` : '';
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/memory/list-images${dirParam}`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(data => { setBrowseFiles(data); setBrowseLoading(false); })
      .catch(() => setBrowseLoading(false));
  };

  const pluginGroups = VOL_PLUGINS[os] || VOL_PLUGINS.windows;
  // Replace lines 810-812
  const dispCols = (activeSection && sections[activeSection]?.columns) || [];
  const dispRows = ((activeSection && sections[activeSection]?.rows) || [])
  . filter(r => Object.values(r).some(v => String(v ?? '').toLowerCase().includes(filter.toLowerCase())));

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

      {/* Plugin sidebar */}
      <div style={{ width: 210, background: C.bg, borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
        <div style={{ padding: '5px 10px', fontSize: 9, color: C.greyDim, borderBottom: `1px solid #0a0a0a`, letterSpacing: 1 }}>PLUGIN_LIBRARY</div>
        <div style={{ padding: '5px 8px', borderBottom: `1px solid #0a0a0a` }}>
          <select value={os} onChange={e => { setOs(e.target.value); setSelectedPlugins(new Set()); setOpenGroup(Object.keys(VOL_PLUGINS[e.target.value])[0]); }}
            style={{ ...Inp, width: '100%' }}>
            <option value="windows">Windows</option>
            <option value="linux">Linux</option>
            <option value="mac">macOS</option>
          </select>
        </div>
        {mode === 'single' && (
          <div style={{ padding: '4px 10px', borderBottom: `1px solid #0a0a0a`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: C.greyDim, fontSize: 9 }}>{selectedPlugins.size} selected</span>
            <span onClick={() => setSelectedPlugins(new Set())} style={{ color: C.red, fontSize: 9, cursor: 'pointer' }}>CLEAR ALL</span>
          </div>
        )}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {Object.entries(pluginGroups).map(([grp, plugins]) => (
            <div key={grp}>
              <div onClick={() => setOpenGroup(openGroup === grp ? null : grp)}
                style={{ padding: '6px 10px', fontSize: 9, color: C.grey, cursor: 'pointer', borderBottom: `1px solid #0a0a0a`,
                  fontWeight: 'bold', userSelect: 'none', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>{openGroup === grp ? '▼' : '▶'} {grp.toUpperCase()}</span>
                {mode === 'single' && openGroup === grp && (
                  <span onClick={e => { e.stopPropagation(); selectGroup(grp); }}
                    style={{ fontSize: 8, color: C.green, cursor: 'pointer', marginLeft: 4 }}>ALL</span>
                )}
              </div>
              {openGroup === grp && plugins.map(p => {
                const checked = selectedPlugins.has(p);
                return (
                  <div key={p} onClick={() => mode === 'single' && togglePlugin(p)}
                    style={{ padding: '5px 10px 5px 14px', fontSize: 10, cursor: mode === 'single' ? 'pointer' : 'default',
                      borderLeft: `2px solid ${checked ? C.green : 'transparent'}`,
                      color: checked ? C.green : C.greyDim,
                      background: checked ? 'rgba(0,255,65,0.04)' : 'transparent',
                      borderBottom: `1px solid #0a0a0a`, fontFamily: 'monospace',
                      display: 'flex', alignItems: 'center', gap: 7 }}>
                    {mode === 'single' && (
                      <div style={{ width: 10, height: 10, border: `1px solid ${checked ? C.green : C.border}`,
                        background: checked ? C.green : 'transparent', flexShrink: 0 }} />
                    )}
                    {p.split('.').pop()}
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Main panel */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Mode tabs + config */}
        <div style={{ background: C.bg, borderBottom: `1px solid ${C.border}`, padding: '10px 15px', flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
            {[['single', 'SINGLE / MULTI'], ['full', 'FULL_SCAN'], ['actor', 'ACTOR_SCAN'], ['acquire', 'ACQUIRE']].map(([m, lbl]) => (
              <button key={m} onClick={() => setMode(m)}
                style={{ padding: '4px 12px', fontSize: 9, fontFamily: 'monospace', fontWeight: 'bold', cursor: 'pointer',
                  background: mode === m ? C.green : 'transparent', color: mode === m ? '#000' : C.greyDim,
                  border: `1px solid ${mode === m ? C.green : C.border}` }}>
                {lbl}
              </button>
            ))}
          </div>

          {mode !== 'acquire' && (
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
              <div style={{ flex: 2, display: 'flex', flexDirection: 'column', gap: 7 }}>
                {/* Image path */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={Lbl}>MEMORY_IMAGE:</span>
                    <input value={imgPath} onChange={e => setImgPath(e.target.value)}
                      placeholder="/app/memory-dumps/dump.raw"
                      style={{ ...Inp, flex: 1 }} />
                    <button onClick={openBrowse}
                      style={{ ...Btn, background: 'transparent', color: C.green, border: `1px solid ${C.green}`, padding: '4px 10px', fontSize: 9 }}>
                      BROWSE
                    </button>
                  </div>
                  {browseOpen && (
                    <div style={{ border: `1px solid ${C.border}`, background: C.bgCard, marginLeft: 123 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        padding: '4px 8px', borderBottom: `1px solid ${C.border}` }}>
                        <span style={{ color: C.greyDim, fontSize: 9, fontFamily: 'monospace' }}>
                          FILES IN /app/memory-dumps
                        </span>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          <span onClick={openBrowse} style={{ color: C.amber, fontSize: 9, cursor: 'pointer', fontFamily: 'monospace' }}>↺ REFRESH</span>
                          <span onClick={() => setBrowseOpen(false)} style={{ color: C.greyDim, fontSize: 9, cursor: 'pointer', fontFamily: 'monospace' }}>✕</span>
                        </div>
                      </div>
                      {browseLoading && (
                        <div style={{ padding: '8px', color: C.greyDim, fontSize: 9, fontFamily: 'monospace' }}>Scanning...</div>
                      )}
                      {!browseLoading && browseFiles.length === 0 && (
                        <div style={{ padding: '8px 10px', color: C.greyDim, fontSize: 9, fontFamily: 'monospace', lineHeight: 1.6 }}>
                          No image files found.<br />
                          Copy your dump into <span style={{ color: C.white }}>.\memory-dumps\</span> on the host,<br />
                          then click Refresh.
                        </div>
                      )}
                      {browseFiles.map(f => (
                        <div key={f.path} onClick={() => { setImgPath(f.path); setBrowseOpen(false); }}
                          style={{ padding: '5px 10px', cursor: 'pointer', borderBottom: `1px solid #0a0a0a`,
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                          onMouseEnter={e => e.currentTarget.style.background = C.bgHover}
                          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                          <span style={{ color: C.white, fontSize: 10, fontFamily: 'monospace' }}>{f.filename}</span>
                          <span style={{ color: C.greyDim, fontSize: 9, fontFamily: 'monospace', flexShrink: 0, marginLeft: 12 }}>
                            {f.size >= 1073741824 ? (f.size / 1073741824).toFixed(1) + ' GB'
                              : f.size >= 1048576 ? (f.size / 1048576).toFixed(0) + ' MB'
                              : (f.size / 1024).toFixed(0) + ' KB'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={Lbl}>SYMBOL_PATHS:</span>
                  <input value={symPaths} onChange={e => setSymPaths(e.target.value)} placeholder="optional"
                    style={{ ...Inp, flex: 1 }} />
                </div>
                {mode === 'single' && (
                  <>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={Lbl}>PLUGIN_ARGS:</span>
                      <input value={pluginArgs} onChange={e => setPluginArgs(e.target.value)} placeholder="e.g. --pid 1234"
                        style={{ ...Inp, flex: 1 }} />
                    </div>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={Lbl}>YARA_RULES:</span>
                      <input value={yaraPath} onChange={e => setYaraPath(e.target.value)} placeholder="C:\\rules\\custom.yar (optional)"
                        style={{ ...Inp, flex: 1 }} />
                    </div>
                  </>
                )}
                {mode === 'actor' && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={Lbl}>THREAT_ACTOR:</span>
                    <select value={actor} onChange={e => setActor(e.target.value)} style={{ ...Inp, flex: 1 }}>
                      {THREAT_ACTORS.map(a => <option key={a} value={a}>{a}</option>)}
                    </select>
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-end' }}>
                {mode === 'single' && <div style={{ color: C.green, fontSize: 11, fontWeight: 'bold' }}>{selectedPlugins.size} plugin{selectedPlugins.size !== 1 ? 's' : ''} selected</div>}
                {isRunning
                  ? <button onClick={stopStream} style={{ ...Btn, background: C.red, color: C.white }}>■ STOP</button>
                  : analysisMode === 'DEAD_DISK_LOCAL'
                    ? <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <select value={selectedAgent || ''} onChange={e => setSelectedAgent(e.target.value)}
                          style={{ ...Inp, width: 200, fontSize: 10 }}>
                          <option value="">SELECT AGENT...</option>
                          {agents.map(a => (
                            <option key={a.agent_id} value={a.agent_id}>
                              {a.hostname} ({a.analyst})
                            </option>
                          ))}
                        </select>
                        <button onClick={handleDispatchToAgent} disabled={!selectedAgent}
                          style={{ ...Btn, background: C.green, color: '#000', opacity: selectedAgent ? 1 : 0.5 }}>
                          ▶ RUN ON AGENT
                        </button>
                      </div>
                    : <button onClick={handleRun} style={Btn}>▶ EXECUTE</button>
                }
              </div>
            </div>
          )}

          {/* Acquire / Dump panel */}
          {mode === 'acquire' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ color: C.amber, fontSize: 11, marginBottom: 2 }}>⚠ LIVE MEMORY ACQUISITION — Requires admin privileges</div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={Lbl}>OUTPUT_PATH:</span>
                <input value={acquireDest} onChange={e => setAcquireDest(e.target.value)} placeholder="C:\\memory_dump.raw"
                  style={{ ...Inp, flex: 1 }} />
                <button onClick={handleAcquire} disabled={isAcquiring}
                  style={{ ...Btn, opacity: isAcquiring ? 0.5 : 1 }}>
                  {isAcquiring ? 'ACQUIRING...' : '▶ ACQUIRE'}
                </button>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={Lbl}>DUMP_PID:</span>
                <input value={dumpPid} onChange={e => setDumpPid(e.target.value)} placeholder="Process ID" style={{ ...Inp, width: 100 }} />
                <span style={Lbl}>DUMP_DEST:</span>
                <input value={dumpDest} onChange={e => setDumpDest(e.target.value)} placeholder="C:\\dumps\\" style={{ ...Inp, flex: 1 }} />
                <button onClick={handleDump} disabled={isDumping}
                  style={{ ...Btn, background: 'transparent', border: `1px solid ${C.amber}`, color: C.amber, opacity: isDumping ? 0.5 : 1 }}>
                  {isDumping ? 'DUMPING...' : '▶ DUMP_PID'}
                </button>
              </div>
              {acquireLogs.length > 0 && (
                <div style={{ maxHeight: 75, overflowY: 'auto', background: '#0a0a0a', border: `1px solid ${C.border}`, padding: 6 }}>
                  {acquireLogs.map((l, i) => (
                    <div key={i} style={{ fontSize: 9, color: l.type === 'error' ? C.red : l.type === 'success' ? C.green : C.greyDim, fontFamily: 'monospace' }}>
                      [{l.t}] {l.m}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Multi-plugin section tabs */}
        {mode !== 'acquire' && Object.keys(sections).length > 0 && (
          <div style={{ display: 'flex', overflowX: 'auto', background: '#080808', borderBottom: `1px solid #0a0a0a`, padding: '5px 10px', gap: 4, flexShrink: 0 }}>
            {Object.keys(sections).map(p => (
              <button key={p} onClick={() => setActiveSection(p)}
                style={{ background: C.bg, border: `1px solid ${activeSection === p ? C.green : C.border}`,
                  color: activeSection === p ? C.green : C.greyDim, padding: '3px 10px', fontSize: 9, fontFamily: 'monospace', cursor: 'pointer', whiteSpace: 'nowrap' }}>
                {p.split('.').pop()} ({sections[p].rows.length})
              </button>
            ))}
          </div>
        )}

        {/* Results + log panel */}
        {mode !== 'acquire' && (
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
              {dispCols.length > 0 ? (
                <>
                  <div style={{ padding: '5px 12px', background: C.bg, borderBottom: `1px solid #0a0a0a`,
                    display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
                    <span style={{ color: C.grey, fontSize: 11 }}>{dispRows.length} ROWS</span>
                    <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="FILTER..."
                      style={{ ...Inp, width: 200 }} />
                  </div>
                  <div style={{ flex: 1, overflowY: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
                      <thead>
                        <tr style={{ background: C.bgHeader, position: 'sticky', top: 0, zIndex: 1 }}>
                          {dispCols.filter(c => !c.startsWith('_')).map(col => (
                            <th key={col} style={{ padding: '6px 10px', textAlign: 'left', color: C.grey, borderBottom: `1px solid ${C.border}`, fontWeight: 'bold' }}>{col}</th>
                          ))}
                          <th style={{ padding: '6px 10px', textAlign: 'left', color: C.grey, borderBottom: `1px solid ${C.border}`, minWidth: 100 }}>MITRE</th>
                        </tr>
                      </thead>
                      <tbody>
                        {dispRows.map((row, i) => {
                          const badges = row._mitre_techniques || [];
                          return (
                            <tr key={i} style={{ borderBottom: `1px solid #0a0a0a`, background: i % 2 === 0 ? '#040404' : C.bg }}>
                              {dispCols.filter(c => !c.startsWith('_')).map(col => (
                                <td key={col} style={{ padding: '5px 10px', color: C.white, verticalAlign: 'top' }}>{row[col] ?? '---'}</td>
                              ))}
                              <td style={{ padding: '5px 10px', verticalAlign: 'top' }}>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                                  {badges.map(b => (
                                    <span key={b.t_code} onClick={() => setExpandedT(expandedT === b.t_code ? null : b.t_code)}
                                      style={{ fontSize: 9, padding: '1px 4px', cursor: 'pointer',
                                        border: `1px solid ${CONF_COLOR[b.confidence] || C.border}`,
                                        color: CONF_COLOR[b.confidence] || C.grey, fontFamily: 'monospace' }}>
                                      {b.t_code} [{b.confidence}]
                                    </span>
                                  ))}
                                </div>
                                {badges.some(b => b.t_code === expandedT) && (
                                  <div style={{ marginTop: 3, fontSize: 9, color: C.grey, lineHeight: 1.3 }}>
                                    {MITRE_NAMES[expandedT]}
                                  </div>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div style={{ flex: 1, padding: 20 }}>
                  <div style={{ color: C.greyDim, fontSize: 12 }}>
                    {mode === 'single'
                      ? `AWAITING_EXECUTION — ${selectedPlugins.size} plugin(s) selected`
                      : 'AWAITING_SCAN_EXECUTION — Configure and press EXECUTE'}
                  </div>
                </div>
              )}
            </div>
            <LogCol logs={logs} />
          </div>
        )}
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// KNOWN MALWARE SIGNATURES TAB
// ══════════════════════════════════════════════════════════════════════════════
const MalwareSignaturesTab = ({ assetId, onSummaryUpdate, collab, analysisMode = 'UNKNOWN' }) => {
  const [scanPath, setScanPath]     = useState('C:\\');
  const [recursive, setRecursive]   = useState(true);
  const [remove, setRemove]         = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [isUpdating, setIsUpdating] = useState(false);
  const [updateResult, setUpdateResult] = useState(null);
  const [threats, setThreats]       = useState([]);
  const [scanned, setScanned]       = useState(null);
  const [infected, setInfected]     = useState(null);
  const [logs, setLogs]             = useState([]);
  const [filter, setFilter]         = useState('');
  const readerRef = useRef(null);
  const evtSourceRef = useRef(null);
  const [agents, setAgents]               = useState([]);
  const [selectedAgent, setSelectedAgent] = useState(null);

  useEffect(() => {
    if (!assetId) return;
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/scan/clam/results/${assetId}`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!data) return;
        setScanned(data.scanned || 0);
        setThreats(data.threats || []);
        if (data.scan_path) setScanPath(data.scan_path);
        if (onSummaryUpdate) onSummaryUpdate('av', { scanned: data.scanned, infected: data.infected });
      }).catch(() => {});
  }, [assetId]);

  const CLAM = 'C:\\Users\\Sentinel\\Desktop\\Tests\\ORCAWEB\\backend\\bin\\clamav';

  const addLog = (m, type = 'info') => setLogs(p => [{ t: ts(), m, type }, ...p].slice(0, 500));
  const stopScan = () => {
    try { readerRef.current?.cancel(); } catch {} readerRef.current = null;
    try { evtSourceRef.current?.close(); } catch {} evtSourceRef.current = null;
    setIsScanning(false);
  };

  useEffect(() => {
    if (analysisMode !== 'DEAD_DISK_LOCAL') return;
    fetch(`${import.meta.env.VITE_API_URL}/api/agent/list`, { headers: getAuth() })
      .then(r => r.json())
      .then(data => setAgents(data.filter(a => a.status === 'ONLINE')))
      .catch(() => {});
  }, [analysisMode]);

  const handleDispatchToAgent = async () => {
    if (!scanPath.trim()) { addLog('Scan path required.', 'error'); return; }
    setIsScanning(true); setThreats([]); setScanned(null); setInfected(null); setLogs([]);
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/agent/dispatch`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({
          agent_id: selectedAgent,
          job_type: 'clamav',
          params: { scan_path: scanPath, asset_id: Number(assetId) }
        })
      });
      const { job_id } = await r.json();
      addLog(`ClamAV job dispatched to agent: ${job_id}`);
      const evtSource = new EventSource(
        `${import.meta.env.VITE_API_URL}/api/agent/jobs/${job_id}/stream`
      );
      evtSourceRef.current = evtSource;
      evtSource.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.type === 'log') addLog(evt.data.message || String(evt.data));
          else if (evt.type === 'error') { addLog(evt.data.message || String(evt.data), 'error'); setIsScanning(false); evtSource.close(); evtSourceRef.current = null; }
          else if (evt.type === 'done') {
            setScanned(evt.data.scanned_files); setInfected(evt.data.infected_files);
            setThreats(evt.data.threats || []);
            addLog(`SCAN COMPLETE — Scanned: ${evt.data.scanned_files}, Infected: ${evt.data.infected_files}`,
              evt.data.infected_files > 0 ? 'error' : 'success');
            setIsScanning(false);
            if (onSummaryUpdate) onSummaryUpdate('av', { scanned: evt.data.scanned_files, infected: evt.data.infected_files });
            evtSource.close(); evtSourceRef.current = null;
          }
        } catch {}
      };
      evtSource.onerror = () => { addLog('Agent connection lost.', 'error'); setIsScanning(false); evtSource.close(); evtSourceRef.current = null; };
    } catch (e) { addLog('DISPATCH_ERROR: ' + e.message, 'error'); setIsScanning(false); }
  };

  const handleUpdate = async () => {
    setIsUpdating(true); setUpdateResult(null);
    addLog('Running freshclam — this may take a moment...');
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/scan/clam/update`,
        { method: 'POST', headers: getAuth(), body: JSON.stringify({ clam_base: CLAM }) });
      const d = await resp.json();
      setUpdateResult(d);
      addLog(d.message || 'Update complete.', d.status === 'SUCCESS' ? 'success' : 'error');
    } catch (e) { addLog('UPDATE_ERROR: ' + e.message, 'error'); }
    finally { setIsUpdating(false); }
  };

  const handleScan = async () => {
    if (!scanPath.trim()) { addLog('CRITICAL: Scan target path required.', 'error'); return; }

    // ── TOOL LOCK CHECK ──
    if (collab) {
      const lockResult = await collab.acquireToolLock(assetId, 'clamav');
      if (lockResult.status === 'LOCKED') {
        addLog(`BLOCKED: ClamAV is running for this asset by ${lockResult.locked_by} — wait for completion.`, 'error');
        return;
      }
    }
  // ── END TOOL LOCK ──

    stopScan();
    setIsScanning(true); setThreats([]); setScanned(null); setInfected(null); setLogs([]);
    addLog(`Starting ClamAV scan: ${scanPath}`);
    // Mirrors the `threats` state locally -- the 'done' handler below runs
    // inside this same closure, so `threats` there would still be the `[]`
    // it was reset to above, not what setThreats accumulated via SSE. This
    // is what actually gets persisted to the DB.
    let scannedThreats = [];
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/mitre/scan/clam`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({ asset_id: String(assetId), scan_path: scanPath, recursive, remove, clam_base: CLAM })
      });
      if (!resp.ok) { const e = await resp.json(); addLog('BACKEND: ' + (e.detail || resp.statusText), 'error'); setIsScanning(false); return; }
      const reader = resp.body.getReader(); readerRef.current = reader;
      const dec = new TextDecoder(); let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) { setIsScanning(false); break; }
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(line => {
          if (!line.startsWith('data: ')) return;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'log') addLog(evt.data);
            else if (evt.type === 'threat') { scannedThreats = [...scannedThreats, evt.data]; setThreats(scannedThreats); addLog(evt.data, 'error'); }
            else if (evt.type === 'summary') addLog(evt.data);
            else if (evt.type === 'done') {
              setScanned(evt.data.scanned_files); setInfected(evt.data.infected_files);
              addLog(`SCAN COMPLETE — Scanned: ${evt.data.scanned_files}, Infected: ${evt.data.infected_files}`,
                evt.data.infected_files > 0 ? 'error' : 'success');
              setIsScanning(false);
              if (onSummaryUpdate) onSummaryUpdate('av', { scanned: evt.data.scanned_files, infected: evt.data.infected_files });
              fetch(`${import.meta.env.VITE_API_URL}/api/mitre/scan/clam/results/save`, { method: 'POST', headers: getAuth(), body: JSON.stringify({ asset_id: Number(assetId), scan_path: scanPath, scanned: evt.data.scanned_files, infected: evt.data.infected_files, threats: scannedThreats }) }).catch(() => {});
            }
            else if (evt.type === 'error') { addLog(evt.data, 'error'); setIsScanning(false); }
          } catch {}
        });
      }
    } catch (e) { addLog('STREAM_ERROR: ' + e.message, 'error'); setIsScanning(false); }
    finally { if (collab) collab.releaseToolLock(assetId, 'clamav'); }
  };

  const filteredThreats = threats.filter(t => t.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Config bar */}
      <div style={{ background: C.bg, borderBottom: `1px solid ${C.border}`, padding: '10px 15px', flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={Lbl}>SCAN_TARGET:</span>
          <input value={scanPath} onChange={e => setScanPath(e.target.value)} placeholder="C:\Users\"
            style={{ ...Inp, flex: 1, minWidth: 200 }} />
          <label style={{ color: C.grey, fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', fontFamily: 'monospace' }}>
            <input type="checkbox" checked={recursive} onChange={e => setRecursive(e.target.checked)} style={{ marginRight: 4 }} /> RECURSIVE
          </label>
          <label style={{ color: remove ? C.red : C.greyDim, fontSize: 11, cursor: 'pointer', display: 'flex', alignItems: 'center', fontFamily: 'monospace' }}>
            <input type="checkbox" checked={remove} onChange={e => setRemove(e.target.checked)} style={{ marginRight: 4 }} /> REMOVE_THREATS
          </label>
          {isScanning
            ? <button onClick={stopScan} style={{ ...Btn, background: C.red, color: C.white }}>■ STOP_SCAN</button>
            : analysisMode === 'DEAD_DISK_LOCAL'
              ? <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <select value={selectedAgent || ''} onChange={e => setSelectedAgent(e.target.value)}
                    style={{ ...Inp, width: 200, fontSize: 10 }}>
                    <option value="">SELECT AGENT...</option>
                    {agents.map(a => (
                      <option key={a.agent_id} value={a.agent_id}>
                        {a.hostname} ({a.analyst})
                      </option>
                    ))}
                  </select>
                  <button onClick={handleDispatchToAgent} disabled={!selectedAgent}
                    style={{ ...Btn, background: C.green, color: '#000', opacity: selectedAgent ? 1 : 0.5 }}>
                    ▶ RUN ON AGENT
                  </button>
                </div>
              : <button onClick={handleScan} style={Btn}>▶ RUN_CLAMSCAN</button>
          }
          <button onClick={handleUpdate} disabled={isUpdating}
            style={{ ...Btn, background: 'transparent', border: `1px solid ${C.border}`, color: C.grey, opacity: isUpdating ? 0.5 : 1 }}>
            {isUpdating ? 'UPDATING...' : '⟳ UPDATE_DEFS'}
          </button>
        </div>
        {updateResult && (
          <div style={{ marginTop: 8, padding: '6px 10px', fontSize: 11, fontFamily: 'monospace',
            background: updateResult.return_code <= 1 ? 'rgba(0,255,65,0.04)' : 'rgba(255,68,68,0.04)',
            border: `1px solid ${updateResult.return_code <= 1 ? C.green : C.red}`,
            color: updateResult.return_code <= 1 ? C.green : C.red }}>
            {updateResult.message}
            {updateResult.return_code > 1 && (
              <details style={{ marginTop: 4 }}>
                <summary style={{ cursor: 'pointer', fontSize: 10 }}>Show output</summary>
                <pre style={{ color: C.greyDim, fontSize: 9, marginTop: 4, whiteSpace: 'pre-wrap', maxHeight: 120, overflow: 'auto' }}>
                  {updateResult.output}
                </pre>
              </details>
            )}
          </div>
        )}
      </div>

      {/* Summary bar */}
      {scanned !== null && (
        <div style={{ display: 'flex', background: '#0a0a0a', borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          {[['SCANNED_FILES', scanned, C.white], ['INFECTED', infected, infected > 0 ? C.red : C.green],
            ['STATUS', infected > 0 ? '⚠ THREATS_DETECTED' : '✓ CLEAN', infected > 0 ? C.red : C.green]
          ].map(([l, v, col]) => (
            <div key={l} style={{ padding: '10px 20px', borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
              <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
              <span style={{ color: col, fontSize: typeof v === 'number' ? 20 : 11, fontWeight: 'bold', fontFamily: 'monospace' }}>{String(v)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderRight: `1px solid #0a0a0a` }}>
          <div style={{ padding: '5px 12px', background: '#0a0a0a', borderBottom: `1px solid #0a0a0a`,
            display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
            <span style={{ color: C.grey, fontSize: 10, letterSpacing: 1 }}>THREAT_SIGNATURES ({filteredThreats.length})</span>
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="FILTER..."
              style={{ ...Inp, width: 160 }} />
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
            {filteredThreats.length === 0 ? (
              <div style={{ color: C.greyDim, fontSize: 12, padding: 10 }}>
                {isScanning ? 'SCANNING IN PROGRESS...' : scanned !== null ? 'NO_THREATS_DETECTED — System clean.' : 'AWAITING_SCAN_EXECUTION — Configure target and press RUN_CLAMSCAN.'}
              </div>
            ) : filteredThreats.map((t, i) => (
              <div key={i} style={{ padding: '6px 10px', borderBottom: `1px solid #0a0a0a`, display: 'flex', alignItems: 'flex-start' }}>
                <span style={{ color: C.red, marginRight: 8, flexShrink: 0 }}>⚠</span>
                <span style={{ color: C.amber, fontSize: 11, wordBreak: 'break-all', fontFamily: 'monospace' }}>{t}</span>
              </div>
            ))}
          </div>
        </div>
        <LogCol logs={logs} width={300} />
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// VULN SCAN TAB — Syft + Grype
// ══════════════════════════════════════════════════════════════════════════════
const VulnScanTab = ({ assetId, analysisMode, collab, onScanComplete }) => {
  const [scanPath, setScanPath]       = useState('C:\\');
  const [offline, setOffline]         = useState(false);
  const [isScanning, setIsScanning]   = useState(false);
  const [logs, setLogs]               = useState([]);
  const [summary, setSummary]         = useState(null);
  const [vulns, setVulns]             = useState([]);
  const [filter, setFilter]           = useState('');
  const [sevFilter, setSevFilter]     = useState('ALL');
  const [sortCol, setSortCol]         = useState('severity');
  const [sortDir, setSortDir]         = useState('asc');
  const readerRef                       = useRef(null);
  const evtSourceRef                    = useRef(null);
  const [agents, setAgents]             = useState([]);
  const [selectedAgent, setSelectedAgent] = useState(null);

  const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Unknown: 4 };
  const handleSort = col => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
  };

  const addLog = (m, type = 'info') => setLogs(p => [{ t: ts(), m, type }, ...p].slice(0, 500));
  const stopScan = () => {
    try { readerRef.current?.cancel(); } catch {} readerRef.current = null;
    try { evtSourceRef.current?.close(); } catch {} evtSourceRef.current = null;
    setIsScanning(false);
  };

  useEffect(() => {
    if (analysisMode !== 'DEAD_DISK_LOCAL') return;
    fetch(`${import.meta.env.VITE_API_URL}/api/agent/list`, { headers: getAuth() })
      .then(r => r.json())
      .then(data => setAgents(data.filter(a => a.status === 'ONLINE')))
      .catch(() => {});
  }, [analysisMode]);

  const handleDispatchToAgent = async () => {
    if (!scanPath.trim()) { addLog('SCAN_PATH required', 'error'); return; }
    setIsScanning(true); setLogs([]); setSummary(null);
    addLog('Dispatching Grype scan to agent...');
    try {
      const r = await fetch(`${import.meta.env.VITE_API_URL}/api/agent/dispatch`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({
          agent_id: selectedAgent,
          job_type: 'grype',
          params: { scan_path: scanPath, asset_id: Number(assetId) }
        })
      });
      const { job_id } = await r.json();
      addLog(`Grype job dispatched: ${job_id}`);
      const evtSource = new EventSource(
        `${import.meta.env.VITE_API_URL}/api/agent/jobs/${job_id}/stream`
      );
      evtSourceRef.current = evtSource;
      evtSource.onmessage = (e) => {
        try {
          const evt = JSON.parse(e.data);
          if (evt.type === 'log') addLog(evt.data.message || String(evt.data));
          else if (evt.type === 'error') { addLog(evt.data.message || String(evt.data), 'error'); setIsScanning(false); evtSource.close(); evtSourceRef.current = null; }
          else if (evt.type === 'done') {
            const vulnData = evt.data.vulnerabilities || [];
            const counts = { total: vulnData.length, critical: 0, high: 0, medium: 0, low: 0 };
            vulnData.forEach(m => {
              const s = ((m.vulnerability?.severity) || '').toLowerCase();
              if (s === 'critical') counts.critical++;
              else if (s === 'high') counts.high++;
              else if (s === 'medium') counts.medium++;
              else if (s === 'low') counts.low++;
            });
            setSummary(counts);
            if (onScanComplete) onScanComplete(counts);
            addLog(`GRYPE COMPLETE — ${vulnData.length} vulnerabilities found`, vulnData.length > 0 ? 'error' : 'success');
            setIsScanning(false);
            evtSource.close(); evtSourceRef.current = null;
          }
        } catch {}
      };
      evtSource.onerror = () => { addLog('Agent connection lost.', 'error'); setIsScanning(false); evtSource.close(); evtSourceRef.current = null; };
    } catch (e) { addLog('DISPATCH_ERROR: ' + e.message, 'error'); setIsScanning(false); }
  };

  // Load existing results on mount
  useEffect(() => {
    if (!assetId) return;
    fetch(`${import.meta.env.VITE_API_URL}/api/assets/${assetId}/vuln-results`, { headers: getAuth() })
      .then(r => r.ok ? r.json() : [])
      .then(data => {
        if (!data.length) return;
        setVulns(data);
        // Rebuild summary from stored results
        const counts = { total: data.length, critical: 0, high: 0, medium: 0, low: 0 };
        data.forEach(v => {
          const s = (v.severity || '').toUpperCase();
          if (s === 'CRITICAL') counts.critical++;
          else if (s === 'HIGH') counts.high++;
          else if (s === 'MEDIUM') counts.medium++;
          else if (s === 'LOW') counts.low++;
        });
        setSummary(counts);
        if (onScanComplete) onScanComplete(counts);
      })
      .catch(() => {});
  }, [assetId]);

  const handleScan = async () => {
    if (!scanPath.trim()) { addLog('SCAN_PATH required', 'error'); return; }
    if (collab) {
      const lock = await collab.acquireToolLock(assetId, 'grype');
      if (lock.status === 'LOCKED') {
        addLog(`BLOCKED: Vuln scan running for this asset by ${lock.locked_by}`, 'error');
        return;
      }
    }
    stopScan();
    setIsScanning(true); setLogs([]); setSummary(null);
    addLog(`Starting Syft → Grype pipeline on ${scanPath}`);
    try {
      const resp = await fetch(`${import.meta.env.VITE_API_URL}/api/assets/vuln-scan`, {
        method: 'POST', headers: getAuth(),
        body: JSON.stringify({ asset_id: assetId, scan_path: scanPath, offline }),
      });
      if (!resp.ok) { const e = await resp.json(); addLog('BACKEND: ' + (e.detail || resp.statusText), 'error'); setIsScanning(false); return; }
      const reader = resp.body.getReader(); readerRef.current = reader;
      const dec = new TextDecoder(); let buf = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) { setIsScanning(false); break; }
        buf += dec.decode(value, { stream: true });
        const lines = buf.split('\n'); buf = lines.pop();
        lines.forEach(line => {
          if (!line.startsWith('data: ')) return;
          try {
            const evt = JSON.parse(line.slice(6));
            if (evt.type === 'log')     addLog(evt.data);
            else if (evt.type === 'error')   addLog(evt.data, 'error');
            else if (evt.type === 'summary') {
              setSummary(evt.data);
              if (onScanComplete) onScanComplete(evt.data);
              // Reload results from DB
              fetch(`${import.meta.env.VITE_API_URL}/api/assets/${assetId}/vuln-results`, { headers: getAuth() })
                .then(r => r.json()).then(setVulns).catch(() => {});
            }
            else if (evt.type === 'done') {
              addLog(evt.data, evt.data.includes('FAILED') ? 'error' : 'success');
              setIsScanning(false);
            }
          } catch {}
        });
      }
    } catch (e) { addLog('STREAM_ERROR: ' + e.message, 'error'); setIsScanning(false); }
    finally { if (collab) collab.releaseToolLock(assetId, 'grype'); }
  };

  const isDead = analysisMode === 'DEAD_DISK_LOCAL' || analysisMode === 'DEAD_DISK_REMOTE';

  const sevColor = { Critical: C.red, High: '#ff8800', Medium: C.amber, Low: C.green, Unknown: C.greyDim };

  const filtered = vulns.filter(v => {
    const matchSev = sevFilter === 'ALL' || v.severity === sevFilter;
    const matchText = !filter || v.cve_id?.toLowerCase().includes(filter.toLowerCase()) ||
      v.package?.toLowerCase().includes(filter.toLowerCase());
    return matchSev && matchText;
  }).sort((a, b) => {
    let av, bv;
    if (sortCol === 'severity') {
      av = SEV_ORDER[a.severity] ?? 99;
      bv = SEV_ORDER[b.severity] ?? 99;
    } else {
      av = (a[sortCol] || '').toLowerCase();
      bv = (b[sortCol] || '').toLowerCase();
    }
    if (av < bv) return sortDir === 'asc' ? -1 : 1;
    if (av > bv) return sortDir === 'asc' ?  1 : -1;
    return 0;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Config bar */}
      <div style={{ background: C.bg, borderBottom: `1px solid ${C.border}`, padding: '10px 15px', flexShrink: 0 }}>
        {!isDead ? (
          <div style={{ color: C.amber, fontSize: 11, fontFamily: 'monospace' }}>
            ⚠ VULN_SCAN requires DEAD_DISK_LOCAL or DEAD_DISK_REMOTE mode
          </div>
        ) : (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
            <span style={Lbl}>SCAN_PATH:</span>
            <input value={scanPath} onChange={e => setScanPath(e.target.value)}
              placeholder="N:\\" style={{ ...Inp, flex: 1, minWidth: 200 }} />
            <label style={{ color: offline ? C.amber : C.greyDim, fontSize: 11, cursor: 'pointer',
              display: 'flex', alignItems: 'center', fontFamily: 'monospace' }}>
              <input type="checkbox" checked={offline} onChange={e => setOffline(e.target.checked)}
                style={{ marginRight: 4 }} /> OFFLINE_DB
            </label>
            {isScanning
              ? <button onClick={stopScan} style={{ ...Btn, background: C.red, color: C.white }}>■ STOP</button>
              : analysisMode === 'DEAD_DISK_LOCAL'
                ? <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <select value={selectedAgent || ''} onChange={e => setSelectedAgent(e.target.value)}
                      style={{ ...Inp, width: 200, fontSize: 10 }}>
                      <option value="">SELECT AGENT...</option>
                      {agents.map(a => (
                        <option key={a.agent_id} value={a.agent_id}>
                          {a.hostname} ({a.analyst})
                        </option>
                      ))}
                    </select>
                    <button onClick={handleDispatchToAgent} disabled={!selectedAgent}
                      style={{ ...Btn, background: C.green, color: '#000', opacity: selectedAgent ? 1 : 0.5 }}>
                      ▶ RUN ON AGENT
                    </button>
                  </div>
                : <button onClick={handleScan} style={Btn}>▶ RUN_VULN_SCAN</button>
            }
          </div>
        )}
      </div>

      {/* Summary bar */}
      {summary && (
        <div style={{ display: 'flex', background: '#0a0a0a', borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          {[
            ['TOTAL',    summary.total,    C.white],
            ['CRITICAL', summary.critical, summary.critical > 0 ? C.red : C.greyDim],
            ['HIGH',     summary.high,     summary.high > 0 ? '#ff8800' : C.greyDim],
            ['MEDIUM',   summary.medium,   summary.medium > 0 ? C.amber : C.greyDim],
            ['LOW',      summary.low,      summary.low > 0 ? C.green : C.greyDim],
          ].map(([l, v, col]) => (
            <div key={l} style={{ padding: '10px 20px', borderRight: `1px solid ${C.border}`,
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
              <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{l}</span>
              <span style={{ color: col, fontSize: 20, fontWeight: 'bold', fontFamily: 'monospace' }}>{v}</span>
            </div>
          ))}
        </div>
      )}

      {/* Results + log */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* Vuln table */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Filter bar */}
          <div style={{ padding: '6px 12px', background: '#0a0a0a', borderBottom: `1px solid #0a0a0a`,
            display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="FILTER CVE / PACKAGE..."
              style={{ ...Inp, width: 220 }} />
            {['ALL','Critical','High','Medium','Low'].map(s => (
              <button key={s} onClick={() => setSevFilter(s)}
                style={{ padding: '2px 8px', fontSize: 9, fontFamily: 'monospace', cursor: 'pointer',
                  background: sevFilter === s ? (sevColor[s] || C.green) : 'transparent',
                  color: sevFilter === s ? '#000' : (sevColor[s] || C.greyDim),
                  border: `1px solid ${sevColor[s] || C.border}` }}>
                {s}
              </button>
            ))}
            <span style={{ color: C.greyDim, fontSize: 9, marginLeft: 'auto' }}>{filtered.length} results</span>
          </div>

          {/* Table */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {filtered.length === 0 ? (
              <div style={{ color: C.greyDim, fontSize: 12, padding: 20 }}>
                {isScanning ? 'SCAN IN PROGRESS...' : vulns.length > 0 ? 'NO_RESULTS_MATCH_FILTER' : 'AWAITING_SCAN — Configure path and press RUN_VULN_SCAN'}
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
                <thead>
                  <tr style={{ background: '#0a0a0a', position: 'sticky', top: 0 }}>
                    {[
                      ['SEVERITY',    'severity'],
                      ['CVE_ID',      'cve_id'],
                      ['PACKAGE',     'package'],
                      ['VERSION',     'version'],
                      ['FIX_VERSION', 'fix_version'],
                      ['FIX_STATE',   'fix_state'],
                    ].map(([label, col]) => (
                      <th key={col} onClick={() => handleSort(col)}
                        style={{ padding: '6px 10px', color: sortCol === col ? C.green : C.greyDim,
                          fontSize: 9, letterSpacing: 1, textAlign: 'left',
                          borderBottom: `1px solid ${C.border}`, cursor: 'pointer',
                          userSelect: 'none', whiteSpace: 'nowrap' }}>
                        {label}{sortCol === col ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ' ⇅'}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((v, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid #0a0a0a`,
                      background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                      <td style={{ padding: '5px 10px' }}>
                        <span style={{ color: sevColor[v.severity] || C.greyDim, fontWeight: 'bold', fontSize: 10 }}>
                          {v.severity}
                        </span>
                      </td>
                      <td style={{ padding: '5px 10px', color: C.green }}>{v.cve_id}</td>
                      <td style={{ padding: '5px 10px', color: C.white }}>{v.package}</td>
                      <td style={{ padding: '5px 10px', color: C.grey }}>{v.version}</td>
                      <td style={{ padding: '5px 10px', color: v.fix_version ? C.green : C.greyDim }}>
                        {v.fix_version || '—'}
                      </td>
                      <td style={{ padding: '5px 10px', color: C.greyDim, fontSize: 10 }}>{v.fix_state || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <LogCol logs={logs} width={280} />
      </div>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════

// ── NetConfigTab ────────────────────────────────────────────────────────────
const NetConfigTab = ({ netConfigText, netConfigFile, netConfigSaving, onConfigLoad }) => {
  const fileRef = React.useRef(null);
  const handleFile = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = (ev) => onConfigLoad(ev.target.result, f.name);
    reader.readAsText(f);
  };

  return (
    <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14, height: '100%', boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
        <input ref={fileRef} type="file"
          accept=".txt,.cfg,.conf,.log,.ios,.xml,.json,.yaml,.yml"
          onChange={handleFile} style={{ display: 'none' }} />
        <button onClick={() => fileRef.current?.click()} style={{
          background: netConfigText ? 'transparent' : C.green,
          color: netConfigText ? C.green : '#000',
          border: `1px solid ${C.green}`,
          padding: '5px 16px', fontSize: 10,
          fontFamily: 'monospace', fontWeight: 'bold', cursor: 'pointer',
        }}>
          {netConfigText ? '↺ REPLACE CONFIG' : '⬆ UPLOAD DEVICE CONFIG'}
        </button>
        {netConfigFile && <span style={{ color: C.greyDim, fontSize: 10, fontFamily: 'monospace' }}>{netConfigFile}</span>}
        {netConfigSaving && <span style={{ color: C.amber, fontSize: 10, fontFamily: 'monospace' }}>SAVING…</span>}
      </div>

      {netConfigText ? (
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <InlineConfigViewer configText={netConfigText} fileName={netConfigFile} fullHeight />
        </div>
      ) : (
        <div style={{ color: C.greyDim, fontSize: 11, fontFamily: 'monospace', padding: '40px 0', textAlign: 'center' }}>
          No configuration loaded — upload a device config file above.<br />
          <span style={{ fontSize: 10, color: '#999' }}>Supported: .cfg .conf .ios .txt .xml .json .yaml</span>
        </div>
      )}
    </div>
  );
};

// ── InlineConfigViewer ─────────────────────────────────────────────────────
const InlineConfigViewer = ({ configText, fileName, fullHeight }) => {
  const [search, setSearch]           = React.useState('');
  const [searchInput, setSearchInput] = React.useState('');
  const [jumpLine, setJumpLine]       = React.useState('');

  const lines = configText ? configText.split('\n') : [];
  const isMatch = (line) => search && line.toLowerCase().includes(search.toLowerCase());

  const handleJump = () => {
    const n = parseInt(jumpLine);
    if (!isNaN(n) && n > 0 && n <= lines.length) {
      const el = document.getElementById('icfg-line-' + n);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
  };

  const getLineColor = (line) => {
    const t = line.trim();
    if (!t) return '#333';
    if (t.startsWith('!') || t.startsWith('#') || t.startsWith('//')) return '#445544';
    if (/^(interface|ip|no |router|hostname|version|service|crypto|aaa|line|vlan|spanning)/i.test(t)) return '#00cc33';
    if (/^(permit|deny|access-list|policy|rule|zone|nat|acl)/i.test(t)) return '#ffaa00';
    if (/password|secret|key|token|credential/i.test(t)) return '#ff6666';
    if (/^end$|^exit$/i.test(t)) return '#445566';
    return '#aabbcc';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', ...(fullHeight ? { height: '100%' } : { maxHeight: 480 }), border: `1px solid ${C.border}`, background: '#050505' }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 6, padding: '6px 10px', borderBottom: `1px solid ${C.border}`,
        flexShrink: 0, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ color: C.green, fontSize: 10, fontFamily: 'monospace', fontWeight: 'bold' }}>
          CONFIG: {fileName || 'device_config'}
        </span>
        <span style={{ color: C.greyDim, fontSize: 9 }}>{lines.length} LINES</span>
        <input placeholder="SEARCH..." value={searchInput}
          onChange={e => setSearchInput(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') setSearch(searchInput); }}
          style={{ ...Inp, width: 140, fontSize: 9, padding: '2px 6px' }} />
        <button onClick={() => setSearch(searchInput)}
          style={{ ...Btn, fontSize: 8, padding: '2px 6px' }}>GO</button>
        {search && <button onClick={() => { setSearch(''); setSearchInput(''); }}
          style={{ ...Btn, fontSize: 8, padding: '2px 6px', color: C.greyDim }}>CLR</button>}
        <input placeholder="LINE#" value={jumpLine}
          onChange={e => setJumpLine(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') handleJump(); }}
          style={{ ...Inp, width: 60, fontSize: 9, padding: '2px 6px' }} />
        <button onClick={handleJump}
          style={{ ...Btn, fontSize: 8, padding: '2px 6px' }}>JUMP</button>
        {search && <span style={{ color: C.amber, fontSize: 9 }}>
          {lines.filter(l => isMatch(l)).length} matches
        </span>}
      </div>
      {/* Lines */}
      <div style={{ overflowY: 'auto', overflowX: 'auto', flex: 1 }}>
        <table style={{ borderCollapse: 'collapse', minWidth: '100%' }}>
          <tbody>
            {lines.map((line, i) => {
              const n = i + 1;
              const matched = isMatch(line);
              return (
                <tr key={n} id={'icfg-line-' + n}
                  style={{ background: matched ? 'rgba(255,170,0,0.1)' : n % 2 === 0 ? '#080808' : 'transparent' }}>
                  <td style={{ padding: '0px 10px 0px 6px', color: matched ? C.amber : C.greyDim,
                    fontSize: 10, textAlign: 'right', userSelect: 'none',
                    borderRight: `1px solid ${C.border}`, whiteSpace: 'nowrap', minWidth: 36,
                    fontWeight: matched ? 'bold' : 'normal', fontFamily: 'Consolas, monospace' }}>
                    {n}
                  </td>
                  <td style={{ padding: '0px 8px 0px 10px', fontSize: 10, whiteSpace: 'pre',
                    color: matched ? C.amber : getLineColor(line), fontFamily: 'Consolas, monospace' }}>
                    {line || '\u00a0'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ROOT: EVIDENCE WINDOW
// PATCH: Replace lines 1190–1261 in EvidenceWindow.jsx
//
// ══════════════════════════════════════════════════════════════════════════════
// REPORT TAB
// ══════════════════════════════════════════════════════════════════════════════
const ReportTab = ({ caseName, assetId }) => {
  const [report, setReport]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const fetchReport = async () => {
    setLoading(true); setError(null);
    try {
      const url = `${import.meta.env.VITE_API_URL}/api/reports/${encodeURIComponent(caseName)}${assetId ? `?asset_id=${assetId}` : ''}`;
      const r = await fetch(url, { headers: getAuth() });
      if (!r.ok) { setError(`HTTP ${r.status}`); return; }
      setReport(await r.json());
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { if (caseName) fetchReport(); }, [caseName, assetId]);

  if (loading) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.greyDim, fontSize: 12 }}>
      ASSEMBLING_REPORT...
    </div>
  );
  if (error) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: C.red, fontSize: 12 }}>
      REPORT_ERROR: {error}
    </div>
  );
  if (!report) return null;

  const { summary, bluf_notes, timeline, techniques, assets } = report;
  const vCol = { MALICIOUS: C.red, 'NON-MALICIOUS': C.green, UNDETERMINED: C.greyDim, 'EVIDENCE FOUND': C.purple, NO_ARTIFACTS: C.greyDim };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 14, boxSizing: 'border-box' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{ color: C.green, fontSize: 14, fontWeight: 'bold' }}>{report.case_name}</div>
          <div style={{ color: C.greyDim, fontSize: 10, marginTop: 3 }}>FOCUS: {report.focus_country} &nbsp;·&nbsp; GENERATED: {new Date(report.generated_at).toLocaleString()}</div>
        </div>
        <button onClick={fetchReport} style={{ ...Btn, background: 'transparent', border: `1px solid ${C.green}`, color: C.green }}>↻ REFRESH</button>
      </div>

      <Card title="INVESTIGATION_SUMMARY">
        <div style={{ padding: 14, display: 'flex', gap: 0, flexWrap: 'wrap' }}>
          {[
            ['TOTAL',        summary.total_techniques, C.white],
            ['CLOSED',       summary.closed,           C.green],
            ['EVIDENCE',     summary.with_evidence,    C.purple],
            ['NO_ARTIFACTS', summary.no_artifacts,     C.greyDim],
            ['PENDING',      summary.pending,          '#ffaa00'],
            ['COMPLETION',   `${summary.completion_pct}%`, C.green],
            ['MALICIOUS',    summary.malicious,        C.red],
            ['NON-MALICIOUS',summary.non_malicious,    C.green],
            ['UNDETERMINED', summary.undetermined,     C.greyDim],
          ].map(([label, val, col]) => (
            <div key={label} style={{ padding: '10px 18px', borderRight: `1px solid ${C.border}`, display: 'flex', flexDirection: 'column', gap: 3 }}>
              <span style={{ color: C.greyDim, fontSize: 9, letterSpacing: 1 }}>{label}</span>
              <span style={{ color: col, fontSize: 22, fontWeight: 'bold' }}>{val}</span>
            </div>
          ))}
        </div>
      </Card>

      {assets.length > 0 && (
        <Card title={`ASSETS (${assets.length})`}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
            <thead><tr style={{ background: C.bgHeader }}>
              {['HOSTNAME','OS','TYPE','MODE'].map(h => <th key={h} style={{ padding: '6px 12px', textAlign: 'left', color: C.greyDim, borderBottom: `1px solid ${C.border}` }}>{h}</th>)}
            </tr></thead>
            <tbody>{assets.map(a => (
              <tr key={a.id} style={{ borderBottom: `1px solid #0a0a0a` }}>
                <td style={{ padding: '5px 12px', color: C.green }}>{a.hostname || `ASSET_${a.id}`}</td>
                <td style={{ padding: '5px 12px', color: C.white }}>{a.os || '—'}</td>
                <td style={{ padding: '5px 12px', color: C.grey }}>{a.asset_type || '—'}</td>
                <td style={{ padding: '5px 12px', color: C.greyDim }}>{a.analysis_mode || '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </Card>
      )}

      {bluf_notes.length > 0 && (
        <Card title="BLUF_NOTES">
          <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {bluf_notes.map((n, i) => (
              <div key={i} style={{ borderLeft: `3px solid ${C.green}`, paddingLeft: 12 }}>
                <div style={{ color: C.greyDim, fontSize: 9, marginBottom: 4 }}>{n.author || 'ANALYST'} &nbsp;·&nbsp; {n.created_at ? new Date(n.created_at).toLocaleString() : ''}</div>
                <div style={{ color: C.white, fontSize: 12, whiteSpace: 'pre-wrap' }}>{n.text}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {timeline.length > 0 && (
        <Card title={`ANALYST_TIMELINE (${timeline.length})`}>
          <div style={{ maxHeight: 320, overflowY: 'auto' }}>
            {timeline.map((entry, i) => (
              <div key={i} style={{ padding: '8px 14px', borderBottom: `1px solid #0a0a0a`, display: 'flex', gap: 12 }}>
                <div style={{ color: C.green, fontSize: 10, minWidth: 70, flexShrink: 0 }}>{entry.t_code}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: C.greyDim, fontSize: 9, marginBottom: 3 }}>[{entry.initials || entry.author || '?'}] &nbsp;·&nbsp; {entry.note_type} &nbsp;·&nbsp; {entry.created_at ? new Date(entry.created_at).toLocaleString() : ''}</div>
                  <div style={{ color: C.white, fontSize: 11, whiteSpace: 'pre-wrap' }}>{entry.text}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title={`TECHNIQUE_VERDICTS (${techniques.length})`}>
        <div style={{ maxHeight: 400, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, fontFamily: 'monospace' }}>
            <thead><tr style={{ background: C.bgHeader, position: 'sticky', top: 0 }}>
              {['T_CODE','TECHNIQUE','STATUS','EVIDENCE','VERDICT','ACTORS'].map(h => (
                <th key={h} style={{ padding: '6px 10px', textAlign: 'left', color: C.greyDim, borderBottom: `1px solid ${C.border}` }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>{techniques.map((t, i) => {
              const v = (t.verdict || 'UNDETERMINED').toUpperCase();
              return (
                <tr key={i} style={{ borderBottom: `1px solid #0a0a0a` }}>
                  <td style={{ padding: '4px 10px', color: C.green }}>{t.t_code}</td>
                  <td style={{ padding: '4px 10px', color: C.grey, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.technique_name}</td>
                  <td style={{ padding: '4px 10px', color: t.technique_status === 'CLOSED' ? C.green : C.greyDim }}>{t.technique_status || 'UNCLAIMED'}</td>
                  <td style={{ padding: '4px 10px', color: t.evidence_imported ? C.purple : C.greyDim }}>{t.evidence_imported ? '✓' : '—'}</td>
                  <td style={{ padding: '4px 10px', color: vCol[v] || C.greyDim }}>{v}</td>
                  <td style={{ padding: '4px 10px', color: C.greyDim, fontSize: 10, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.associated_actors || '—'}</td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

// ══════════════════════════════════════════════════════════════════════════════
// THE FIX: Tab content is now always mounted. Each tab wrapper uses
// display: 'flex'/'none' to show/hide. This means MemoryAnalysisTab,
// MalwareSignaturesTab, and ArtifactAnalysisTab are NEVER unmounted when
// switching tabs — their state, refs, and active SSE streams all survive.
// ══════════════════════════════════════════════════════════════════════════════
const EvidenceWindow = ({ assetId, assetName, tCode, isOpen, onClose, tacticList, caseName, collab, analysisMode = 'UNKNOWN', assetIp = '', caseType = 'INVESTIGATION', assetType = '', localDir = null, memSummary: memSummaryProp = null, avSummary: avSummaryProp = null, vulnSummary: vulnSummaryProp = null, behavioralSummary: behavioralSummaryProp = null, onSummaryUpdate }) => {
  const { handle401 } = useAuth();
  const isIR = caseType === 'INCIDENT_RESPONSE';
  const NETWORK_TYPES = ['FIREWALL', 'ROUTER', 'SWITCH', 'NETWORK', 'AP', 'LOAD_BALANCER', 'PROXY', 'VPN', 'IDS', 'IPS', 'WAF'];
  const isNetworkDevice = NETWORK_TYPES.some(t => (assetType || '').toUpperCase().includes(t));
  const [netConfigText, setNetConfigText] = useState('');
  const [netConfigFile, setNetConfigFile] = useState('');
  const [netConfigSaving, setNetConfigSaving] = useState(false);
  const [tab, setTab]                 = useState('OVERVIEW');
  const [progressLabel, setProgressLabel] = useState(null);
  // Summary state — initialized from lifted props, updates propagate back up
  const [memSummary, setMemSummaryLocal]          = useState(memSummaryProp);
  const [avSummary, setAvSummaryLocal]            = useState(avSummaryProp);
  const [vulnSummary, setVulnSummaryLocal]        = useState(vulnSummaryProp);
  const [behavioralSummary, setBehavioralSummaryLocal] = useState(behavioralSummaryProp);
  const [capaIdentifiedTechniques, setCapaIdentifiedTechniques] = useState(new Set());

  const setMemSummary        = (data) => { setMemSummaryLocal(data);        onSummaryUpdate && onSummaryUpdate('memory',     assetId, data); };
  const setAvSummary         = (data) => { setAvSummaryLocal(data);         onSummaryUpdate && onSummaryUpdate('av',         assetId, data); };
  const setVulnSummary       = (data) => { setVulnSummaryLocal(data);       onSummaryUpdate && onSummaryUpdate('vuln',       assetId, data); };
  const setBehavioralSummary = (data) => { setBehavioralSummaryLocal(data); onSummaryUpdate && onSummaryUpdate('behavioral', assetId, data); };

useEffect(() => {
    if (isOpen) {
      setTab('OVERVIEW');
      setProgressLabel(null);
      setNetConfigText('');
      setNetConfigFile('');
      // Restore from lifted state — don't reset to null
      setMemSummaryLocal(memSummaryProp);
      setAvSummaryLocal(avSummaryProp);
      setVulnSummaryLocal(vulnSummaryProp);
      setBehavioralSummaryLocal(behavioralSummaryProp);
      if (collab && assetId) collab.loadTechniqueStatuses(assetId);
      // Persist vuln summary across sessions by deriving counts from stored results
      fetch(`${import.meta.env.VITE_API_URL}/api/assets/${assetId}/vuln-results`, { headers: getAuth() })
        .then(r => r.ok ? r.json() : [])
        .then(rows => {
          if (!rows.length) return;
          const counts = { total: rows.length, critical: 0, high: 0, medium: 0, low: 0 };
          rows.forEach(r => {
            const s = (r.severity || '').toLowerCase();
            if (s === 'critical') counts.critical++;
            else if (s === 'high')     counts.high++;
            else if (s === 'medium')   counts.medium++;
            else if (s === 'low')      counts.low++;
          });
          setVulnSummary(counts);  // also propagates to InvestigationWorkspace
        })
        .catch(() => {});
      // Restore behavioral summary from last completed job
      fetch(`${import.meta.env.VITE_API_URL}/api/behavioral/asset/${assetId}/latest`, { headers: getAuth() })
        .then(r => r.ok ? r.json() : null)
        .then(data => {
          if (!data) return;
          setBehavioralSummaryLocal({
            techniqueCount: data.capa?.technique_count || 0,
            iocCount: data.floss?.ioc_count || 0,
            apiCallCount: data.speakeasy?.api_calls?.length || 0,
          });
        })
        .catch(() => {});
      // Load CAPA-identified technique IDs for badge rendering in the technique table
      fetch(`${import.meta.env.VITE_API_URL}/api/behavioral/asset/${assetId}/capa-techniques`, { headers: getAuth() })
        .then(r => r.ok ? r.json() : [])
        .then(rows => setCapaIdentifiedTechniques(new Set(rows.map(r => r.technique_id))))
        .catch(() => {});
      // Load persisted network config if this is a network device asset
      if (isNetworkDevice && assetId) {
        fetch(`${import.meta.env.VITE_API_URL}/api/mitre/assets/${assetId}/net-config`, { headers: getAuth() })
          .then(r => r.ok ? r.json() : null)
          .then(data => {
            if (data?.text) { setNetConfigText(data.text); setNetConfigFile(data.filename || ''); }
          })
          .catch(() => {});
      }
    }
  }, [isOpen, assetId]);


  const handleConfigLoad = (text, name) => {
    setNetConfigText(text);
    setNetConfigFile(name);
    setNetConfigSaving(true);
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/assets/${assetId}/net-config`, {
      method: 'POST',
      headers: getAuth(),
      body: JSON.stringify({ text, filename: name }),
    }).finally(() => setNetConfigSaving(false));
  };

  const TABS = ['OVERVIEW', 'ARTIFACT_ANALYSIS', ...(isNetworkDevice ? ['NET_CONFIG'] : []), 'MEMORY_ANALYSIS', 'KNOWN_MALWARE_SIGNATURES', 'VULN_SCAN', 'BEHAVIORAL_ANALYSIS'];
  const TAB_LABELS = {
    'ARTIFACT_ANALYSIS': isIR ? 'IR ARTIFACTS' : 'ARTIFACT ANALYSIS',
    'BEHAVIORAL_ANALYSIS': behavioralSummary?.techniqueCount > 0
      ? `BEHAVIORAL ANALYSIS [${behavioralSummary.techniqueCount}]`
      : 'BEHAVIORAL ANALYSIS',
  };

  // Shared style for each tab's wrapper div.
  // When the tab is active: flex column filling all available space.
  // When inactive: display none — component stays mounted, state/streams preserved.
  const tabStyle = (name) => ({
    display: tab === name ? 'flex' : 'none',
    flexDirection: 'column',
    flex: 1,
    overflow: 'hidden',
  });

  return (
    <div style={{ display: isOpen ? 'contents' : 'none' }}>
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.97)', display: 'flex',
      justifyContent: 'center', alignItems: 'center', zIndex: 1000, fontFamily: 'monospace' }}>
      <div style={{ width: '93%', height: '93%', background: '#050505', border: `1px solid ${isIR ? C.red : C.green}`,
        display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Header */}
        <div style={{ padding: '10px 20px', borderBottom: `1px solid ${C.border}`, display: 'flex',
          justifyContent: 'space-between', alignItems: 'center', background: C.bg, flexShrink: 0 }}>
          <div style={{ color: C.green, fontWeight: 'bold', fontSize: 14 }}>
            [INVESTIGATION_WORKSPACE]: {(assetName || `ASSET_${assetId}`).toUpperCase()}
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: C.red, cursor: 'pointer', fontWeight: 'bold', fontSize: 16, fontFamily: 'monospace' }}>[ X ]</button>
        </div>

        {/* Analysis mode banner */}
        {analysisMode === 'UNKNOWN' && (
          <div style={{ padding: '5px 20px', background: 'rgba(255,170,0,0.06)', borderBottom: `1px solid ${C.amber}`,
            color: C.amber, fontSize: 10, letterSpacing: 1, flexShrink: 0 }}>
            ⚠ ANALYSIS_MODE: UNKNOWN — set mode on ASSETS tab to gate tool availability
          </div>
        )}
        {analysisMode !== 'UNKNOWN' && (
          <div style={{ padding: '5px 20px', background: 'rgba(0,255,65,0.03)', borderBottom: `1px solid ${C.border}`,
            color: C.greyDim, fontSize: 10, letterSpacing: 1, flexShrink: 0 }}>
            MODE: {analysisMode}
          </div>
        )}

        {/* Collection status bar — shows real progress while collection runs */}
        <CollectionStatusBar tacticList={tacticList} />

        {/* Tab bar */}
        <div style={{ display: 'flex', background: C.bg, borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
          {TABS.map(t => (
            <button key={t} onClick={() => setTab(t)}
              style={{ padding: '10px 20px', border: 'none', cursor: 'pointer', fontSize: 11,
                fontFamily: 'monospace', fontWeight: 'bold', letterSpacing: 1,
                borderBottom: `2px solid ${tab === t ? C.green : 'transparent'}`,
                color: tab === t ? C.green : C.greyDim,
                background: tab === t ? 'rgba(0,255,65,0.04)' : 'transparent' }}>
              {(TAB_LABELS[t] || t).replace(/_/g, ' ')}
            </button>
          ))}
        </div>

        {/* Content — ALL tabs always mounted, toggled with display */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

          <div style={tabStyle('OVERVIEW')}>
            <OverviewTab tacticList={tacticList || []} memSummary={memSummary} avSummary={avSummary} vulnSummary={vulnSummary} behavioralSummary={behavioralSummary} capaIdentifiedTechniques={capaIdentifiedTechniques} isNetworkDevice={isNetworkDevice} netConfigText={netConfigText} netConfigFile={netConfigFile} netConfigSaving={netConfigSaving} onConfigLoad={handleConfigLoad} />
          </div>

          <div style={tabStyle('ARTIFACT_ANALYSIS')}>
            {isIR ? (
              <ArtifactTreeTab assetId={assetId} assetName={assetName} />
            ) : (
              <ArtifactAnalysisTab
                assetId={assetId} assetName={assetName}
                tacticList={tacticList || []} caseName={caseName}
                onCollectionStarted={setProgressLabel}
                collab={collab} analysisMode={analysisMode} assetIp={assetIp}
                isNetworkDevice={isNetworkDevice} netConfigText={netConfigText} netConfigFile={netConfigFile}
              />
            )}
          </div>

          <div style={tabStyle('NET_CONFIG')}>
            <NetConfigTab
              netConfigText={netConfigText}
              netConfigFile={netConfigFile}
              netConfigSaving={netConfigSaving}
              onConfigLoad={handleConfigLoad}
            />
          </div>

          <div style={tabStyle('MEMORY_ANALYSIS')}>
            <MemoryAnalysisTab
              assetId={assetId}
              collab={collab}
              analysisMode={analysisMode}
              localDir={localDir}
              onSummaryUpdate={(type, data) => {
                if (type === 'memory') setMemSummary(data);
                else if (type === 'av') setAvSummary(data);
              }}
            />
          </div>

          <div style={tabStyle('KNOWN_MALWARE_SIGNATURES')}>
            <MalwareSignaturesTab
              assetId={assetId}
              collab={collab}
              analysisMode={analysisMode}
              onSummaryUpdate={(type, data) => {
                if (type === 'memory') setMemSummary(data);
                else if (type === 'av') setAvSummary(data);
              }}
            />
          </div>

          <div style={tabStyle('VULN_SCAN')}>
            <VulnScanTab
              assetId={assetId}
              analysisMode={analysisMode}
              collab={collab}
              onScanComplete={setVulnSummary}
            />
          </div>

          <div style={tabStyle('BEHAVIORAL_ANALYSIS')}>
            <BehavioralAnalysisTab
              key={assetId}
              assetId={assetId}
              onSummaryUpdate={setBehavioralSummary}
            />
          </div>

          <div style={tabStyle('REPORT')}>
            <ReportTab caseName={caseName} assetId={assetId} />
          </div>

        </div>
      </div>
    </div>
    </div>
  );
};

export default EvidenceWindow;

// ── TimelineViewer ─────────────────────────────────────────────────────────────
const SOURCE_COLORS = {
  MFT:                   '#00ff41',
  EVENT_LOGS_SECURITY:   '#ff4141',
  EVENT_LOGS_SYSMON:     '#ff6b6b',
  EVENT_LOGS_POWERSHELL: '#ffaa00',
  EVENT_LOGS_SYSTEM:     '#ff8800',
  EVENT_LOGS_APPLICATION:'#ffcc00',
  EVENT_LOGS_WMI:        '#ff4444',
  EVENT_LOGS_WINRM:      '#ff7777',
  EVENT_LOGS_TASKSCHEDULER: '#ffaa44',
  PREFETCH:              '#00ccff',
  LNK_JUMPLISTS:         '#cc88ff',
  SCHEDULED_TASKS:       '#ff88cc',
};
const FLAG_COLORS = {
  DELETED:   '#ff4141',
  TIMESTOMP: '#ffaa00',
  ADS:       '#9b59ff',
  RUN:       '#00ccff',
  LNK:       '#cc88ff',
  TASK:      '#ff88cc',
  NORMAL:    '#333',
};
const ALL_SOURCES = [
  'MFT','EVENT_LOGS_SECURITY','EVENT_LOGS_SYSMON','EVENT_LOGS_POWERSHELL',
  'EVENT_LOGS_SYSTEM','EVENT_LOGS_APPLICATION','EVENT_LOGS_WMI','EVENT_LOGS_WINRM',
  'EVENT_LOGS_TASKSCHEDULER','PREFETCH','LNK_JUMPLISTS','SCHEDULED_TASKS',
];

const _hlEsc = t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const highlight = (text, terms) => {
  if (!text || !terms || terms.length === 0) return text;
  const esc = terms.map(_hlEsc);
  const parts = String(text).split(new RegExp(`(${esc.join('|')})`, 'gi'));
  if (parts.length <= 1) return text;
  const isMatch = new RegExp(`^(${esc.join('|')})$`, 'i');
  return parts.map((p, i) =>
    isMatch.test(p)
      ? <span key={i} style={{ background: '#ffaa00', color: '#000', borderRadius: 2, padding: '0 1px' }}>{p}</span>
      : p
  );
};

export const TimelineViewer = ({ assetId }) => {
  const [entries, setEntries]         = useState([]);
  const [total, setTotal]             = useState(0);
  const [page, setPage]               = useState(0);
  const [loading, setLoading]         = useState(false);
  const [dateFrom, setDateFrom]       = useState('');
  const [dateTo, setDateTo]           = useState('');
  const [timeFrom, setTimeFrom]       = useState('');
  const [timeTo, setTimeTo]           = useState('');
  const [filters, setFilters]         = useState([]);
  const [filterInput, setFilterInput] = useState('');
  const [sources, setSources]         = useState(new Set(ALL_SOURCES));
  const [expanded, setExpanded]       = useState(new Set());
  const PAGE_SIZE = 200;
  const [showChart, setShowChart]     = useState(false);
  const [chartData, setChartData]     = useState([]);
  const [chartLoading, setChartLoading] = useState(false);
  const [intervalNum, setIntervalNum] = useState(1);
  const [intervalUnit, setIntervalUnit] = useState('hour');
  const [chartSources, setChartSources] = useState(
    new Set(ALL_SOURCES.filter(s => s !== 'MFT'))
  );

  const toggleSource = (src) => {
    setSources(prev => {
      const n = new Set(prev);
      n.has(src) ? n.delete(src) : n.add(src);
      return n;
    });
    setPage(0);
  };

  const buildDateParam = (date, time, isEnd) => {
    if (!date) return '';
    if (time) return `${date}T${time}:00`;
    return isEnd ? `${date}T23:59:59` : `${date}T00:00:00`;
  };

  const fetchTimeline = async (p = 0, flt = filters, df = dateFrom, dt = dateTo, srcs = sources, tf = timeFrom, tt = timeTo) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: p, page_size: PAGE_SIZE,
        date_from: buildDateParam(df, tf, false),
        date_to:   buildDateParam(dt, tt, true),
        filters: (flt || []).join('||'),
        sources: [...srcs].join(','),
      });
      const r = await fetch(
        `${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/timeline?${params}`,
        { credentials: 'include', headers: { 'Content-Type': 'application/json' } }
      );
      const d = await r.json();
      setEntries(d.entries || []);
      setTotal(d.total || 0);
      setPage(p);
    } catch { setEntries([]); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchTimeline(0); }, [assetId, sources, dateFrom, dateTo, timeFrom, timeTo, filters]);

  useEffect(() => {
    if (showChart) fetchChartData();
  }, [filters, sources, dateFrom, dateTo, timeFrom, timeTo]);

  const addFilter = () => {
    const val = filterInput.trim();
    if (!val || filters.includes(val)) return;
    const newFilters = [...filters, val];
    setFilters(newFilters);
    setFilterInput('');
    fetchTimeline(0, newFilters);
  };

  const removeFilter = (f) => {
    const newFilters = filters.filter(x => x !== f);
    setFilters(newFilters);
    fetchTimeline(0, newFilters);
  };

  const fetchChartData = async () => {
    setChartLoading(true);
    try {
      const hasDateRange = dateFrom || dateTo;
      // With a date range: fetch all events in the window (no cap)
      // Without: use first 5000 rows as a representative sample
      const fetchPage = async (page, acc = []) => {
        const params = new URLSearchParams({
          page, page_size: 2000,
          date_from: buildDateParam(dateFrom, timeFrom, false),
          date_to:   buildDateParam(dateTo, timeTo, true),
          filters: filters.join('||'),
          sources: [...chartSources].join(','),
        });
        const r = await fetch(
          `${import.meta.env.VITE_API_URL}/api/mitre/evidence/${assetId}/timeline?${params}`,
          { credentials: 'include', headers: { 'Content-Type': 'application/json' } }
        );
        const d = await r.json();
        const combined = [...acc, ...(d.entries || [])];
        // If date range set, paginate through all results; otherwise stop at first page
        if (hasDateRange && d.entries?.length === 2000 && combined.length < 50000) {
          return fetchPage(page + 1, combined);
        }
        return { entries: combined, total: d.total || 0 };
      };
      const { entries, total } = await fetchPage(0);

      // Bucket by interval
      const unitMs = { second: 1000, minute: 60000, hour: 3600000, day: 86400000 };
      const bucketMs = intervalNum * (unitMs[intervalUnit] || 3600000);

      const buckets = {};
      entries.forEach(e => {
        if (!e.ts) return;
        const t = new Date(e.ts).getTime();
        const bucket = Math.floor(t / bucketMs) * bucketMs;
        if (!buckets[bucket]) buckets[bucket] = { ts: bucket };
        const src = e.source.replace('EVENT_LOGS_', 'EVT_');
        buckets[bucket][src] = (buckets[bucket][src] || 0) + 1;
      });

      const sorted = Object.values(buckets).sort((a, b) => a.ts - b.ts).map(b => ({
        ...b,
        label: (() => {
          const d = new Date(b.ts);
          if (intervalUnit === 'day') return d.toISOString().slice(0, 10);
          if (intervalUnit === 'hour' || intervalUnit === 'minute') return d.toISOString().slice(0, 16).replace('T', ' ');
          return d.toISOString().slice(0, 19).replace('T', ' ');
        })(),
      }));
      setChartData(sorted);
    } catch(e) { console.error(e); }
    finally { setChartLoading(false); }
  };

  const toggleChartSource = (src) => {
    setChartSources(prev => {
      const n = new Set(prev);
      n.has(src) ? n.delete(src) : n.add(src);
      return n;
    });
  };

  const fmtTs = (iso) => {
    if (!iso) return '---';
    try {
      const d = new Date(iso);
      return d.toISOString().replace('T', ' ').replace('Z', '').slice(0, 19);
    } catch { return iso; }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, padding: '6px 12px',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, alignItems: 'center' }}>

        {/* Date + time range pickers */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ color: C.greyDim, fontSize: 9 }}>FROM</span>
          <input type="date" value={dateFrom}
            onChange={e => { setDateFrom(e.target.value); setPage(0); }}
            style={{ ...Inp, width: 125, fontSize: 10, colorScheme: 'dark' }} />
          <input type="time" value={timeFrom}
            onChange={e => { setTimeFrom(e.target.value); setPage(0); }}
            style={{ ...Inp, width: 85, fontSize: 10, colorScheme: 'dark' }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ color: C.greyDim, fontSize: 9 }}>TO</span>
          <input type="date" value={dateTo}
            onChange={e => { setDateTo(e.target.value); setPage(0); }}
            style={{ ...Inp, width: 125, fontSize: 10, colorScheme: 'dark' }} />
          <input type="time" value={timeTo}
            onChange={e => { setTimeTo(e.target.value); setPage(0); }}
            style={{ ...Inp, width: 85, fontSize: 10, colorScheme: 'dark' }} />
        </div>
        {(dateFrom || dateTo) && (
          <button onClick={() => { setDateFrom(''); setDateTo(''); setTimeFrom(''); setTimeTo(''); setPage(0); }}
            style={{ ...Btn, fontSize: 9, padding: '3px 7px', color: C.greyDim }}>CLR</button>
        )}

        {/* Filter stack */}
        <input placeholder="ADD FILTER..." value={filterInput}
          onChange={e => setFilterInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && addFilter()}
          style={{ ...Inp, width: 180, fontSize: 10 }} />
        <button onClick={addFilter} style={{ ...Btn, fontSize: 9, padding: '3px 8px' }}>+ ADD</button>

        <span style={{ color: C.greyDim, fontSize: 9, marginLeft: 4 }}>
          {total.toLocaleString()} EVENTS
        </span>
      </div>

      {/* Active filter pills */}
      {filters.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '4px 12px',
          borderBottom: `1px solid ${C.border}`, flexShrink: 0, alignItems: 'center' }}>
          <span style={{ color: C.greyDim, fontSize: 9, marginRight: 4 }}>FILTERS:</span>
          {filters.map((f, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 3,
              background: 'rgba(255,170,0,0.1)', border: '1px solid #ffaa00',
              padding: '1px 6px', fontSize: 9, color: '#ffaa00', fontFamily: 'monospace' }}>
              <span>{f}</span>
              <button onClick={() => removeFilter(f)} style={{
                background: 'none', border: 'none', color: '#ffaa00', cursor: 'pointer',
                fontSize: 10, padding: '0 0 0 3px', lineHeight: 1, fontFamily: 'monospace'
              }}>×</button>
            </div>
          ))}
          <button onClick={() => { setFilters([]); fetchTimeline(0, []); }}
            style={{ ...Btn, fontSize: 8, padding: '1px 6px', color: C.greyDim }}>CLR ALL</button>
        </div>
      )}

      {/* Visualize toggle button */}
      <div style={{ padding: '4px 12px', borderBottom: `1px solid ${C.border}`, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
        <button onClick={() => setShowChart(c => !c)} style={{
          ...Btn, fontSize: 9, padding: '3px 10px',
          background: showChart ? C.green + '22' : 'transparent',
          color: showChart ? C.green : C.greyDim,
          border: `1px solid ${showChart ? C.green : C.border}`,
        }}>📊 VISUALIZE</button>
        {showChart && (
          <>
            <span style={{ color: C.greyDim, fontSize: 9 }}>INTERVAL</span>
            <select value={intervalNum} onChange={e => setIntervalNum(Number(e.target.value))}
              style={{ ...Inp, width: 55, fontSize: 10, padding: '2px 4px' }}>
              {[1,2,5,10,15,30].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
            <select value={intervalUnit} onChange={e => setIntervalUnit(e.target.value)}
              style={{ ...Inp, width: 80, fontSize: 10, padding: '2px 4px' }}>
              <option value="second">SECOND</option>
              <option value="minute">MINUTE</option>
              <option value="hour">HOUR</option>
              <option value="day">DAY</option>
            </select>
            <button onClick={fetchChartData} style={{ ...Btn, fontSize: 9, padding: '3px 10px',
              background: C.green, color: '#000', fontWeight: 'bold' }}>
              {chartLoading ? 'LOADING...' : 'GENERATE'}
            </button>
          </>
        )}
      </div>

      {/* Chart panel */}
      {showChart && chartData.length > 0 && (
        <div style={{ height: 180, flexShrink: 0, padding: '8px 4px 0 4px',
          borderBottom: `1px solid ${C.border}`, background: '#020202' }}>
          {/* Chart source toggles */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, padding: '0 8px 4px 8px' }}>
            {ALL_SOURCES.filter(s => s !== 'MFT').map(src => {
              const active = chartSources.has(src);
              const col = SOURCE_COLORS[src] || C.greyDim;
              return (
                <button key={src} onClick={() => toggleChartSource(src)} style={{
                  background: active ? col + '22' : 'transparent',
                  border: `1px solid ${active ? col : C.border}`,
                  color: active ? col : C.greyDim,
                  fontSize: 8, padding: '1px 5px', cursor: 'pointer', fontFamily: 'monospace',
                }}>{src.replace('EVENT_LOGS_', 'EVT_')}</button>
              );
            })}
            <button onClick={() => toggleChartSource('MFT')} style={{
              background: chartSources.has('MFT') ? SOURCE_COLORS.MFT + '22' : 'transparent',
              border: `1px solid ${chartSources.has('MFT') ? SOURCE_COLORS.MFT : C.border}`,
              color: chartSources.has('MFT') ? SOURCE_COLORS.MFT : C.greyDim,
              fontSize: 8, padding: '1px 5px', cursor: 'pointer', fontFamily: 'monospace',
            }}>MFT</button>
          </div>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={chartData} margin={{ top: 0, right: 8, left: -20, bottom: 0 }}>
              <XAxis dataKey="label" tick={{ fill: '#444', fontSize: 8 }} interval="preserveStartEnd" />
              <YAxis tick={{ fill: '#444', fontSize: 8 }} />
              <Tooltip
                contentStyle={{ background: '#0a0a0a', border: '1px solid #333', fontSize: 10, fontFamily: 'monospace' }}
                labelStyle={{ color: C.green }}
                itemStyle={{ color: '#ccc' }}
              />
              {[...chartSources].map(src => (
                <Bar key={src} dataKey={src.replace('EVENT_LOGS_', 'EVT_')}
                  stackId="a" fill={SOURCE_COLORS[src] || C.greyDim} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Source filter pills */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '4px 12px',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0 }}>
        {ALL_SOURCES.map(src => {
          const active = sources.has(src);
          const col = SOURCE_COLORS[src] || C.greyDim;
          return (
            <button key={src} onClick={() => toggleSource(src)} style={{
              background: active ? col + '22' : 'transparent',
              border: `1px solid ${active ? col : C.border}`,
              color: active ? col : C.greyDim,
              fontSize: 9, padding: '2px 7px', cursor: 'pointer',
              fontFamily: 'monospace', letterSpacing: 0.5,
            }}>{src.replace('EVENT_LOGS_', 'EVT_')}</button>
          );
        })}
      </div>

      {/* Column headers */}
      <div style={{ display: 'flex', padding: '3px 12px', background: '#0a0a0a',
        borderBottom: `1px solid ${C.border}`, flexShrink: 0, fontSize: 9,
        color: C.greyDim, letterSpacing: 1, gap: 0 }}>
        <span style={{ width: 155, flexShrink: 0 }}>TIMESTAMP (UTC)</span>
        <span style={{ width: 160, flexShrink: 0 }}>SOURCE</span>
        <span style={{ width: 80, flexShrink: 0 }}>FLAG</span>
        <span style={{ flex: 1 }}>TITLE / DETAIL</span>
        <span style={{ width: 100, flexShrink: 0, textAlign: 'right' }}>EXTRA</span>
      </div>

      {/* Entries */}
      <div style={{ flex: 1, overflowY: 'auto', fontFamily: 'monospace' }}>
        {loading ? (
          <div style={{ color: C.green, fontSize: 12, padding: 16 }}>ASSEMBLING_TIMELINE...</div>
        ) : entries.length === 0 ? (
          <div style={{ color: C.greyDim, fontSize: 12, padding: 16 }}>NO_EVENTS_IN_RANGE</div>
        ) : entries.map((e, i) => {
          const srcCol  = SOURCE_COLORS[e.source] || C.greyDim;
          const flagCol = FLAG_COLORS[e.flag] || C.greyDim;
          const isExp   = expanded.has(i);
          return (
            <div key={i}
              onClick={() => setExpanded(prev => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n; })}
              style={{
                display: 'flex', alignItems: 'flex-start', padding: '4px 12px',
                borderBottom: `1px solid #0a0a0a`, cursor: 'pointer',
                background: isExp ? 'rgba(255,65,65,0.04)' : 'transparent',
                transition: 'background 0.1s',
              }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
              onMouseLeave={ev => ev.currentTarget.style.background = isExp ? 'rgba(255,65,65,0.04)' : 'transparent'}
            >
              <span style={{ width: 155, flexShrink: 0, color: C.greyDim, fontSize: 10 }}>{fmtTs(e.ts)}</span>
              <span style={{ width: 160, flexShrink: 0, color: srcCol, fontSize: 10, fontWeight: 'bold' }}>
                {e.source.replace('EVENT_LOGS_', 'EVT_')}
              </span>
              <span style={{ width: 80, flexShrink: 0, fontSize: 9,
                color: flagCol, background: flagCol + '18',
                padding: '1px 4px', border: `1px solid ${flagCol}44`, textAlign: 'center' }}>
                {e.flag}
              </span>
              <div style={{ flex: 1, paddingLeft: 8, minWidth: 0 }}>
                <div style={{ color: C.white, fontSize: 10, fontWeight: 'bold',
                  whiteSpace: isExp ? 'normal' : 'nowrap',
                  overflow: isExp ? 'visible' : 'hidden',
                  textOverflow: isExp ? 'unset' : 'ellipsis' }}>
                  {highlight(e.title, filters)}
                </div>
                {(isExp || e.detail) && (
                  <div style={{ color: C.greyDim, fontSize: 9, marginTop: 2,
                    whiteSpace: isExp ? 'pre-wrap' : 'nowrap',
                    overflow: isExp ? 'visible' : 'hidden',
                    textOverflow: isExp ? 'unset' : 'ellipsis',
                    maxWidth: '100%' }}>
                    {highlight(e.detail, filters)}
                  </div>
                )}
              </div>
              <span style={{ width: 100, flexShrink: 0, textAlign: 'right',
                color: C.greyDim, fontSize: 9 }}>{highlight(e.extra, filters)}</span>
            </div>
          );
        })}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center',
          gap: 12, padding: '6px 12px', borderTop: `1px solid ${C.border}`, flexShrink: 0 }}>
          <button onClick={() => fetchTimeline(page - 1)} disabled={page === 0}
            style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: page === 0 ? C.greyDim : C.white }}>◀ PREV</button>
          <span style={{ color: C.greyDim, fontSize: 10 }}>
            PAGE {page + 1} / {totalPages} · {total.toLocaleString()} EVENTS
          </span>
          <button onClick={() => fetchTimeline(page + 1)} disabled={page >= totalPages - 1}
            style={{ ...Btn, fontSize: 9, padding: '3px 10px', color: page >= totalPages - 1 ? C.greyDim : C.white }}>NEXT ▶</button>
        </div>
      )}
    </div>
  );
};
