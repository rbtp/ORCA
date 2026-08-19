import React from 'react';

export default function KapeProtocol({ protocolData }) {
  if (!protocolData) return null;

  // Split the pipe-delimited string into an array, or fallback to empty
  const modules = protocolData.kape_modules 
    ? protocolData.kape_modules.split('|') 
    : [];

  const targets = Array.isArray(protocolData.kape_targets) 
    ? protocolData.kape_targets 
    : [];

  return (
    <div style={ContainerStyle}>
      <div style={HeaderStyle}>[ KAPE_FORENSIC_MAP ]</div>
      
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' }}>
        {/* TARGETS SECTION */}
        <section>
          <div style={LabelStyle}>TARGETS (.tkape)</div>
          <div style={DataBox}>
            {targets.length > 0 ? targets.map((t, i) => (
              <div key={i} style={ItemStyle}>
                <span style={Bullet}>&gt;</span> {t}
              </div>
            )) : <div style={DimText}>NO_TARGETS_MAPPED</div>}
          </div>
        </section>

        {/* MODULES SECTION */}
        <section>
          <div style={LabelStyle}>MODULES (.mkape)</div>
          <div style={DataBox}>
            {modules.length > 0 ? modules.map((m, i) => (
              <div key={i} style={ItemStyle}>
                <span style={Bullet}>&gt;</span> {m}
              </div>
            )) : <div style={DimText}>NO_MODULES_MAPPED</div>}
          </div>
        </section>
      </div>
    </div>
  );
}

// Styles to match your existing Investigation UI
const ContainerStyle = { marginTop: '15px', borderTop: '1px solid #222', paddingTop: '15px' };
const HeaderStyle = { color: '#00ff41', fontSize: '10px', fontWeight: 'bold', marginBottom: '10px' };
const LabelStyle = { color: '#666', fontSize: '9px', marginBottom: '5px' };
const DataBox = { background: '#080808', border: '1px solid #111', padding: '10px', minHeight: '60px' };
const ItemStyle = { color: '#ccc', fontSize: '11px', marginBottom: '4px', fontFamily: 'monospace' };
const Bullet = { color: '#00ff41', marginRight: '8px' };
const DimText = { color: '#999', fontSize: '10px' };