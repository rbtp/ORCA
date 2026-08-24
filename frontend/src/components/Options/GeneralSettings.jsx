import React, { useState } from 'react';

const TRANSPORT_KEY = 'orca_default_transport';

export default function GeneralSettings() {
  const [defaultTransport, setDefaultTransport] = useState(() => {
    const v = localStorage.getItem(TRANSPORT_KEY);
    return (v === 'WINRM' || v === 'SMB_TASK') ? v : 'SMB_TASK';
  });

  const handleTransportChange = (v) => {
    setDefaultTransport(v);
    localStorage.setItem(TRANSPORT_KEY, v);
  };

  return (
    <div style={{ fontFamily: 'monospace', color: '#eee', maxWidth: '800px' }}>

      <div style={{ marginBottom: '40px' }}>
        <h2 style={{ color: '#ffaa00', letterSpacing: '8px', fontSize: '22px', margin: 0, fontWeight: 900 }}>
          GENERAL_SETTINGS
        </h2>
        <div style={{ color: '#888', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
          DISPLAY // USER_EXPERIENCE
        </div>
      </div>

      <section style={{ border: '1px solid #111', padding: '28px', marginBottom: '24px', background: '#030303' }}>
        <div style={{ color: '#999', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          TEXT_CLARITY
        </div>

        <div style={{ color: '#aaa', fontSize: '10px', lineHeight: '1.7' }}>
          Text legibility is now a fixed part of the color palette rather than a per-session
          adjustment -- the old brightness slider only applied a uniform filter over the whole
          screen, which scaled backgrounds along with text and never actually fixed contrast.
        </div>
      </section>

      <section style={{ border: '1px solid #111', padding: '28px', background: '#030303' }}>
        <div style={{ color: '#999', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          DEPLOY_DEFAULTS
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxWidth: '360px' }}>
          <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>DEFAULT_TRANSPORT</span>
          <select value={defaultTransport} onChange={e => handleTransportChange(e.target.value)}
            style={{
              background: '#0a0a0a', border: '1px solid #2a2a2a', color: '#eee',
              fontFamily: 'monospace', fontSize: 10, padding: '6px 8px',
            }}>
            <option value="SMB_TASK">SMB / SCHTASK</option>
            <option value="WINRM">WINRM</option>
          </select>
          <div style={{ color: '#777', fontSize: '9px', lineHeight: '1.6', marginTop: '4px' }}>
            Pre-selected transport in the Deploy/Triage panel's TRANSPORT dropdown when opening
            a case. This only sets the starting selection — it can still be changed per-deploy.
          </div>
        </div>
      </section>

    </div>
  );
}
