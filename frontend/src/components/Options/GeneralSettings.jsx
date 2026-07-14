import React, { useState } from 'react';

const DEFAULT_BRIGHTNESS = 1.0;
const LS_KEY = 'orca-text-brightness';

export default function GeneralSettings() {
  const [brightness, setBrightness] = useState(() => {
    const saved = localStorage.getItem(LS_KEY);
    const parsed = parseFloat(saved);
    return isNaN(parsed) ? DEFAULT_BRIGHTNESS : parsed;
  });

  const apply = (val) => {
    document.documentElement.style.setProperty('--text-brightness', val);
    localStorage.setItem(LS_KEY, val);
    setBrightness(val);
  };

  const reset = () => apply(DEFAULT_BRIGHTNESS);

  return (
    <div style={{ fontFamily: 'monospace', color: '#eee', maxWidth: '800px' }}>

      <div style={{ marginBottom: '40px' }}>
        <h2 style={{ color: '#ffaa00', letterSpacing: '8px', fontSize: '22px', margin: 0, fontWeight: 900 }}>
          GENERAL_SETTINGS
        </h2>
        <div style={{ color: '#222', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
          DISPLAY // USER_EXPERIENCE
        </div>
      </div>

      <section style={{ border: '1px solid #111', padding: '28px', background: '#030303' }}>
        <div style={{ color: '#333', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          TEXT_CLARITY
        </div>

        <div style={{ color: '#444', fontSize: '10px', lineHeight: '1.7', marginBottom: '28px' }}>
          Adjusts brightness of all text elements across every panel, modal, and overlay.
          Default is 1.00 — the current calibrated appearance.
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '8px' }}>
          <span style={{ color: '#333', fontSize: '9px', letterSpacing: '1px', minWidth: '28px', textAlign: 'right' }}>
            DIM
          </span>
          <div style={{ flex: 1, position: 'relative' }}>
            <input
              type="range"
              min="0.6"
              max="2.5"
              step="0.01"
              value={brightness}
              onChange={e => apply(parseFloat(e.target.value))}
              style={{
                width: '100%',
                accentColor: '#00ff41',
                cursor: 'pointer',
                background: 'transparent',
              }}
            />
          </div>
          <span style={{ color: '#333', fontSize: '9px', letterSpacing: '1px', minWidth: '40px' }}>
            BRIGHT
          </span>
          <span style={{
            color: '#00ff41', fontSize: '13px', fontWeight: 'bold',
            minWidth: '40px', textAlign: 'right',
          }}>
            {brightness.toFixed(2)}
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '28px', paddingLeft: '44px', paddingRight: '112px' }}>
          <span style={{ color: '#1a1a1a', fontSize: '8px' }}>0.6</span>
          <span style={{ color: brightness === DEFAULT_BRIGHTNESS ? '#333' : '#1a1a1a', fontSize: '8px' }}>1.0</span>
          <span style={{ color: '#1a1a1a', fontSize: '8px' }}>2.5</span>
        </div>

        <button
          onClick={reset}
          disabled={brightness === DEFAULT_BRIGHTNESS}
          style={{
            padding: '9px 22px',
            background: 'none',
            border: `1px solid ${brightness === DEFAULT_BRIGHTNESS ? '#1a1a1a' : '#333'}`,
            color: brightness === DEFAULT_BRIGHTNESS ? '#1a1a1a' : '#555',
            cursor: brightness === DEFAULT_BRIGHTNESS ? 'not-allowed' : 'pointer',
            fontFamily: 'monospace',
            fontSize: '10px',
            letterSpacing: '2px',
            transition: 'all 0.15s',
          }}
          onMouseEnter={e => {
            if (brightness !== DEFAULT_BRIGHTNESS) {
              e.currentTarget.style.borderColor = '#00ff41';
              e.currentTarget.style.color = '#00ff41';
            }
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = brightness === DEFAULT_BRIGHTNESS ? '#1a1a1a' : '#333';
            e.currentTarget.style.color = brightness === DEFAULT_BRIGHTNESS ? '#1a1a1a' : '#555';
          }}
        >
          RESET_DEFAULT
        </button>
      </section>

    </div>
  );
}
