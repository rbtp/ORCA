import React from 'react';

export default function GeneralSettings() {
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

      <section style={{ border: '1px solid #111', padding: '28px', background: '#030303' }}>
        <div style={{ color: '#999', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          TEXT_CLARITY
        </div>

        <div style={{ color: '#aaa', fontSize: '10px', lineHeight: '1.7' }}>
          Text legibility is now a fixed part of the color palette rather than a per-session
          adjustment -- the old brightness slider only applied a uniform filter over the whole
          screen, which scaled backgrounds along with text and never actually fixed contrast.
        </div>
      </section>

    </div>
  );
}
