import React from 'react';

const C = {
  green: '#00ff41', red: '#ff4444', amber: '#ffaa00',
  border: '#2a2a2a', bg: '#000', bgCard: '#0d0d0d',
  grey: '#aaaaaa', greyDim: '#777777',
};

const TYPE_STYLE = {
  ACCESS_ATTEMPT: { color: C.amber,  icon: '⚡' },
  KICKBACK:       { color: C.red,    icon: '↩' },
  INFO:           { color: C.green,  icon: '◆' },
};

/**
 * CollabNotificationTray
 *
 * Fixed bottom-right panel. Shows persistent notifications that require
 * explicit analyst dismissal. Each card shows type, message, timestamp,
 * and a [ DISMISS ] button.
 *
 * Also shows SSE connection status dot top-right of the tray.
 *
 * Props:
 *   notifications    — array from useCollaboration
 *   dismissNotification(id) — callback
 *   connected        — boolean
 */
export default function CollabNotificationTray({ notifications, dismissNotification, connected }) {
  if (notifications.length === 0 && connected) return (
    <div style={ConnDot(connected)} title={connected ? 'COLLAB_STREAM: ACTIVE' : 'COLLAB_STREAM: RECONNECTING'} />
  );

  return (
    <div style={TrayWrap}>
      {/* Connection status */}
      <div style={ConnDot(connected)} title={connected ? 'COLLAB_STREAM: ACTIVE' : 'COLLAB_STREAM: RECONNECTING'} />

      {notifications.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 400, overflowY: 'auto' }}>
          {notifications.map(n => {
            const { color, icon } = TYPE_STYLE[n.type] || TYPE_STYLE.INFO;
            const timeStr = n.ts ? n.ts.toLocaleTimeString([], { hour12: false }) : '';
            return (
              <div key={n.id} style={CardStyle(color)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'flex-start', flex: 1 }}>
                    <span style={{ color, fontSize: 12, flexShrink: 0, marginTop: 1 }}>{icon}</span>
                    <div>
                      <div style={{ color, fontSize: 9, letterSpacing: 1, marginBottom: 3 }}>{n.type}</div>
                      <div style={{ color: '#ddd', fontSize: 11, fontFamily: 'monospace', lineHeight: 1.4 }}>
                        {n.message}
                      </div>
                      <div style={{ color: C.greyDim, fontSize: 9, marginTop: 4 }}>[{timeStr}]</div>
                    </div>
                  </div>
                  <button
                    onClick={() => dismissNotification(n.id)}
                    style={DismissBtn}
                  >
                    [ DISMISS ]
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const TrayWrap = {
  position: 'fixed',
  bottom: 20,
  right: 20,
  zIndex: 9999,
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'flex-end',
  gap: 6,
  width: 320,
  fontFamily: 'monospace',
};

const ConnDot = (connected) => ({
  position: 'fixed',
  bottom: 20,
  right: 20,
  width: 8,
  height: 8,
  borderRadius: '50%',
  background: connected ? '#00ff41' : '#ff4444',
  boxShadow: connected ? '0 0 6px #00ff41' : '0 0 6px #ff4444',
  zIndex: 9999,
  cursor: 'default',
});

const CardStyle = (color) => ({
  background: C.bgCard,
  border: `1px solid ${color}`,
  padding: '10px 12px',
  boxShadow: `0 0 12px rgba(0,0,0,0.8)`,
  animation: 'slideIn 0.2s ease',
});

const DismissBtn = {
  background: 'transparent',
  border: '1px solid #333',
  color: C.greyDim,
  fontSize: 9,
  fontFamily: 'monospace',
  padding: '3px 6px',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
  flexShrink: 0,
};
