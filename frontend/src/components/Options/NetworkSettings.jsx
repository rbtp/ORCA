import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';

const API = `${import.meta.env.VITE_API_URL}/api/network`;

const getAuthHeaders = () => ({ 'Content-Type': 'application/json' });

const fmtDate = (iso) => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString('en-CA'); // YYYY-MM-DD
  } catch { return iso; }
};

const dayColor = (days) => {
  if (days === null || days === undefined) return '#555';
  if (days > 90) return '#00ff41';
  if (days > 30) return '#ffaa00';
  return '#ff4444';
};

export default function NetworkSettings() {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [certInfo, setCertInfo]           = useState(null);
  const [certLoading, setCertLoading]     = useState(true);
  const [identity, setIdentity]           = useState(null);
  const [identityLoading, setIdentityLoading] = useState(true);
  const [regenerating, setRegenerating]   = useState(false);
  const [confirmOpen, setConfirmOpen]     = useState(false);
  const [status, setStatus]               = useState(null); // {type: 'success'|'error', text}

  const fetchCertInfo = async () => {
    setCertLoading(true);
    try {
      const r = await fetch(`${API}/cert-info`, { credentials: 'include', headers: getAuthHeaders() });
      if (r.ok) setCertInfo(await r.json());
      else setCertInfo(null);
    } catch { setCertInfo(null); }
    finally { setCertLoading(false); }
  };

  const fetchIdentity = async () => {
    setIdentityLoading(true);
    try {
      const r = await fetch(`${API}/detected-identity`, { credentials: 'include', headers: getAuthHeaders() });
      if (r.ok) setIdentity(await r.json());
    } catch { }
    finally { setIdentityLoading(false); }
  };

  useEffect(() => {
    fetchCertInfo();
    fetchIdentity();
  }, []);

  const handleRegenerate = async () => {
    setConfirmOpen(false);
    setRegenerating(true);
    setStatus(null);
    try {
      const r = await fetch(`${API}/regenerate-cert`, {
        method: 'POST',
        credentials: 'include',
        headers: getAuthHeaders(),
      });
      const data = await r.json();
      if (r.ok) {
        setStatus({ type: 'success', text: data.message });
        // Refresh cert info after backend restarts (give it 5s)
        setTimeout(fetchCertInfo, 5000);
      } else {
        setStatus({ type: 'error', text: data.detail || 'REGEN_FAILED' });
      }
    } catch (e) {
      setStatus({ type: 'error', text: e.message });
    } finally {
      setRegenerating(false);
    }
  };

  return (
    <div style={{ fontFamily: 'monospace', color: '#eee', maxWidth: '800px' }}>

      {/* Header */}
      <div style={{ marginBottom: '40px' }}>
        <h2 style={{ color: '#ffaa00', letterSpacing: '8px', fontSize: '22px', margin: 0, fontWeight: 900 }}>
          NETWORK_SETTINGS
        </h2>
        <div style={{ color: '#222', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
          TLS CERTIFICATE MANAGEMENT // ORCA INTERNAL CA
        </div>
      </div>

      {/* Status banner */}
      {status && (
        <div style={{
          padding: '12px 16px', marginBottom: '24px', fontSize: '11px',
          background: status.type === 'success' ? 'rgba(0,255,65,0.06)' : 'rgba(255,68,68,0.06)',
          border: `1px solid ${status.type === 'success' ? '#00ff41' : '#ff4444'}`,
          color: status.type === 'success' ? '#00ff41' : '#ff4444',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        }}>
          <span>{status.type === 'success' ? '✓' : '✗'} {status.text}</span>
          <button onClick={() => setStatus(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '16px' }}>×</button>
        </div>
      )}

      {/* TLS Certificate section */}
      <section style={{ border: '1px solid #111', padding: '28px', marginBottom: '24px', background: '#030303' }}>
        <div style={{ color: '#333', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          TLS_CERTIFICATE
        </div>

        {certLoading ? (
          <div style={{ color: '#333', fontSize: '11px' }}>READING_CERT...</div>
        ) : !certInfo || !certInfo.cert_exists ? (
          <div style={{ color: '#ff4444', fontSize: '11px', letterSpacing: '1px' }}>NO_CERTIFICATE_FOUND</div>
        ) : (
          <div style={{ display: 'grid', gap: '14px' }}>
            <Row label="KEY_TYPE"  value={certInfo.key_type || '—'} />
            <Row label="EXPIRES"
              value={`${fmtDate(certInfo.not_after)} `}
              extra={
                certInfo.days_remaining !== null
                  ? <span style={{ color: dayColor(certInfo.days_remaining), fontSize: '10px' }}>
                      ({certInfo.days_remaining}d remaining)
                    </span>
                  : null
              }
            />
            <div>
              <div style={{ color: '#333', fontSize: '9px', letterSpacing: '2px', marginBottom: '8px' }}>SUBJECT_ALT_NAMES</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {certInfo.sans.length > 0
                  ? certInfo.sans.map((s, i) => (
                      <span key={i} style={{
                        padding: '3px 10px', background: '#0a0a0a', border: '1px solid #1a1a1a',
                        color: s.startsWith('IP:') ? '#00b8ff' : '#ffaa00', fontSize: '10px',
                      }}>{s}</span>
                    ))
                  : <span style={{ color: '#333', fontSize: '10px' }}>NO_SANS_DETECTED</span>
                }
              </div>
            </div>
          </div>
        )}
      </section>

      {/* Server Identity section */}
      <section style={{ border: '1px solid #111', padding: '28px', marginBottom: '24px', background: '#030303' }}>
        <div style={{ color: '#333', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          DETECTED_SERVER_IDENTITY
        </div>
        {identityLoading ? (
          <div style={{ color: '#333', fontSize: '11px' }}>PROBING...</div>
        ) : identity ? (
          <div style={{ display: 'grid', gap: '14px' }}>
            <Row label="OUTBOUND_IP" value={identity.ip} valueColor="#00b8ff" />
            <Row label="HOSTNAME"    value={identity.hostname} valueColor="#ffaa00" />
            <div style={{ color: '#1a1a1a', fontSize: '9px', marginTop: '4px' }}>
              New cert SAN will cover: IP:{identity.ip}, DNS:{identity.hostname}, DNS:localhost
            </div>
          </div>
        ) : (
          <div style={{ color: '#ff4444', fontSize: '11px' }}>IDENTITY_PROBE_FAILED</div>
        )}
      </section>

      {/* Regenerate section */}
      {isAdmin ? (
        <section style={{ border: '1px solid #1a1200', padding: '28px', background: '#030303' }}>
          <div style={{ color: '#333', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
            CERTIFICATE_OPERATIONS
          </div>

          {/* Warning */}
          <div style={{
            padding: '12px 16px', marginBottom: '20px', fontSize: '10px',
            background: 'rgba(255,170,0,0.04)', border: '1px solid #1a1200',
            color: '#ffaa00', lineHeight: '1.6',
          }}>
            ⚠ Regeneration replaces the current certificate. The backend will restart
            (~2s downtime). Nginx will pick up the new cert within 10s.
            Browsers will show a security warning on the next visit — click "proceed anyway" to continue.
          </div>

          <button
            onClick={() => setConfirmOpen(true)}
            disabled={regenerating}
            style={{
              padding: '12px 28px', background: 'none',
              border: `1px solid ${regenerating ? '#333' : '#ffaa00'}`,
              color: regenerating ? '#333' : '#ffaa00',
              cursor: regenerating ? 'not-allowed' : 'pointer',
              fontFamily: 'monospace', fontSize: '11px', fontWeight: 'bold',
              letterSpacing: '2px', transition: 'all 0.15s',
            }}
          >
            {regenerating ? 'REGENERATING...' : 'REGENERATE_CERTIFICATE'}
          </button>
        </section>
      ) : (
        <section style={{ border: '1px solid #111', padding: '20px', background: '#030303' }}>
          <div style={{ color: '#333', fontSize: '10px', letterSpacing: '2px' }}>
            CERTIFICATE_OPERATIONS — ADMIN_ACCESS_REQUIRED
          </div>
        </section>
      )}

      {/* Confirm modal */}
      {confirmOpen && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000,
        }}>
          <div style={{
            background: '#050505', border: '1px solid #1a1200', padding: '40px',
            maxWidth: '460px', width: '100%', fontFamily: 'monospace',
          }}>
            <div style={{ color: '#ffaa00', fontSize: '14px', fontWeight: 900, letterSpacing: '4px', marginBottom: '20px' }}>
              CONFIRM_CERT_REGEN
            </div>
            {identity && (
              <div style={{ color: '#444', fontSize: '11px', marginBottom: '20px', lineHeight: '1.8' }}>
                New certificate will cover:<br />
                <span style={{ color: '#00b8ff' }}>IP: {identity.ip}</span><br />
                <span style={{ color: '#ffaa00' }}>DNS: {identity.hostname}, localhost</span>
              </div>
            )}
            <div style={{ color: '#333', fontSize: '10px', marginBottom: '28px' }}>
              Backend restart required (~2s downtime).
            </div>
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => setConfirmOpen(false)}
                style={{ flex: 1, padding: '12px', background: 'none', border: '1px solid #222', color: '#555', cursor: 'pointer', fontFamily: 'monospace' }}
              >
                ABORT
              </button>
              <button
                onClick={handleRegenerate}
                style={{ flex: 1, padding: '12px', background: '#ffaa00', border: 'none', color: '#000', cursor: 'pointer', fontFamily: 'monospace', fontWeight: 'bold' }}
              >
                CONFIRM
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ label, value, valueColor = '#eee', extra }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', gap: '16px', alignItems: 'center' }}>
      <div style={{ color: '#333', fontSize: '9px', letterSpacing: '2px' }}>{label}</div>
      <div style={{ color: valueColor, fontSize: '12px' }}>
        {value}{extra}
      </div>
    </div>
  );
}
