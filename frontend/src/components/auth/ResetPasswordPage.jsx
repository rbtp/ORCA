import React, { useState, useEffect } from 'react';

// Public, token-gated page for /reset-password/:token -- used for both
// admin-initiated and self-service ("forgot password") resets, since the
// backend stores both in the same password_reset_tokens table.
export default function ResetPasswordPage({ token }) {
  const [status, setStatus] = useState('LOADING'); // LOADING | READY | INVALID | DONE
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(`/api/auth/reset-password/${token}`);
        if (!res.ok) { setStatus('INVALID'); return; }
        const data = await res.json();
        setUsername(data.username);
        setStatus('READY');
      } catch {
        setStatus('INVALID');
      }
    })();
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (password.length < 8) { setError('PASSWORD_MUST_BE_AT_LEAST_8_CHARACTERS'); return; }
    if (password !== confirm) { setError('PASSWORDS_DO_NOT_MATCH'); return; }
    setSubmitting(true);
    try {
      const res = await fetch(`/api/auth/reset-password/${token}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      if (res.ok) {
        setStatus('DONE');
      } else {
        const data = await res.json().catch(() => ({}));
        setError(data.detail || `RESET_FAILED (${res.status})`);
      }
    } catch (err) {
      setError(`COULD_NOT_REACH_SERVER: ${err.message}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={Overlay}>
      <div style={Box}>
        {status === 'LOADING' && <div style={Muted}>VERIFYING_LINK...</div>}

        {status === 'INVALID' && (
          <>
            <h2 style={{ color: '#ff4141', margin: '0 0 10px 0' }}>[ LINK_INVALID_OR_EXPIRED ]</h2>
            <div style={Muted}>This reset link is no longer valid. Request a new one, or ask your administrator.</div>
          </>
        )}

        {status === 'DONE' && (
          <>
            <h2 style={{ color: '#00ff41', margin: '0 0 10px 0' }}>[ PASSWORD_UPDATED ]</h2>
            <div style={Muted}>Your password has been changed. You can now log in.</div>
            <a href="/" style={LinkBtn}>GO_TO_LOGIN</a>
          </>
        )}

        {status === 'READY' && (
          <>
            <h2 style={{ color: '#00ff41', margin: '0 0 6px 0' }}>[ RESET_PASSWORD ]</h2>
            <div style={Muted}>Setting a new password for <strong style={{ color: '#eee' }}>{username}</strong></div>
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '15px', marginTop: '20px' }}>
              <input
                type="password" placeholder="NEW_PASSWORD" value={password}
                onChange={(e) => setPassword(e.target.value)} style={InputStyle} autoFocus
              />
              <input
                type="password" placeholder="CONFIRM_PASSWORD" value={confirm}
                onChange={(e) => setConfirm(e.target.value)} style={InputStyle}
              />
              {error && <div style={ErrorText}>{error}</div>}
              <button type="submit" disabled={submitting} style={{ ...SubmitBtn, opacity: submitting ? 0.5 : 1 }}>
                {submitting ? 'UPDATING...' : 'SET_NEW_PASSWORD'}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

const Overlay = { height: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center', background: '#000', fontFamily: 'monospace' };
const Box = { width: 420, border: '1px solid #00ff41', padding: '40px', background: '#050505', boxShadow: '0 0 20px rgba(0, 255, 65, 0.2)' };
const Muted = { color: '#aaa', fontSize: '12px', lineHeight: 1.6 };
const InputStyle = { background: '#000', border: '1px solid #333', color: '#00ff41', padding: '10px', fontFamily: 'monospace' };
const SubmitBtn = { background: '#00ff41', color: '#000', border: 'none', padding: '10px', fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace' };
const ErrorText = { color: '#ff4141', fontSize: '11px' };
const LinkBtn = { display: 'inline-block', marginTop: '16px', color: '#00ff41', textDecoration: 'none', border: '1px solid #00ff41', padding: '8px 16px', fontSize: '12px' };
