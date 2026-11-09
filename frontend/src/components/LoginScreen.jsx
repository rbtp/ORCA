import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

const LoginScreen = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mode, setMode] = useState('LOGIN'); // LOGIN | FORGOT
  const [forgotInput, setForgotInput] = useState('');
  const [forgotMessage, setForgotMessage] = useState('');
  const [forgotSubmitting, setForgotSubmitting] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(username, password);
    if (!result.success) alert(result.message);
  };

  const handleForgotSubmit = async (e) => {
    e.preventDefault();
    setForgotSubmitting(true);
    setForgotMessage('');
    try {
      const res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username_or_email: forgotInput }),
      });
      const data = await res.json().catch(() => ({}));
      setForgotMessage(data.message || 'If that account exists, a password reset link has been sent.');
    } catch (err) {
      setForgotMessage(`COULD_NOT_REACH_SERVER: ${err.message}`);
    } finally {
      setForgotSubmitting(false);
    }
  };

  return (
    <div style={LoginOverlay}>
      <div style={LoginBox}>
        {mode === 'LOGIN' ? (
          <>
            <h2 style={{color: '#00ff41'}}>[ ORCA_IDENTITY_VERIFICATION ]</h2>
            <form onSubmit={handleSubmit} style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
              <input
                type="text"
                placeholder="USERNAME"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                style={InputStyle}
              />
              <input
                type="password"
                placeholder="PASSWORD"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={InputStyle}
              />
              <button type="submit" style={LoginBtn}>INITIALIZE_SESSION</button>
            </form>
            <div
              onClick={() => { setMode('FORGOT'); setForgotMessage(''); setForgotInput(''); }}
              style={ForgotLink}
            >
              FORGOT_PASSWORD?
            </div>
          </>
        ) : (
          <>
            <h2 style={{color: '#00ff41'}}>[ REQUEST_PASSWORD_RESET ]</h2>
            {forgotMessage ? (
              <div style={{ color: '#aaa', fontSize: '12px', lineHeight: 1.6, marginTop: '10px' }}>{forgotMessage}</div>
            ) : (
              <form onSubmit={handleForgotSubmit} style={{display: 'flex', flexDirection: 'column', gap: '15px'}}>
                <input
                  type="text"
                  placeholder="USERNAME_OR_EMAIL"
                  value={forgotInput}
                  onChange={(e) => setForgotInput(e.target.value)}
                  style={InputStyle}
                  autoFocus
                />
                <button type="submit" disabled={forgotSubmitting} style={{ ...LoginBtn, opacity: forgotSubmitting ? 0.5 : 1 }}>
                  {forgotSubmitting ? 'SENDING...' : 'SEND_RESET_LINK'}
                </button>
              </form>
            )}
            <div onClick={() => setMode('LOGIN')} style={ForgotLink}>
              ← BACK_TO_LOGIN
            </div>
          </>
        )}
      </div>
    </div>
  );
};

// Styles to match your terminal theme
const LoginOverlay = { height: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center', background: '#000' };
const LoginBox = { width: 340, border: '1px solid #00ff41', padding: '40px', background: '#050505', boxShadow: '0 0 20px rgba(0, 255, 65, 0.2)' };
const InputStyle = { background: '#000', border: '1px solid #333', color: '#00ff41', padding: '10px', fontFamily: 'monospace' };
const LoginBtn = { background: '#00ff41', color: '#000', border: 'none', padding: '10px', fontWeight: 'bold', cursor: 'pointer' };
const ForgotLink = { marginTop: '16px', color: '#666', fontSize: '10px', fontFamily: 'monospace', cursor: 'pointer', letterSpacing: '1px', textAlign: 'center' };

export default LoginScreen;
