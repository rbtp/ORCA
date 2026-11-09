import React, { useState } from 'react';
import { useAuth } from '../../context/AuthContext';

export default function MyAccount() {
  const { user } = useAuth();
  const [email, setEmail] = useState(user?.email || '');
  const [initials, setInitials] = useState(user?.initials || '');
  const [profileMsg, setProfileMsg] = useState('');
  const [profileSaving, setProfileSaving] = useState(false);

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwMsg, setPwMsg] = useState('');
  const [pwSaving, setPwSaving] = useState(false);

  const handleSaveProfile = async (e) => {
    e.preventDefault();
    setProfileMsg('');
    setProfileSaving(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/me`, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initials, email }),
      });
      const data = await res.json().catch(() => ({}));
      setProfileMsg(res.ok ? 'PROFILE_UPDATED' : (data.detail || `UPDATE_FAILED (${res.status})`));
    } catch (err) {
      setProfileMsg(`COULD_NOT_REACH_SERVER: ${err.message}`);
    } finally {
      setProfileSaving(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setPwMsg('');
    if (newPassword.length < 8) { setPwMsg('NEW_PASSWORD_MUST_BE_AT_LEAST_8_CHARACTERS'); return; }
    if (newPassword !== confirmPassword) { setPwMsg('NEW_PASSWORDS_DO_NOT_MATCH'); return; }
    setPwSaving(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/change-password`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        setPwMsg('PASSWORD_UPDATED');
        setCurrentPassword(''); setNewPassword(''); setConfirmPassword('');
      } else {
        setPwMsg(data.detail || `UPDATE_FAILED (${res.status})`);
      }
    } catch (err) {
      setPwMsg(`COULD_NOT_REACH_SERVER: ${err.message}`);
    } finally {
      setPwSaving(false);
    }
  };

  return (
    <div style={{ fontFamily: 'monospace', color: '#eee', maxWidth: '800px' }}>

      <div style={{ marginBottom: '40px' }}>
        <h2 style={{ color: '#00ff41', letterSpacing: '8px', fontSize: '22px', margin: 0, fontWeight: 900 }}>
          MY_ACCOUNT
        </h2>
        <div style={{ color: '#888', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
          {user?.username?.toUpperCase()} // {user?.role?.toUpperCase()}
        </div>
      </div>

      <section style={{ border: '1px solid #111', padding: '28px', marginBottom: '24px', background: '#030303' }}>
        <div style={{ color: '#999', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          PROFILE
        </div>
        <form onSubmit={handleSaveProfile} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: '360px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>INITIALS</span>
            <input
              value={initials} maxLength={5}
              onChange={(e) => setInitials(e.target.value.toUpperCase())}
              style={InputStyle}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>EMAIL</span>
            <input
              type="email" value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com" style={InputStyle}
            />
            <div style={{ color: '#777', fontSize: '9px', lineHeight: '1.6' }}>
              Used for password-reset links if this instance has outbound email configured.
            </div>
          </div>
          {profileMsg && <div style={{ color: profileMsg === 'PROFILE_UPDATED' ? '#00ff41' : '#ff4141', fontSize: 10 }}>{profileMsg}</div>}
          <button type="submit" disabled={profileSaving} style={{ ...SubmitBtn, opacity: profileSaving ? 0.5 : 1 }}>
            {profileSaving ? 'SAVING...' : 'SAVE_PROFILE'}
          </button>
        </form>
      </section>

      <section style={{ border: '1px solid #111', padding: '28px', background: '#030303' }}>
        <div style={{ color: '#999', fontSize: '9px', letterSpacing: '3px', marginBottom: '20px' }}>
          CHANGE_PASSWORD
        </div>
        <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: '360px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>CURRENT_PASSWORD</span>
            <input
              type="password" value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              style={InputStyle}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>NEW_PASSWORD</span>
            <input
              type="password" value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              style={InputStyle}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <span style={{ color: '#888', fontSize: 9, letterSpacing: 1 }}>CONFIRM_NEW_PASSWORD</span>
            <input
              type="password" value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              style={InputStyle}
            />
          </div>
          {pwMsg && <div style={{ color: pwMsg === 'PASSWORD_UPDATED' ? '#00ff41' : '#ff4141', fontSize: 10 }}>{pwMsg}</div>}
          <button type="submit" disabled={pwSaving} style={{ ...SubmitBtn, opacity: pwSaving ? 0.5 : 1 }}>
            {pwSaving ? 'UPDATING...' : 'UPDATE_PASSWORD'}
          </button>
        </form>
      </section>

    </div>
  );
}

const InputStyle = { background: '#0a0a0a', border: '1px solid #2a2a2a', color: '#eee', fontFamily: 'monospace', fontSize: 12, padding: '10px' };
const SubmitBtn = { background: '#00ff41', color: '#000', border: 'none', padding: '10px', fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace', width: 'fit-content', paddingLeft: 24, paddingRight: 24 };
