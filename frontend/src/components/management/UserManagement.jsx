import React, { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL;

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [createMode, setCreateMode] = useState('INVITE'); // INVITE | DIRECT
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [editTarget, setEditTarget] = useState(null); // { username, initials, role, email }
  const [linkModal, setLinkModal] = useState(null); // { title, link, emailed }

  const [newUser, setNewUser] = useState({
    username: '', password: '', initials: '', role: 'analyst', email: '',
  });

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API}/api/admin/users`, { credentials: 'include' });
      const data = await res.json();
      if (res.ok && Array.isArray(data)) setUsers(data);
    } catch (err) { console.error("FETCH_ERROR:", err); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchUsers(); }, []);

  const resetCreateForm = () => setNewUser({ username: '', password: '', initials: '', role: 'analyst', email: '' });

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      if (createMode === 'INVITE') {
        const res = await fetch(`${API}/api/admin/users/invite`, {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: newUser.username, initials: newUser.initials, role: newUser.role, email: newUser.email || null }),
        });
        const data = await res.json();
        if (res.ok) {
          setShowForm(false); resetCreateForm(); fetchUsers();
          setLinkModal({
            title: `INVITE_SENT — ${data.username}`,
            link: data.link,
            emailed: data.emailed,
          });
        } else {
          alert(`INVITE_FAILED: ${data.detail}`);
        }
      } else {
        const res = await fetch(`${API}/api/admin/users/create`, {
          method: 'POST', credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: newUser.username, password: newUser.password, initials: newUser.initials, role: newUser.role }),
        });
        if (res.ok) {
          alert("OPERATOR_REGISTERED_SUCCESSFULLY");
          setShowForm(false); resetCreateForm(); fetchUsers();
        } else {
          const errData = await res.json();
          alert(`REGISTRATION_FAILED: ${errData.detail}`);
        }
      }
    } catch (err) {
      alert("NETWORK_CRITICAL_FAILURE");
    }
  };

  const confirmDeleteUser = async () => {
    const username = deleteTarget;
    setDeleteTarget(null); setDeleteConfirmText('');
    try {
      const res = await fetch(`${API}/api/admin/users/${username}`, { method: 'DELETE', credentials: 'include' });
      if (res.ok) fetchUsers();
      else { const err = await res.json(); alert(`PURGE_FAILED: ${err.detail}`); }
    } catch (err) { console.error("PURGE_CONNECTION_ERROR:", err); }
  };

  const handleToggleActive = async (username) => {
    try {
      const res = await fetch(`${API}/api/admin/users/${username}/toggle-active`, { method: 'POST', credentials: 'include' });
      const data = await res.json();
      if (res.ok) fetchUsers();
      else alert(`TOGGLE_FAILED: ${data.detail}`);
    } catch (err) { alert("NETWORK_CRITICAL_FAILURE"); }
  };

  const handleResetPassword = async (username) => {
    try {
      const res = await fetch(`${API}/api/admin/users/${username}/reset-password`, { method: 'POST', credentials: 'include' });
      const data = await res.json();
      if (res.ok) {
        setLinkModal({ title: `RESET_LINK — ${username}`, link: data.link, emailed: data.emailed });
      } else {
        alert(`RESET_FAILED: ${data.detail}`);
      }
    } catch (err) { alert("NETWORK_CRITICAL_FAILURE"); }
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${API}/api/admin/users/${editTarget.username}`, {
        method: 'PATCH', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initials: editTarget.initials, role: editTarget.role, email: editTarget.email }),
      });
      const data = await res.json();
      if (res.ok) { setEditTarget(null); fetchUsers(); }
      else alert(`EDIT_FAILED: ${data.detail}`);
    } catch (err) { alert("NETWORK_CRITICAL_FAILURE"); }
  };

  return (
    <div style={ContainerStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={HeaderStyle}>USER_AUTHORIZATION_REGISTRY</h3>
        <button style={showForm ? CancelBtn : AddBtn} onClick={() => setShowForm(!showForm)}>
          {showForm ? "ABORT_REGISTRATION" : "REGISTER_NEW_OPERATOR +"}
        </button>
      </div>

      {showForm ? (
        <form onSubmit={handleCreateUser} style={FormStyle}>
          <div style={{ gridColumn: 'span 2', display: 'flex', gap: 10 }}>
            <button type="button" onClick={() => setCreateMode('INVITE')}
              style={createMode === 'INVITE' ? ModeTabActive : ModeTab}>EMAIL_INVITE (RECOMMENDED)</button>
            <button type="button" onClick={() => setCreateMode('DIRECT')}
              style={createMode === 'DIRECT' ? ModeTabActive : ModeTab}>SET_PASSWORD_DIRECTLY</button>
          </div>

          <div style={InputGroup}>
            <label style={LabelStyle}>ID_USERNAME</label>
            <input style={InputStyle} value={newUser.username}
              onChange={(e) => setNewUser({...newUser, username: e.target.value})}
              placeholder="e.g. jsmith" required />
          </div>

          {createMode === 'DIRECT' ? (
            <div style={InputGroup}>
              <label style={LabelStyle}>ACCESS_KEY_PASSWORD</label>
              <input type="password" style={InputStyle} value={newUser.password}
                onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                placeholder="••••••••" required />
            </div>
          ) : (
            <div style={InputGroup}>
              <label style={LabelStyle}>EMAIL (OPTIONAL — LINK SHOWN EITHER WAY)</label>
              <input type="email" style={InputStyle} value={newUser.email}
                onChange={(e) => setNewUser({...newUser, email: e.target.value})}
                placeholder="jsmith@example.com" />
            </div>
          )}

          <div style={InputGroup}>
            <label style={LabelStyle}>OPERATOR_INITIALS</label>
            <input style={InputStyle} maxLength="5" value={newUser.initials}
              onChange={(e) => setNewUser({...newUser, initials: e.target.value.toUpperCase()})}
              placeholder="JMS" required />
          </div>
          <div style={InputGroup}>
            <label style={LabelStyle}>ASSIGNED_ROLE</label>
            <select style={InputStyle} value={newUser.role}
              onChange={(e) => setNewUser({...newUser, role: e.target.value})}>
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMINISTRATOR</option>
            </select>
          </div>
          <button type="submit" style={SubmitBtn}>
            {createMode === 'INVITE' ? 'SEND_INVITE' : 'COMMIT_TO_REGISTRY'}
          </button>
        </form>
      ) : (
        <table style={TableStyle}>
          <thead>
            <tr style={HeadRow}>
              <th>OPERATOR</th>
              <th>INITIALS</th>
              <th>ROLE_LEVEL</th>
              <th>EMAIL</th>
              <th>LAST_LOGIN</th>
              <th>STATUS</th>
              <th style={{ textAlign: 'right' }}>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {users.map(u => (
              <tr key={u.username} style={BodyRow}>
                <td>{u.username.toUpperCase()}</td>
                <td style={{color: '#00ff41'}}>[{u.initials}]</td>
                <td>{u.role.toUpperCase()}</td>
                <td style={{ color: '#888', fontSize: 11 }}>{u.email || '—'}</td>
                <td style={{ color: '#888', fontSize: 10 }}>
                  {u.last_login ? new Date(u.last_login).toLocaleString() : 'NEVER'}
                </td>
                <td>
                  {u.is_active
                    ? (<><span style={ActivePulse} /> ACTIVE</>)
                    : (<><span style={InactiveDot} /> DEACTIVATED</>)}
                </td>
                <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                  <button onClick={() => setEditTarget({ username: u.username, initials: u.initials, role: u.role, email: u.email || '' })} style={ActionBtnStyle}>
                    [ EDIT ]
                  </button>
                  <button onClick={() => handleResetPassword(u.username)} style={ActionBtnStyle}>
                    [ RESET_PW ]
                  </button>
                  <button onClick={() => handleToggleActive(u.username)} style={{ ...ActionBtnStyle, color: u.is_active ? '#ffb400' : '#00ff41' }}>
                    [ {u.is_active ? 'DEACTIVATE' : 'ACTIVATE'} ]
                  </button>
                  <button onClick={() => { setDeleteTarget(u.username); setDeleteConfirmText(''); }} style={DeleteBtnStyle}>
                    [ PURGE ]
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {editTarget && (
        <div style={ModalOverlay}>
          <div style={ModalBox}>
            <div style={{ color: '#00ff41', fontSize: 13, fontWeight: 'bold', marginBottom: 16, letterSpacing: 1 }}>
              EDIT_OPERATOR — {editTarget.username.toUpperCase()}
            </div>
            <form onSubmit={handleSaveEdit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={InputGroup}>
                <label style={LabelStyle}>OPERATOR_INITIALS</label>
                <input style={InputStyle} maxLength="5" value={editTarget.initials}
                  onChange={(e) => setEditTarget({...editTarget, initials: e.target.value.toUpperCase()})} required />
              </div>
              <div style={InputGroup}>
                <label style={LabelStyle}>ASSIGNED_ROLE</label>
                <select style={InputStyle} value={editTarget.role}
                  onChange={(e) => setEditTarget({...editTarget, role: e.target.value})}>
                  <option value="analyst">ANALYST</option>
                  <option value="admin">ADMINISTRATOR</option>
                </select>
              </div>
              <div style={InputGroup}>
                <label style={LabelStyle}>EMAIL</label>
                <input type="email" style={InputStyle} value={editTarget.email}
                  onChange={(e) => setEditTarget({...editTarget, email: e.target.value})} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 6 }}>
                <button type="button" onClick={() => setEditTarget(null)} style={CancelBtn}>ABORT</button>
                <button type="submit" style={SubmitBtn}>SAVE_CHANGES</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {linkModal && (
        <div style={ModalOverlay}>
          <div style={ModalBox}>
            <div style={{ color: '#00ff41', fontSize: 13, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>
              {linkModal.title}
            </div>
            <div style={{ color: '#aaa', fontSize: 11, marginBottom: 14, lineHeight: 1.5 }}>
              {linkModal.emailed
                ? 'This link was emailed to the operator. It is also shown below in case you need to hand it off another way.'
                : 'No outbound email is configured on this instance — hand this link to the operator directly.'}
            </div>
            <input readOnly style={InputStyle} value={linkModal.link} onFocus={(e) => e.target.select()} />
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
              <button onClick={() => setLinkModal(null)} style={SubmitBtn}>DONE</button>
            </div>
          </div>
        </div>
      )}

      {deleteTarget && (
        <div style={ModalOverlay}>
          <div style={{ ...ModalBox, border: '1px solid #ff4141' }}>
            <div style={{ color: '#ff4141', fontSize: 13, fontWeight: 'bold', marginBottom: 12, letterSpacing: 1 }}>
              PURGE_OPERATOR — {deleteTarget.toUpperCase()}
            </div>
            <div style={{ color: '#aaa', fontSize: 11, marginBottom: 14, lineHeight: 1.5 }}>
              This permanently revokes access for this operator. Type the username <strong style={{ color: '#fff' }}>{deleteTarget}</strong> to confirm.
              Consider DEACTIVATE instead if you may need to restore this account later.
            </div>
            <input
              autoFocus
              style={InputStyle}
              value={deleteConfirmText}
              onChange={(e) => setDeleteConfirmText(e.target.value)}
              placeholder={deleteTarget}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 16 }}>
              <button
                onClick={() => { setDeleteTarget(null); setDeleteConfirmText(''); }}
                style={CancelBtn}
              >
                ABORT
              </button>
              <button
                disabled={deleteConfirmText !== deleteTarget}
                onClick={confirmDeleteUser}
                style={{
                  background: deleteConfirmText === deleteTarget ? '#ff4141' : '#1a0000',
                  border: 'none', color: deleteConfirmText === deleteTarget ? '#000' : '#ff4141',
                  padding: '10px 20px', fontFamily: 'monospace', fontWeight: 'bold',
                  cursor: deleteConfirmText === deleteTarget ? 'pointer' : 'not-allowed',
                  opacity: deleteConfirmText === deleteTarget ? 1 : 0.4,
                }}
              >
                CONFIRM_PURGE
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// STYLES
const ContainerStyle = { padding: '20px', background: '#050505', border: '1px solid #111' };
const HeaderStyle = { color: '#00ff41', fontSize: '14px', letterSpacing: '2px', margin: 0 };
const TableStyle = { width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '12px' };
const HeadRow = { textAlign: 'left', color: '#aaa', borderBottom: '1px solid #111' };
const BodyRow = { borderBottom: '1px solid #0a0a0a', height: '40px' };
const ActivePulse = { display: 'inline-block', width: '8px', height: '8px', background: '#00ff41', borderRadius: '50%', marginRight: '10px', boxShadow: '0 0 5px #00ff41' };
const InactiveDot = { display: 'inline-block', width: '8px', height: '8px', background: '#555', borderRadius: '50%', marginRight: '10px' };

const FormStyle = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', padding: '20px', border: '1px solid #111', background: '#080808' };
const InputGroup = { display: 'flex', flexDirection: 'column', gap: '8px' };
const LabelStyle = { color: '#aaa', fontSize: '9px', fontFamily: 'monospace' };
const InputStyle = { background: '#000', border: '1px solid #222', color: '#00ff41', padding: '10px', fontSize: '12px', fontFamily: 'monospace', outline: 'none', width: '100%', boxSizing: 'border-box' };
const AddBtn = { background: 'none', border: '1px dashed #00ff41', color: '#00ff41', padding: '10px 20px', cursor: 'pointer', fontFamily: 'monospace' };
const CancelBtn = { background: 'none', border: '1px solid #ff4141', color: '#ff4141', padding: '10px 20px', cursor: 'pointer', fontFamily: 'monospace' };
const SubmitBtn = { gridColumn: 'span 2', background: '#00ff41', border: 'none', color: '#000', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace', marginTop: '10px' };
const DeleteBtnStyle = { background: 'none', border: 'none', color: '#ff4141', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px', letterSpacing: '1px', marginLeft: '10px' };
const ActionBtnStyle = { background: 'none', border: 'none', color: '#888', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px', letterSpacing: '1px', marginLeft: '10px' };
const ModeTab = { flex: 1, background: 'none', border: '1px solid #222', color: '#888', padding: '10px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px' };
const ModeTabActive = { ...ModeTab, border: '1px solid #00ff41', color: '#00ff41' };

const ModalOverlay = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 };
const ModalBox = { width: 420, background: '#0a0a0a', border: '1px solid #00ff41', padding: 20, fontFamily: 'monospace' };
