import React, { useState, useEffect } from 'react';

export default function UserManagement() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  
  // New User State
  const [newUser, setNewUser] = useState({
    username: '',
    password: '',
    initials: '',
    role: 'analyst' // Default role
  });

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/admin/users`, {
        credentials: 'include',
      });
      const data = await res.json();
      if (res.ok && Array.isArray(data)) {
        setUsers(data);
      }
    } catch (err) { console.error("FETCH_ERROR:", err); }
    finally { setLoading(false); }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/admin/users/create`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser)
      });

      if (res.ok) {
        alert("OPERATOR_REGISTERED_SUCCESSFULLY");
        setShowForm(false);
        setNewUser({ username: '', password: '', initials: '', role: 'analyst' });
        fetchUsers(); // Refresh the list
      } else {
        const errData = await res.json();
        alert(`REGISTRATION_FAILED: ${errData.detail}`);
      }
    } catch (err) {
      alert("NETWORK_CRITICAL_FAILURE");
    }
  };

  const handleDeleteUser = async (username) => {
    if (!window.confirm(`CONFIRM_PURGE_REQUEST: ${username.toUpperCase()}?`)) return;

    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/admin/users/${username}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (res.ok) {
        fetchUsers(); // Refresh list
      } else {
        const err = await res.json();
        alert(`PURGE_FAILED: ${err.detail}`);
      }
    } catch (err) {
      console.error("PURGE_CONNECTION_ERROR:", err);
    }
  };

  useEffect(() => { fetchUsers(); }, []);

  return (
    <div style={ContainerStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h3 style={HeaderStyle}>USER_AUTHORIZATION_REGISTRY</h3>
        <button 
          style={showForm ? CancelBtn : AddBtn} 
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? "ABORT_REGISTRATION" : "REGISTER_NEW_OPERATOR +"}
        </button>
      </div>
      
      {showForm ? (
        <form onSubmit={handleCreateUser} style={FormStyle}>
          <div style={InputGroup}>
            <label style={LabelStyle}>ID_USERNAME</label>
            <input 
              style={InputStyle} 
              value={newUser.username}
              onChange={(e) => setNewUser({...newUser, username: e.target.value})}
              placeholder="e.g. jsmith"
              required
            />
          </div>
          <div style={InputGroup}>
            <label style={LabelStyle}>ACCESS_KEY_PASSWORD</label>
            <input 
              type="password"
              style={InputStyle} 
              value={newUser.password}
              onChange={(e) => setNewUser({...newUser, password: e.target.value})}
              placeholder="••••••••"
              required
            />
          </div>
          <div style={InputGroup}>
            <label style={LabelStyle}>OPERATOR_INITIALS</label>
            <input 
              style={InputStyle} 
              maxLength="3"
              value={newUser.initials}
              onChange={(e) => setNewUser({...newUser, initials: e.target.value.toUpperCase()})}
              placeholder="JMS"
              required
            />
          </div>
          <div style={InputGroup}>
            <label style={LabelStyle}>ASSIGNED_ROLE</label>
            <select 
              style={InputStyle} 
              value={newUser.role}
              onChange={(e) => setNewUser({...newUser, role: e.target.value})}
            >
              <option value="analyst">ANALYST</option>
              <option value="admin">ADMINISTRATOR</option>
            </select>
          </div>
          <button type="submit" style={SubmitBtn}>COMMIT_TO_REGISTRY</button>
        </form>
      ) : (
        <table style={TableStyle}>
          <thead>
            <tr style={HeadRow}>
              <th>OPERATOR</th>
              <th>INITIALS</th>
              <th>ROLE_LEVEL</th>
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
                <td><span style={ActivePulse} /> ACTIVE_LINK</td>
                <td style={{ textAlign: 'right' }}>
                  <button 
                    onClick={() => handleDeleteUser(u.username)}
                    style={DeleteBtnStyle}
                  >
                    [ PURGE ]
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// STYLES
const ContainerStyle = { padding: '20px', background: '#050505', border: '1px solid #111' };
const HeaderStyle = { color: '#00ff41', fontSize: '14px', letterSpacing: '2px', margin: 0 };
const TableStyle = { width: '100%', borderCollapse: 'collapse', fontFamily: 'monospace', fontSize: '12px' };
const HeadRow = { textAlign: 'left', color: '#444', borderBottom: '1px solid #111' };
const BodyRow = { borderBottom: '1px solid #0a0a0a', height: '40px' };
const ActivePulse = { display: 'inline-block', width: '8px', height: '8px', background: '#00ff41', borderRadius: '50%', marginRight: '10px', boxShadow: '0 0 5px #00ff41' };

const FormStyle = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', padding: '20px', border: '1px solid #111', background: '#080808' };
const InputGroup = { display: 'flex', flexDirection: 'column', gap: '8px' };
const LabelStyle = { color: '#444', fontSize: '9px', fontFamily: 'monospace' };
const InputStyle = { background: '#000', border: '1px solid #222', color: '#00ff41', padding: '10px', fontSize: '12px', fontFamily: 'monospace', outline: 'none' };
const AddBtn = { background: 'none', border: '1px dashed #00ff41', color: '#00ff41', padding: '10px 20px', cursor: 'pointer', fontFamily: 'monospace' };
const CancelBtn = { background: 'none', border: '1px solid #ff4141', color: '#ff4141', padding: '10px 20px', cursor: 'pointer', fontFamily: 'monospace' };
const SubmitBtn = { gridColumn: 'span 2', background: '#00ff41', border: 'none', color: '#000', padding: '12px', fontWeight: 'bold', cursor: 'pointer', fontFamily: 'monospace', marginTop: '10px' };
const DeleteBtnStyle = { background: 'none', border: 'none', color: '#ff4141', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px', letterSpacing: '1px' };