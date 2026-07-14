import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

const LoginScreen = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const result = await login(username, password);
    if (!result.success) alert(result.message);
  };

  return (
    <div style={LoginOverlay}>
      <div style={LoginBox}>
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
      </div>
    </div>
  );
};

// Styles to match your terminal theme
const LoginOverlay = { height: '100vh', display: 'flex', justifyContent: 'center', alignItems: 'center', background: '#000' };
const LoginBox = { border: '1px solid #00ff41', padding: '40px', background: '#050505', boxShadow: '0 0 20px rgba(0, 255, 65, 0.2)' };
const InputStyle = { background: '#000', border: '1px solid #333', color: '#00ff41', padding: '10px', fontFamily: 'monospace' };
const LoginBtn = { background: '#00ff41', color: '#000', border: 'none', padding: '10px', fontWeight: 'bold', cursor: 'pointer' };

export default LoginScreen;