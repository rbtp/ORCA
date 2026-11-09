import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fortawesome/fontawesome-free/css/all.min.css'
import './index.css'
import App from './App.jsx'
// Import the provider
import { AuthProvider } from './context/AuthContext'
import EnrollmentPage from './components/auth/EnrollmentPage.jsx'
import ResetPasswordPage from './components/auth/ResetPasswordPage.jsx'

// Enrollment/reset links (/enroll/:token, /reset-password/:token) are
// public and token-gated -- rendered directly here, before AuthProvider,
// since the person clicking them has no session and shouldn't be routed
// through the normal login gate. No react-router elsewhere in this app,
// so this stays a plain pathname check rather than pulling it in for two
// routes.
const path = window.location.pathname;
const enrollMatch = path.match(/^\/enroll\/([^/]+)\/?$/);
const resetMatch = path.match(/^\/reset-password\/([^/]+)\/?$/);

let publicRoute = null;
if (enrollMatch) publicRoute = <EnrollmentPage token={enrollMatch[1]} />;
else if (resetMatch) publicRoute = <ResetPasswordPage token={resetMatch[1]} />;

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {publicRoute ? publicRoute : (
      <AuthProvider>
        <App />
      </AuthProvider>
    )}
  </StrictMode>,
)