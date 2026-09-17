import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './stores/authStore';

// Public
import LandingPage from './pages/public/LandingPage';
import LoginPage from './pages/auth/LoginPage';

// Admin
import AdminLayout from './pages/admin/AdminLayout';
import Dashboard from './pages/admin/Dashboard';
import ExamsPage from './pages/admin/ExamsPage';
import ExamDetailPage from './pages/admin/ExamDetailPage';
import UsersPage from './pages/admin/UsersPage';
import SecurityConsolePage from './pages/admin/SecurityConsolePage';
import AuditPage from './pages/admin/AuditPage';
import IncidentsPage from './pages/admin/IncidentsPage';
import ReleasePage from './pages/admin/ReleasePage';
import BreakGlassCenter from './pages/admin/BreakGlassCenter';
import ContainmentPage from './pages/admin/ContainmentPage';

// Authoring
import AuthoringPage from './pages/authoring/AuthoringPage';

// Reviewer
import ReviewerPage from './pages/reviewer/ReviewerPage';

// Candidate
import CandidateLoginPage from './pages/candidate/CandidateLoginPage';
import ExamPage from './pages/candidate/ExamPage';
import ResultPage from './pages/candidate/ResultPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/candidate/login" element={<CandidateLoginPage />} />
      <Route path="/candidate/exam" element={<ExamPage />} />
      <Route path="/candidate/result" element={<ResultPage />} />

      {/* Reviewer Portal */}
      <Route path="/reviewer" element={<ProtectedRoute><ReviewerPage /></ProtectedRoute>} />

      {/* Protected Admin */}
      <Route path="/admin" element={<ProtectedRoute><AdminLayout /></ProtectedRoute>}>
        <Route index element={<Dashboard />} />
        <Route path="exams" element={<ExamsPage />} />
        <Route path="exams/:examId" element={<ExamDetailPage />} />
        <Route path="authoring" element={<AuthoringPage />} />
        <Route path="release" element={<ReleasePage />} />
        <Route path="users" element={<UsersPage />} />
        <Route path="security" element={<SecurityConsolePage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="break-glass" element={<BreakGlassCenter />} />
        <Route path="containment" element={<ContainmentPage />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
