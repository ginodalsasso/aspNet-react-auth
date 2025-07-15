import {
    BrowserRouter as Router,
    Routes,
    Route,
    Navigate,
} from 'react-router-dom';

import Register from './pages/Register'
import Login from './pages/Login';
import NotFound from './pages/NotFound';
import { AuthProvider } from './context/AuthProvider';
import { useAuth } from './hooks/useAuth';
import Dashboard from './pages/Dashboard';
import LoadingSpinner from './components/layout/LoadingSpinner';
import ConfirmEmail from './pages/ConfirmEmail';
import ForgotPassword from './pages/ForgotPassword';
import ResetPasswordForm from './components/forms/ResetPasswordForm';
import Navbar from './components/layout/Navbar';

function PublicRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, loading } = useAuth();

    if (loading) {
        return <LoadingSpinner />;
    }

    if (isAuthenticated) {
        return <Navigate to="/dashboard" replace />; 
    }

    return <>{children}</>;
}
function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, loading } = useAuth();

    if (loading) {
        return <LoadingSpinner />;
    }

    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    return <>{children}</>;
}

function App() {
    return (
        
        <AuthProvider>
            <Router>
                <Navbar/>
                <Routes>
                    {/* Public routes */}
                    <Route path="/register" element={<PublicRoute> <Register /> </PublicRoute>} />
                    <Route path="/login" element={<PublicRoute> <Login /> </PublicRoute>} />
                    <Route path="/forgot-password" element={<PublicRoute> <ForgotPassword /> </PublicRoute>} />
                    <Route path="/reset-password" element={<PublicRoute> <ResetPasswordForm /> </PublicRoute>} />

                    {/* Email confirmation route */}
                    <Route path="/confirm-email" element={<PublicRoute> <ConfirmEmail /> </PublicRoute>} />

                    {/* Protected routes that require authentication */  }
                    <Route path="/dashboard" element={<ProtectedRoute> <Dashboard /> </ProtectedRoute>} />

                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    {/* Catch-all route for 404 Not Found */}
                    <Route path="*" element={ <NotFound /> } />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
