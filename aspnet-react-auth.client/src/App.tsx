import {
    BrowserRouter as Router,
    Routes,
    Route,
    Navigate,
} from 'react-router-dom';

import Register from './pages/Register'
import Login from './pages/Login';
import { AuthProvider } from './context/AuthProvider';
import { useAuth } from './hooks/useAuth';
import Dashboard from './pages/Dashboard';

function PublicRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, loading } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
    }

    if (isAuthenticated) {
        return <Navigate to="/dashboard" replace />; 
    }

    return <>{children}</>;
}
function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, loading } = useAuth();
    console.log(isAuthenticated)

    if (loading) {
        return <div>Loading...</div>;
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
                <Routes>
                    {/* Public routes */}
                    <Route path="/register" element={<PublicRoute> <Register /> </PublicRoute>} />
                    <Route path="/login" element={<PublicRoute> <Login /> </PublicRoute>} />

                    {/* Protected routes that require authentication */  }
                    <Route path="/dashboard" element={<ProtectedRoute> <Dashboard /> </ProtectedRoute>} />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
