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

                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    {/* Catch-all route for 404 Not Found */}
                    <Route path="*" element={ <NotFound /> } />
                </Routes>
            </Router>
        </AuthProvider>
    );
}

export default App;
