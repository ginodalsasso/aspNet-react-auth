import { useState } from "react";
import LoadingSpinner from "../components/layout/LoadingSpinner";
import { useAuth } from "../hooks/useAuth";
import { authService } from "../services/authService";

function Dashboard() {
    const { user, loading, clearAuth } = useAuth();

    const [message, setMessage] = useState<string>('');

    if (loading) {
        return <LoadingSpinner />;
    }

    const testProtected = async () => {
        console.log('Testing..');
        try {
            const response = await authService.testProtectedRoute();
            if (response.ok) {
                const result = await response.text();
                console.log('Success:', result);
            } else {
                console.log('Failed:', response.status);
            }
        } catch (error) {
            console.error('Error:', error);
        }
    };

    const toggle2FA = async () => {
        if (!user) {
            console.error('User not authenticated');
            return;
        }
        try {
            const response = await authService.toggle2FA(user.id);
            if (response.ok) {
                const result = await response.json();
                setMessage(result.message);
            } else {
                console.error('Failed to toggle 2FA:', response.status);
                setMessage('Failed to toggle 2FA');
            }
        } catch (error) {
            console.error('Error toggling 2FA:', error);
        }
    }

    return (
        <>
            {message && <p>{message}</p>}
            <div className="dashboard-page">
                <h1>Dashboard</h1>
                <h2>Personnal information</h2>
                <p>Id: {user?.id}</p>
                <p>Role: {user?.role}</p>
                <p>Username: {user?.username}</p>
                <p>Email: {user?.email}</p>
                <button onClick={toggle2FA}>
                    Enable 2FA
                </button>
                <button onClick={clearAuth}>
                    Logout
                </button>
                <button onClick={testProtected}>
                    Test Protected Route
                </button>
            </div>
        </>
    );
};

export default Dashboard;