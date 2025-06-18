import { useAuth } from "../hooks/useAuth";
import { authService } from "../services/authService";

function Dashboard() {
    const { user, loading, clearAuth } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
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
    return (
        <div className="dashboard-page">
            <h1>Dashboard</h1>
            <h2>Personnal information</h2>
            <p>Id: {user?.id}</p>
            <p>Role: {user?.role}</p>
            <p>Username: {user?.username}</p>
            <button onClick={clearAuth}>
                Logout
            </button>
            <button onClick={testProtected}>
                Test Protected Route
            </button>
        </div>


    );
};

export default Dashboard;