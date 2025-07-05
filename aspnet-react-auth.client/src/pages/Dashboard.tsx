import LoadingSpinner from "../components/layout/LoadingSpinner";
import { useAuth } from "../hooks/useAuth";
import { authService } from "../services/authService";

function Dashboard() {
    const { user, loading, clearAuth } = useAuth();

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

    const testEmail = async () => {
        console.log('Testing email..');
        try {
            const response = await authService.testEmail();
            if (response.ok) {
                const result = await response.text();
                console.log('Email sent successfully:', result);
            } else {
                console.log('Failed to send email:', response.status);
            }
        } catch (error) {
            console.error('Error sending email:', error);
        }
    }
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
            <button onClick={testEmail}>
                Test Email
            </button>
        </div>

    );
};

export default Dashboard;