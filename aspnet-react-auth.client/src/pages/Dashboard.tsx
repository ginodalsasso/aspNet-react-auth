import { useAuth } from "../hooks/useAuth";

function Dashboard() {
    const { user, loading, clearAuth } = useAuth();

    if (loading) {
        return <div>Loading...</div>;
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
        </div>
    );
};

export default Dashboard;