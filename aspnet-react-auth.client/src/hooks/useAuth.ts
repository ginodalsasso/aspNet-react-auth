import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

export const useAuth = () => {
    const context = useContext(AuthContext);

    // Check if hook is used within AuthProvider
    if (context === undefined) {
        throw new Error('useAuth must be used within an AuthProvider');
    }

    return {
        ...context,                           // Spread all context
        isAuthenticated: !!context.user,     //  true if user exists
    };
};