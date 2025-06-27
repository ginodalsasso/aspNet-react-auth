import { useState, useEffect, type ReactNode } from 'react';
import type { User, AuthContextType } from '../lib/types/auth';
import { parseJWT } from '../lib/utils/jwtUtils';
import { authService } from '../services/authService';
import { AuthContext } from './AuthContext';
export interface AuthProviderProps {
    children: ReactNode;  // All child components that will have access to auth
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {

    const [user, setUser] = useState<User | null>(null);
    const [accessToken, setAccessTokenState] = useState<string | null>(null); // JWT access token in memory
    const [loading, setLoading] = useState(true);

    // Try to get new access token using refresh token cookie
    useEffect(() => {
        const initializeAuth = async () => {
            try {
                await authService.getCsrfToken();

                const response = await authService.refreshToken();

                if (response.ok) {
                    const data = await response.json();
                    setAccessToken(data.accessToken);

                    const userData = parseJWT(data.accessToken);
                    if (userData) {
                        setUser(userData);
                    }
                } else {
                    console.error('Failed to refresh token:', response.statusText);
                }
            } catch (error) {
                console.error('No existing session found', error);
            } finally {
                setLoading(false);
            }
        };

        initializeAuth();
    }, []);

    // Functions to manage auth state by extracting user infos from the JWT
    const setAccessToken = (newAccessToken: string) => {
        const userData = parseJWT(newAccessToken);
        if (userData) {
            setUser(userData);
            setAccessTokenState(newAccessToken);
        }
    };

    // Function to logout a user, clears everything
    const clearAuth = async () => {
        try {
            if (accessToken) {
                await authService.logout();
            }
        } catch (error) {
            console.error('Error during logout:', error);
        } finally {
            setUser(null);
            setAccessTokenState(null);
        }
    };

    // Set auth callbacks for the authService to manage tokens and user state
    // gives authService the "tools" it needs
    useEffect(() => {
        authService.setAuthCallbacks({
            getAccessToken: () => accessToken,
            updateAccessToken: setAccessToken,
            logout: clearAuth
        });
    }, [accessToken]); // Re-run effect when accessToken changes

    // The value object that will be provided to all child components
    const value: AuthContextType = {
        user,           // Current user information
        accessToken,    // Current access token
        loading,        // Loading state
        setAccessToken, // Function to set access token
        clearAuth,      // Function to logout
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
