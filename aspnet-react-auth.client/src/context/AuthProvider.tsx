import { useState, useEffect, type ReactNode } from 'react';
import type { User, AuthContextType } from '../lib/types/auth';
import { parseJWT } from '../lib/utils/jwtUtils';
import { authService } from '../services/authService';
import { AuthContext } from './AuthContext';
import API_ROUTES from '../lib/constants/routes';
export interface AuthProviderProps {
    children: ReactNode;  // All child components that will have access to auth
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {

    const [user, setUser] = useState<User | null>(null);
    const [accessToken, setAccessTokenState] = useState<string | null>(null); // JWT access token in memory
    const [csrfToken, setCsrfToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

    const getCsrfToken = async (token: string) => {
        try {
            const response = await fetch(API_ROUTES.auth.csrfToken, {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                credentials: "include"
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch CSRF token: ${response.statusText}`);
            }

            const data = await response.json();

            setCsrfToken(data.csrfToken);
        } catch (error) {
            console.error("Failed to fetch CSRF token", error);
        }
    };


    // Try to get new access token using refresh token cookie
    useEffect(() => {
        const initializeAuth = async () => {
            try {
                const response = await authService.refreshToken();

                if (response.ok) {
                    const data = await response.json();
                    setAccessToken(data.accessToken);

                    const userData = parseJWT(data.accessToken);
                    if (userData) {
                        setUser(userData);
                    }

                    await getCsrfToken(data.accessToken);

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
            getCsrfToken(newAccessToken);

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
            setCsrfToken(null);
        }
    };

    // Set auth callbacks for the authService to manage tokens and user state
    // gives authService the "tools" it needs
    useEffect(() => {
        authService.setAuthCallbacks({
            getAccessToken: () => accessToken,
            updateAccessToken: setAccessToken,
            logout: clearAuth,
            getCsrfToken: () => csrfToken
        });
    }, [accessToken, csrfToken]); // Re-run effect when accessToken changes

    // The value object that will be provided to all child components
    const value: AuthContextType = {
        user,           // Current user information
        accessToken,    // Current access token
        loading,        // Loading state
        setAccessToken, // Function to set access token
        clearAuth,      // Function to logout
        csrfToken
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
