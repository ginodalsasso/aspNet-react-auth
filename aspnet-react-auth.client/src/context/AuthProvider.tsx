import { useState, useEffect, type ReactNode } from 'react';
import type { AuthContextType, User } from '../lib/types/auth';
import { getStoredTokens, parseJWT, clearStoredTokens, saveTokens } from '../lib/utils/jwtUtils';
import { AuthContext } from './AuthContext';

export interface AuthProviderProps {
    children: ReactNode;  // All child components that will have access to auth
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {

    const [user, setUser] = useState<User | null>(null);
    const [accessToken, setAccessToken] = useState<string | null>(null);
    const [refreshToken, setRefreshToken] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

    // check if user was previously logged in
    useEffect(() => {
        // get stored tokens from localStorage
        const tokens = getStoredTokens();

        // If we found both tokens in storage
        if (tokens.accessToken && tokens.refreshToken) {
            // Try to extract user info from the access token
            const userData = parseJWT(tokens.accessToken);

            if (userData) {
                // Token is valid, restore the user session
                setUser(userData);
                setAccessToken(tokens.accessToken);
                setRefreshToken(tokens.refreshToken);
            } else {
                // Token is invalid, clear it from storage
                clearStoredTokens();
            }
        }

        setLoading(false);
    }, []);

    // Function to login a user, called after successful API login
    const setAuthData = (newAccessToken: string, newRefreshToken: string) => {
        // Extract user info from the new access token
        const userData = parseJWT(newAccessToken);

        if (userData) {
            // Update all auth state
            setUser(userData);
            setAccessToken(newAccessToken);
            setRefreshToken(newRefreshToken);

            // Save tokens to localStorage for persistence
            saveTokens(newAccessToken, newRefreshToken);
        }
    };

    // Function to logout a user, clears everything
    const clearAuth = () => {
        setUser(null);
        setAccessToken(null);
        setRefreshToken(null);

        // Clear tokens from localStorage
        clearStoredTokens();
    };

    // The value object that will be provided to all child components
    const value: AuthContextType = {
        user,
        accessToken,
        refreshToken,
        loading,
        setAuthData,
        clearAuth,
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
