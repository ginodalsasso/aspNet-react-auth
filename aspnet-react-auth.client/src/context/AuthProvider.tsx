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
    const [accessToken, setAccessTokenState] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

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
                }
            } catch (error) {
                console.error('No existing session found', error);
            } finally {
                setLoading(false);
            }
        };

        initializeAuth();
    }, []);


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
            // Toujours nettoyer, même en cas d'erreur
            setUser(null);
            setAccessTokenState(null);
        }
    };

    // Set auth callbacks for the authService to manage tokens and user state
    useEffect(() => {
        authService.setAuthCallbacks({
            getAccessToken: () => accessToken,
            updateAccessToken: setAccessToken,
            logout: clearAuth
        });
    }, [accessToken]);

    // The value object that will be provided to all child components
    const value: AuthContextType = {
        user,
        accessToken,
        loading,
        setAccessToken,
        clearAuth,
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};
