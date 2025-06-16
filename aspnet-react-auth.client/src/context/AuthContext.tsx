import { createContext } from 'react';
import type { AuthContextType } from '../lib/types/auth';

// / AuthContext provides authentication state and functions to the app (ex: user info, access token, refresh token, loading state, and functions to set auth data))
export const AuthContext = createContext<AuthContextType | undefined>(undefined);
