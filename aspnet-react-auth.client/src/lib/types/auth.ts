
export interface User {
    id: string;
    username: string;
    role: string;
    exp: number;
}

// Error types
export interface LoginError {
    username?: string;
    password?: string;
}
export interface RegisterError {
    username?: string;
    password?: string;
}

// API Request types
export interface LoginRequest extends HoneypotField {
    username: string;
    password: string;
}

export interface RegisterRequest extends HoneypotField {
    username: string;
    password: string;
}

// API Response types
export interface TokenResponse {
    accessToken: string;
    refreshToken: string;
}

export interface RegisterResponse {
    message: string;
}

// Form validation types
export interface LoginFormData extends HoneypotField {
    username: string;
    password: string;
}

export interface RegisterFormData extends HoneypotField {
    username: string;
    password: string;
}

export interface HoneypotField {
    website: string; // Honeypot field to detect bots
}


export interface JWTPayload {
    userId: string;
    username: string;
    role: string;
    exp: number;
    iat?: number;
    iss?: string;
    aud?: string;
}

// Protected route props
export interface ProtectedRouteProps {
    children: React.ReactNode;
    requiredRole?: string;
}

export interface AuthContextType {
    user: User | null;
    accessToken: string | null;          // JWT access token
    loading: boolean;                    // Loading state during initialization
    setAccessToken: (accessToken: string) => void; 
    clearAuth: () => void;               // Function to logout user
}