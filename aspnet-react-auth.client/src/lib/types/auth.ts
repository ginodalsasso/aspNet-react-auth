
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
export interface LoginRequest {
    username: string;
    password: string;
}

export interface RegisterRequest {
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
export interface LoginFormData {
    username: string;
    password: string;
}

export interface RegisterFormData {
    username: string;
    password: string;
    //confirmPassword: string;
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