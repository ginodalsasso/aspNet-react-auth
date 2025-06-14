
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

// API Request types
export interface LoginRequest {
    username: string;
    password: string;
}

export interface RegisterRequest {
    username: string;
    password: string;
}

export interface LogoutRequest {
    userId: string;
    refreshToken: string;
}

export interface RefreshTokenRequest {
    userId: string;
    refreshToken: string;
}

// API Response types
export interface TokenResponse {
    accessToken: string;
    refreshToken: string;
}

export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
}

export interface ApiSuccessResponse<T> {
    success: true;
    data: T;
}

export interface ApiErrorResponse {
    success: false;
    error: string;
}

export type ApiResult<T> = ApiSuccessResponse<T> | ApiErrorResponse;


// Form validation types
export interface LoginFormData {
    username: string;
    password: string;
}

export interface RegisterFormData {
    username: string;
    password: string;
    confirmPassword: string;
}

//API Error types
export interface ApiError {
    message: string;
    status?: number;
    code?: string;
}

// JWT Token types
export interface TokenPair {
    accessToken: string | null;
    refreshToken: string | null;
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

export interface AdminRouteProps extends ProtectedRouteProps {
    requiredRole: 'Admin';
}