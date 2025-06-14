
export interface User {
    id: string;
    username: string;
    role: string;
    exp: number;
}

// API Request types
export interface LoginRequest {
    username: string;
    passwordHash: string;
}

export interface RegisterRequest {
    username: string;
    passwordHash: string;
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

// Auth Context types
export interface AuthContextType {
    user: User | null;
    accessToken: string | null;
    refreshToken: string | null;
    loading: boolean;
    isAuthenticated: boolean;
    login: (username: string, password: string) => Promise<ApiResult<TokenResponse>>;
    register: (username: string, password: string) => Promise<ApiResult<User>>;
    logout: () => Promise<void>;
    refreshAccessToken: () => Promise<TokenResponse | null>;
}

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

// HTTP Method types
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

// API Request configuration
export interface ApiRequestConfig {
    method?: HttpMethod;
    headers?: Record<string, string>;
    body?: string;
}

// Protected route props
export interface ProtectedRouteProps {
    children: React.ReactNode;
    requiredRole?: string;
}