// =======================
// User & Auth Types
// =======================

export interface User {
    id: string;
    username: string;
    role: string;
    exp: number;
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

export interface AuthContextType {
    user: User | null;
    accessToken: string | null;
    loading: boolean;
    csrfToken: string | null;
    setAccessToken: (accessToken: string) => void;
    clearAuth: () => void;
}

// =======================
// Shared & Utility Types
// =======================

export interface HoneypotField {
    website: string; // Honeypot field to detect bots
}

// =======================
// Error Types
// =======================

export interface LoginError {
    username?: string;
    password?: string;
}

export interface RegisterError {
    username?: string;
    email?: string;
    password?: string;
    confirmPassword?: string;
}

export interface ForgotPasswordError {
    email?: string;
}

export interface ResetPasswordError {
    userId?: string;
    token?: string;
    newPassword?: string;
    confirmPassword?: string;
}

// =======================
// API Request Types
// =======================

export interface LoginRequest extends HoneypotField {
    username: string;
    password: string;
}

export interface RegisterRequest extends HoneypotField {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
}

export interface ForgotPasswordRequest extends HoneypotField {
    email: string;
}

export interface ResetPasswordRequest extends HoneypotField {
    userId: string;
    token: string;
    newPassword: string;
    confirmPassword: string;
}

export interface ConfirmEmailRequest {
    userId: string;
    token: string;
}

// =======================
// API Response Types
// =======================

export interface TokenResponse {
    accessToken: string;
    refreshToken: string;
}

export interface RegisterResponse {
    message: string;
}

export interface ConfirmEmailResponse {
    message: string;
}

export interface ForgotPasswordResponse {
    message: string;
}

export interface ResetPasswordResponse {
    message: string;
}

export interface TwoFactorResponse {
    message: string;
    accessToken?: string;
}
