import API_ROUTES from '../lib/constants/routes';
import type {
    ConfirmEmailRequest,
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
} from '../lib/types/auth';

interface AuthCallbacks {
    getAccessToken: () => string | null;
    updateAccessToken: (accessToken: string) => void;
    logout: () => void;
    getCsrfToken: () => string | null;
}

export class AuthService {

    private authCallbacks?: AuthCallbacks;

    // Method to set authentication callbacks for managing tokens and user state
    setAuthCallbacks(callbacks: AuthCallbacks) {
        this.authCallbacks = callbacks;
    }

    private responseError(message: string = "Network error. Please check your connection.", status: number = 500) {
        return new Response(JSON.stringify({ message }), { status, statusText: 'Network Error' });
    }

    async refreshToken(): Promise<Response> {
        try {
            const response = await fetch(API_ROUTES.auth.refreshToken, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            return response;
        } catch (error) {
            console.error('Refresh token error:', error);
            return this.responseError();
        }
    }

    // Method to make authenticated requests
    async makeAuthenticatedRequest(url: string, options: RequestInit = {}): Promise<Response> {
        if (!this.authCallbacks) {
            console.error('AuthService: callbacks not configured');
            return this.responseError('Auth service not properly configured', 500);
        }

        // Use the auth callbacks to get the access token and update it if needed
        const { getAccessToken, updateAccessToken, logout, getCsrfToken } = this.authCallbacks;
        const accessToken = getAccessToken();
        const csrfToken = getCsrfToken();

        if (!accessToken) {
            return this.responseError('No access token available', 401);
        }

        if (!csrfToken) {
            console.warn('Missing CSRF token')
            return this.responseError('Missing CSRF token', 403);
        }

        // add Authorization header to options
        const authenticatedOptions: RequestInit = {
            ...options,
            credentials: 'include', // include cookies in the request
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
                'X-XSRF-TOKEN': csrfToken,
                'Authorization': `Bearer ${accessToken}` // add the access token to the Authorization header
            }
        };

        try {
            // Initiate the request with the provided URL and options
            let response = await fetch(url, authenticatedOptions);

            // If error status is 401 (Unauthorized), attempt to refresh token
            if (response.status === 401) {
                const refreshResponse = await this.refreshToken();

                if (refreshResponse.ok) {
                    const newTokenData = await refreshResponse.json(); // get new tokens from response

                    updateAccessToken(newTokenData.accessToken); // update tokens in context

                    const retryOptions: RequestInit = { // RequestInit for retrying the request
                        ...options,
                        credentials: 'include',
                        headers: {
                            'Content-Type': 'application/json',
                            ...options.headers,
                            'X-XSRF-TOKEN': getCsrfToken() ?? '',
                            'Authorization': `Bearer ${newTokenData.accessToken}`
                        }
                    };
                    response = await fetch(url, retryOptions);
                    console.log('Request retried with new token');
                } else {
                    console.error('Token refresh failed, logging out user');
                    logout();
                    return this.responseError('Authentication expired', 401);
                }
            }

            return response;
        } catch (error) {
            console.error('Authenticated request error:', error);
            return this.responseError();
        }
    }

    // Login method to authenticate user
    async login(data: LoginRequest): Promise<Response> {
        try {
            const response = await fetch(API_ROUTES.auth.login, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            return response;
        } catch (error) {
            console.error('Login error:', error);
            return this.responseError();
        }
    }

    async register(data: RegisterRequest): Promise<Response> {

        try {
            const response = await fetch(`${API_ROUTES.auth.register}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            return response;
        } catch (error) {
            console.error('Registration error:', error);
            return this.responseError();
        }
    }

    async confirmEmail(data: ConfirmEmailRequest): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.confirmEmail}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            return response;
        } catch (error) {
            console.error('Confirm email error:', error);
            return this.responseError();
        }
    }

    async logout(): Promise<boolean> {
        try {
            const response = await this.makeAuthenticatedRequest(API_ROUTES.auth.logout, {
                method: 'POST',
            });
            return response.ok;
        } catch (error) {
            console.error('Logout error:', error);
            return false;
        }
    }

    async forgotPassword(data: ForgotPasswordRequest): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.forgotPassword}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });
            
            return response;
        } catch (error) {
            console.error('Forgot password error:', error);
            return this.responseError();
        }
    }

    async resetPassword(data: ResetPasswordRequest): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.resetPassword}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            return response;
        } catch (error) {
            console.error('Reset password error:', error);
            return this.responseError();
        }
    }

    async verify2FA(data: { username: string; token: string }): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.verify2FA}`, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });

            return response;
        } catch (error) {
            console.error('2FA verification error:', error);
            return this.responseError();
        }
    }

    async toggle2FA(userId: string): Promise<Response> {
        try {
            const response = await this.makeAuthenticatedRequest(`${API_ROUTES.auth.toggle2FA}`, {
                method: 'POST',
                body: JSON.stringify({ userId }),
            });
            return response;
        } catch (error) {
            console.error('Toggle 2FA error:', error);
            return this.responseError();
        }
    }

    // Protected routes using makeAuthenticatedRequest
    async testProtectedRoute(): Promise<Response> {
        return this.makeAuthenticatedRequest(`${API_ROUTES.auth.testProtectedRoute}`, {
            method: 'GET'
        });
    }

    async testAdminRoute(): Promise<Response> {
        return this.makeAuthenticatedRequest(`${API_ROUTES.auth.testAdminRoute}`, {
            method: 'GET'
        });
    }
}

export const authService = new AuthService(); // Exporting an instance of AuthService for use in components or hooks