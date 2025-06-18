import API_ROUTES from '../lib/constants/routes';
import type {
    LoginRequest,
    RegisterRequest,
    LogoutRequest,
    RefreshTokenRequest,
    TokenResponse,
} from '../lib/types/auth';

interface AuthCallbacks {
    getTokens: () => { accessToken: string | null; refreshToken: string | null; userId: string | null };
    updateTokens: (accessToken: string, refreshToken: string) => void;
    logout: () => void;
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

    // Method to make authenticated requests
    async makeAuthenticatedRequest(url: string, options: RequestInit = {}): Promise<Response> {
        if (!this.authCallbacks) {
            console.error('AuthService: callbacks not configured');
            return this.responseError('Auth service not properly configured', 500);
        }

        const { getTokens, updateTokens, logout } = this.authCallbacks;
        const { accessToken, refreshToken, userId } = getTokens();

        if (!accessToken) {
            return this.responseError('No access token available', 401);
        }

        // add Authorization header to options
        const authenticatedOptions: RequestInit = {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
                'Authorization': `Bearer ${accessToken}`
            }
        };

        try {
            // Initiate the request with the provided URL and options
            let response = await fetch(url, authenticatedOptions);

            // If error status is 401 (Unauthorized), attempt to refresh token
            if (response.status === 401 && refreshToken && userId) {
                console.log('Attempting refresh...');

                const refreshResponse = await this.refreshToken(userId, refreshToken);

                if (refreshResponse.ok) {
                    const newTokens: TokenResponse = await refreshResponse.json(); // get new tokens from response

                    updateTokens(newTokens.accessToken, newTokens.refreshToken); // update tokens in context

                    const retryOptions: RequestInit = { // RequestInit for retrying the request
                        ...options,
                        headers: {
                            'Content-Type': 'application/json',
                            ...options.headers,
                            'Authorization': `Bearer ${newTokens.accessToken}`
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
    async login(username: string, password: string): Promise<Response> {
        const loginData: LoginRequest = {
            username,
            password 
        };

        try {
            const response = await fetch(`https://localhost:7067/api/Auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(loginData),
            });

            return response;
        } catch (error) {
            console.error('Login error:', error);
            return this.responseError();
        }
    }

    async register(username: string, password: string): Promise<Response> {
        const registerData: RegisterRequest = {
            username,
            password
        };

        try {
            const response = await fetch(`${API_ROUTES.auth.register}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(registerData),
            });

            return response;
        } catch (error) {
            console.error('Registration error:', error);
            return this.responseError();
        }
    }

    async logout(userId: string, refreshToken: string, accessToken: string): Promise<boolean> {
        try {
            const logoutData: LogoutRequest = {
                userId,
                refreshToken
            };

            const response = await fetch(`${API_ROUTES.auth.logout}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${accessToken}`
                },
                body: JSON.stringify(logoutData),
            });

            return response.ok;
        } catch (error) {
            console.error('Logout error:', error);
            return false;
        }
    }

    async refreshToken(userId: string, refreshToken: string): Promise<Response> {
        const refreshData: RefreshTokenRequest = {
            userId,
            refreshToken
        };

        try {
            const response = await fetch(`${API_ROUTES.auth.refreshToken}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(refreshData),
            });

            return response;
        } catch (error) {
            console.error('Refresh token error:', error);
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