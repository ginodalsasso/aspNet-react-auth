import API_ROUTES from '../lib/constants/routes';
import type {
    LoginRequest,
    RegisterRequest,
} from '../lib/types/auth';

interface AuthCallbacks {
    getAccessToken: () => string | null;
    updateAccessToken: (accessToken: string) => void;
    logout: () => void;
}

export class AuthService {

    private authCallbacks?: AuthCallbacks;
    private csrfToken: string | null = null;

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

    async getCsrfToken(): Promise<string | null> {
        if (this.csrfToken) {
            return this.csrfToken;
        }

        try {
            const response = await fetch(API_ROUTES.auth.csrfToken, {
                method: 'GET',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            if (response.ok) {
                const data = await response.json();
                this.csrfToken = data.token;
                return this.csrfToken;
            } else {
                console.error('Failed to get CSRF token:', response.statusText);
                return null;
            }
        } catch (error) {
            console.error('CSRF token error:', error);
            return null;
        }
    }

    // Method to make authenticated requests
    async makeAuthenticatedRequest(url: string, options: RequestInit = {}): Promise<Response> {
        if (!this.authCallbacks) {
            console.error('AuthService: callbacks not configured');
            return this.responseError('Auth service not properly configured', 500);
        }

        // Use the auth callbacks to get the access token and update it if needed
        const { getAccessToken, updateAccessToken, logout } = this.authCallbacks;
        const accessToken = getAccessToken();

        if (!accessToken) {
            return this.responseError('No access token available', 401);
        }

        if (!this.csrfToken) {
            await this.getCsrfToken();
        }

        const csrfHeader= this.csrfToken;

        // add Authorization header to options
        const authenticatedOptions: RequestInit = {
            ...options,
            credentials: 'include', // include cookies in the request
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
                ...(csrfHeader ? { 'X-CSRF-TOKEN': csrfHeader } : {}), // add CSRF token if available
                'Authorization': `Bearer ${accessToken}` // add the access token to the Authorization header
            }
        };

        try {
            // Initiate the request with the provided URL and options
            let response = await fetch(url, authenticatedOptions);

            // If error status is 401 (Unauthorized), attempt to refresh token
            if (response.status === 401) {
                console.log('Attempting refresh...');

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
                            ...(csrfHeader ? { 'X-CSRF-TOKEN': csrfHeader } : {}), // add CSRF token if available
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

    async logout(): Promise<boolean> {
        try {
            const response = await this.makeAuthenticatedRequest(API_ROUTES.auth.logout, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            return response.ok;
        } catch (error) {
            console.error('Logout error:', error);
            return false;
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