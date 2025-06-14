import API_ROUTES from '../lib/constants/routes';
import type {
    LoginRequest,
    RegisterRequest,
    LogoutRequest,
    RefreshTokenRequest,
} from '../lib/types/auth';


export class AuthService {
     
    private responseError(message: string = "Network error. Please check your connection.", status: number = 500) {
        return new Response(JSON.stringify({ message }), { status, statusText: 'Network Error' });
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

    async testProtectedRoute(accessToken: string): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.testProtectedRoute}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${accessToken}`
                },
            });

            return response;
        } catch (error) {
            console.error('Protected route access error:', error);
            return this.responseError();
        }
    }

    async testAdminRoute(accessToken: string): Promise<Response> {
        try {
            const response = await fetch(`${API_ROUTES.auth.testAdminRoute}`, {
                method: 'GET',
                headers: {
                    'Authorisation': `Bearer ${accessToken}`
                },
            });

            return response;
        } catch (error) {
            console.error('Admin route access error:', error);
            return this.responseError();
        }
    }
}

export const authService = new AuthService(); // Exporting an instance of AuthService for use in components or hooks