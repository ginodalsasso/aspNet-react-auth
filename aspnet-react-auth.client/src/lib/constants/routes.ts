
const devURL = "https://localhost:7067";
const prodURL = ""
const API_BASE_URL = devURL ? devURL : prodURL; // if devURL is set, use it; otherwise use prodURL

export const API_URL = `${API_BASE_URL}`;
export const BASE_URL = `${API_BASE_URL}/api`;


const authBase = `${BASE_URL}/Auth`;

const authRoutes = {
    login: `${authBase}/login`,
    register: `${authBase}/register`,
    logout: `${authBase}/logout`,
    refreshToken: `${authBase}/refresh-token`,
    csrfToken: `${authBase}/csrf-token`,
    confirmEmail: `${authBase}/confirm-email`,
    forgotPassword: `${authBase}/forgot-password`,
    resetPassword: `${authBase}/reset-password`,
    verify2FA: `${authBase}/2fa-verify`,
    toggle2FA: `${authBase}/toggle-2fa`,

    // test
    testProtectedRoute: `${authBase}/test-protected-route`,
    testAdminRoute: `${authBase}/test-admin-route`,
}

const API_ROUTES = {
    auth: authRoutes,
};

export default API_ROUTES;