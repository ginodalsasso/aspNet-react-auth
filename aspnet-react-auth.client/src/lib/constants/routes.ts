
const devURL = "https://localhost:7067/";
const prodURL = ""
const API_BASE_URL = devURL ? devURL : prodURL; // if devURL is set, use it; otherwise use prodURL

export const BASE_URL = `${API_BASE_URL}/api`;
export const API_URL = `${API_BASE_URL}`;


const authBase = `${BASE_URL}/Auth`;

const authRoutes = {
    Login: `${authBase}/login`,
    Register: `${authBase}/register`,
    Logout: `${authBase}/logout`,
    RefreshToken: `${authBase}/refresh-token`,
}

const API_ROUTES = {
    auth: authRoutes,
};

export default API_ROUTES;