import type { JWTPayload, TokenPair, User } from "../types/auth";

// Function to decode a JWT on the client side (without signature verification)
export const parseJWT = (token: string): User | null => {
    try {
        // A JWT has 3 parts separated by dots: header.payload.signature
        const base64Url = token.split('.')[1]; // We take the payload (part 2)
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');

        // Decode from base64 to JSON
        const jsonPayload = decodeURIComponent(
            atob(base64)
                .split('')
                .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
                .join('')
        );

        const decoded: JWTPayload = JSON.parse(jsonPayload);

        // Return user info according to API structure
        return {
            id: decoded.userId,           // User ID
            username: decoded.username, 
            role: decoded.role,           
            exp: decoded.exp             // Token expiration date
        };
    } catch (error) {
        console.error('Error decoding JWT:', error);
        return null;
    }
};

// Function to check if a token is expired
export const isTokenExpired = (token: string): boolean => {
    try {
        const decoded = parseJWT(token);
        if (!decoded || !decoded.exp) return true;

        // Compare with current time (in seconds)
        const now = Date.now() / 1000;
        return decoded.exp < now; // If expiration is less than current time, token is expired
    } catch (error) {
        console.error('Error checking token expiration:', error);
        return true; // In case of error, consider as expired
    }
};

// Function to save tokens in localStorage
export const saveTokens = (accessToken: string, refreshToken: string): void => {
    localStorage.setItem('accessToken', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
};

// Function to retrieve tokens from localStorage
export const getStoredTokens = (): TokenPair => {
    return {
        accessToken: localStorage.getItem('accessToken'),
        refreshToken: localStorage.getItem('refreshToken')
    };
};

// Function to remove tokens from localStorage
export const clearStoredTokens = (): void => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
};