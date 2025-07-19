import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from '../ui/FormErrorMessage';
import type { LoginError, LoginRequest, TokenResponse } from '../../lib/types/auth';
import { authService } from '../../services/authService';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import { parseJWT } from '../../lib/utils/jwtUtils';
import { useAuth } from '../../hooks/useAuth';
import { Link, useNavigate } from 'react-router-dom';
import LoadingSpinner from '../layout/LoadingSpinner';
import HoneypotField from '../ui/HoneypotField';

export default function LoginForm() {
    const [formData, setFormData] = useState<LoginRequest>({
        username: '',
        password: '',
        website: '' // Hidden field for honeypot
    });

    const navigate = useNavigate();

    const [errors, setErrors] = useState<LoginError>({});
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [message, setMessage] = useState<string>('');

    // Get auth functions from useAuth to handle login state
    const { setAccessToken } = useAuth();

    const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
        // Destructure name and value from the event target avoid repetition
        const { name, value } = e.target;
        // 
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        
        setIsLoading(true);
        setMessage('');
        setErrors({});

        try {
            const response = await authService.login(formData);
            const result = await response.json();

            if (!response.ok) {
                const is2FA = result.details?.includes('2FA');
                if (is2FA) {
                    navigate('/2fa', { state: { username: formData.username } }); // Pass the username to the 2FA page
                    return;
                }

                await handleApiResponse<TokenResponse>(
                    ['username', 'password'], // Fields to check for backend errors
                    response,
                    setErrors,
                    setMessage,
                    () => {}
                );
                return;
            }

            const user = parseJWT(result.accessToken);
            if (user) {
                setAccessToken(result.accessToken);
                setMessage('Login successful!');
                setFormData({
                    username: '', 
                    password: '', 
                    website: '' 
                });
                setTimeout(() => navigate('/'), 1500);
            } else {
                setMessage('Error processing login response');
            }
        } catch (error) {
            console.error('Network error:', error);
            setMessage('Internal server error');
        } finally {
            setIsLoading(false);
        }
    };

    if (isLoading) {
        return <LoadingSpinner />;
    }

    return (
        <div>
            {message && (
                <div>
                    {message}
                </div>
            )}

            <form onSubmit={handleSubmit}>
                <div>
                    <label htmlFor="username">Username:</label>
                    <input
                        type="text"
                        id="username"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        disabled={isLoading}
                        placeholder="Enter your username"
                        autoComplete="username"
                        required
                    />
                    <FormErrorMessage message={errors?.username} />

                </div>

                <div>
                    <label htmlFor="password">Password:</label>
                    <input
                        type="password"
                        id="password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        disabled={isLoading}
                        placeholder="Enter your password"
                        autoComplete="current-password"
                        required
                    />
                    <FormErrorMessage message={errors?.password} />
                </div>

                <HoneypotField value={formData.website} onChange={handleChange} />


                <button type="submit" disabled={isLoading}>
                    {isLoading ? ' Loading...' : 'Login'}
                </button>
            </form>
            <Link to="/forgot-password">Forgot password?</Link>
        </div>
    );
}
