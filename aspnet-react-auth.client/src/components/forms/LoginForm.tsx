import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from '../ui/FormErrorMessage';
import type { LoginError, LoginFormData, TokenResponse, User } from '../../lib/types/auth';
import { authService } from '../../services/authService';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import { parseJWT, saveTokens } from '../../lib/utils/jwtUtils';

interface LoginFormProps {
    onLoginSuccess?: (user: User, tokens: TokenResponse) => void;
}

export default function LoginForm({ onLoginSuccess }: LoginFormProps) {
    const [formData, setFormData] = useState<LoginFormData>({
        username: '',
        password: ''
    });

    const [errors, setErrors] = useState<LoginError>({});
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [message, setMessage] = useState<string>('');

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
            const response = await authService.login(formData.username, formData.password);

            await handleApiResponse<TokenResponse>(
                ['username', 'password'], // Fields to check for backend errors
                response,
                setErrors,
                setMessage,
                (tokenData) => {
                    // Success handler
                    const user = parseJWT(tokenData.accessToken);

                    if (user) {
                        // Save tokens to localStorage
                        saveTokens(tokenData.accessToken, tokenData.refreshToken);

                        setMessage('Login successful!');
                        setFormData({
                            username: '',
                            password: ''
                        });

                        // On successful login, call the callback with user and token data
                        onLoginSuccess?.(user, tokenData);
                    } else {
                        setMessage('Error processing login response');
                    }
                }
            );
        } catch (error) {
            console.error('Network error:', error);
            setMessage('Internal server error');
        } finally {
            setIsLoading(false);
        }
    };


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
                    />
                    <FormErrorMessage message={errors?.password} />
                </div>

                <button type="submit" disabled={isLoading}>
                    {isLoading ? ' Loading...' : 'Login'}
                </button>
            </form>
        </div>
    );
}
