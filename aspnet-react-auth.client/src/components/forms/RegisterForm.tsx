import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from '../ui/FormErrorMessage';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import type { RegisterError, RegisterRequest, RegisterResponse } from '../../lib/types/auth';
import { authService } from '../../services/authService';
import { useNavigate } from 'react-router-dom';
import LoadingSpinner from '../layout/LoadingSpinner';
import HoneypotField from '../ui/HoneypotField';

export default function RegisterForm() {
    const [formData, setFormData] = useState<RegisterRequest>({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        website: '' // Honeypot field to detect bots
    });

    const navigate = useNavigate();

    const [errors, setErrors] = useState<RegisterError>({});
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [message, setMessage] = useState<string>('');

    const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
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
            const response = await authService.register(formData);
            await handleApiResponse<RegisterResponse>(
                ['username', 'password'], // Fields to check for backend errors
                response,
                setErrors,
                setMessage,
                (data) => {
                    // Success handler
                    setMessage(data.message);
                    setFormData({
                        username: '',
                        email: '',
                        password: '',
                        confirmPassword: '',
                        website: ''
                    });
                    if (response.ok) {
                        setTimeout(() => navigate('/login'), 1500); // Redirect after 1.5 seconds
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

    if (isLoading) {
        return <LoadingSpinner />;
    }

    return (
        <>
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
                    <label htmlFor="email">Email:</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        disabled={isLoading}
                        placeholder="Enter your email"
                    />
                    <FormErrorMessage message={errors?.email} />
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
                <div>
                    <label htmlFor="confirmPassword">Confirm Password:</label>
                    <input
                        type="password"
                        id="confirmPassword"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        disabled={isLoading}
                        placeholder="Confirm your password"
                    />
                    <FormErrorMessage message={errors?.confirmPassword} />
                </div>
                {/* Honeypot field to detect bots */}
                <HoneypotField value={formData.website} onChange={handleChange} />

                <button type="submit" disabled={isLoading}>
                    {isLoading ? 'Loading' : 'Register'}
                </button>
            </form>
        </>
    );
}