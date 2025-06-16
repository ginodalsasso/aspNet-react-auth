import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from '../ui/FormErrorMessage';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import type { RegisterError, RegisterFormData, RegisterResponse } from '../../lib/types/auth';
import { authService } from '../../services/authService';
import { useNavigate } from 'react-router-dom';

export default function RegisterForm() {
    const [formData, setFormData] = useState<RegisterFormData>({
        username: '',
        password: ''
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
            const response = await authService.register(formData.username, formData.password);
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
                        password: ''
                    });
                    if (response.ok) {
                        setTimeout(() => navigate('/login'), 2000); // Redirect after 2 seconds
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
                    {isLoading ? 'Loading' : 'Register'}
                </button>
            </form>
        </div>
    );
}