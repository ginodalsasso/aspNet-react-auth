import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from '../ui/FormErrorMessage';
import type { ForgotPasswordError, ForgotPasswordRequest, ForgotPasswordResponse } from '../../lib/types/auth';
import { authService } from '../../services/authService';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import LoadingSpinner from '../layout/LoadingSpinner';
import HoneypotField from '../ui/HoneypotField';

export default function ForgotPasswordForm() {
    const [formData, setFormData] = useState<ForgotPasswordRequest>({
        email: '',
        website: '' // Hidden field for honeypot
    });

    const [errors, setErrors] = useState<ForgotPasswordError>({});
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
            const response = await authService.forgotPassword(formData);

            await handleApiResponse<ForgotPasswordResponse>(
                ['email'], // Fields to check for backend errors
                response,
                setErrors,
                setMessage,
                (data) => {
                    // success handler
                    if (data) {
                        setMessage(data.message);
                        setFormData({
                            email: '',
                            website: ''
                        });
                    } else {
                        setMessage('Error processing login response');
                    }
                }
            );
        } catch (error) {
            console.error('Error during forgot password request:', error);
            setMessage('An error occurred while processing your request. Please try again later.');
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
                    <label htmlFor="email">Email</label>
                    <input
                        type="email"
                        id="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        required
                    />
                    <FormErrorMessage message={errors?.email} />
                </div>
                <HoneypotField value={formData.website} onChange={handleChange} />

                <button type="submit" disabled={isLoading}>
                    {isLoading ? ' Loading...' : 'Reset Password'}
                </button>
            </form>
        </div>
    );
}
