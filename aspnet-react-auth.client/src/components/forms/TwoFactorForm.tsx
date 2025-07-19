import { useState } from 'react';
import { authService } from '../../services/authService';
import type { TwoFactorResponse } from '../../lib/types/auth';
import handleApiResponse from '../../lib/utils/handleApiResponse';
import FormErrorMessage from '../ui/FormErrorMessage';
import { useNavigate } from 'react-router-dom';
import LoadingSpinner from '../layout/LoadingSpinner';

export default function TwoFactorForm({ username }: { username: string }) {
    const navigate = useNavigate();

    const [token, setToken] = useState<string>('');
    
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [errors, setErrors] = useState<{ token?: string }>({});
    const [message, setMessage] = useState<string>('');

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        setIsLoading(true);
        setMessage('');
        setErrors({});

        try {
            const response = await authService.verify2FA({ username, token });
            await handleApiResponse<TwoFactorResponse>(
                ['token'], // Fields to check for backend errors
                response,
                setErrors,
                setMessage,
                (data) => {
                    // Success handler
                    setMessage(data.message);
                    if (response.ok) {
                        setTimeout(() => navigate('/dashboard'), 1500); // Redirect after 1.5 seconds
                    }
                }
            );
            return; // Ensure we return to avoid further processing
        } catch (error) {
            console.error('Error during reset password request:', error);
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
            {message && <p>{message}</p>}

            <form onSubmit={handleSubmit}>
                <h2>Enter 2FA Code</h2>
                <label htmlFor="2fa-token">2FA Token</label>
                <input
                    autoFocus
                    id='2fa-token'
                    name="token"
                    type="number"
                    placeholder="Enter 2FA code"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    required
                />
                <FormErrorMessage message={errors?.token} />
                <button type="submit">Verify</button>
            </form>
        </>
    );
}
