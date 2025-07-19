import { useState, type ChangeEvent, type FormEvent } from "react";
import LoadingSpinner from "../layout/LoadingSpinner";
import FormErrorMessage from "../ui/FormErrorMessage";
import HoneypotField from "../ui/HoneypotField";
import type { ResetPasswordError, ResetPasswordRequest, ResetPasswordResponse } from "../../lib/types/auth";
import handleApiResponse from "../../lib/utils/handleApiResponse";
import { authService } from "../../services/authService";
import { useSearchParams } from "react-router-dom";

export default function ResetPasswordForm() {
    const [searchParams] = useSearchParams();
    const userId = searchParams.get('userId');
    const token = searchParams.get('token');

    const [formData, setFormData] = useState<ResetPasswordRequest>({
        userId: userId ?? '',
        token: token ?? '',
        newPassword: '',
        confirmPassword: '',
        website: '' // Hidden field for honeypot
    });

    const [errors, setErrors] = useState<ResetPasswordError>({});
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
            const response = await authService.resetPassword(formData);

            await handleApiResponse<ResetPasswordResponse>(
                ['userId', 'token', 'newPassword', 'confirmPassword'], // Fields to check for backend errors
                response,
                setErrors,
                setMessage,
                (data) => {
                    if (data) {
                        setMessage(data.message);
                        setFormData({
                            userId: '',
                            token: '',
                            newPassword: '',
                            confirmPassword: '',
                            website: ''
                        });
                    } else {
                        setMessage('Error processing reset password response');
                    }
                }
            );
        } catch (error) {
            console.error('Error during reset password request:', error);
            setMessage('An error occurred while processing your request. Please try again later.');
        } finally {
            setIsLoading(false);
        }
    };

    if (isLoading) {
        return <LoadingSpinner />;
    }
    
    if (!userId || !token) {
        return (
            <div>
                <h1>Reset Password</h1>
                <p>Invalid reset link.</p>
            </div>
        );
    }

    return (
        <>
            {message && (
                <div>
                    {message}
                </div>
            )}
            <form onSubmit={handleSubmit}>
                <h2>Reset Password</h2>
                <div>
                    <label htmlFor="newPassword">New Password:</label>
                    <input
                        type="password"
                        id="newPassword"
                        name="newPassword"
                        value={formData.newPassword}
                        onChange={handleChange}
                        disabled={isLoading}
                        placeholder="Enter your new password"
                        autoComplete="new-password"
                        required
                    />
                    <FormErrorMessage message={errors?.newPassword} />
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
                        placeholder="Confirm your new password"
                        autoComplete="new-password"
                        required
                    />
                    <FormErrorMessage message={errors?.confirmPassword} />
                </div>
                <HoneypotField value={formData.website} onChange={handleChange} />

                <button type="submit" disabled={isLoading}>
                    {isLoading ? ' Loading...' : 'Reset Password'}
                </button>
            </form>
        </>
    );
}