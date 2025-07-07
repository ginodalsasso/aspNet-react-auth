import { useNavigate, useSearchParams } from "react-router-dom";
import { authService } from "../services/authService";
import type { ConfirmEmailRequest, ConfirmEmailResponse } from "../lib/types/auth";
import handleApiResponse from "../lib/utils/handleApiResponse";
import { useEffect, useState } from "react";
import LoadingSpinner from "../components/layout/LoadingSpinner";
import FormErrorMessage from "../components/ui/FormErrorMessage";

function ConfirmEmail() {
    const [searchParams] = useSearchParams();
    const userId = searchParams.get('userId');
    const token = searchParams.get('token');
    
    const navigate = useNavigate();

    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [message, setMessage] = useState<string>('');

    useEffect(() => {
        const confirmEmail = async () => {
            if (!userId || !token) {
                setMessage('Invalid confirmation link. Please check the URL.');
                return;
            }
            const data: ConfirmEmailRequest = {
                userId,
                token
            };
            setIsLoading(true);
            setMessage('');

            try {
                const response = await authService.confirmEmail(data);

                await handleApiResponse<ConfirmEmailResponse>(
                    ['userId', 'token'], // Fields to check for backend errors
                    response,
                    setErrors,
                    setMessage,
                    (data) => {
                        setMessage(data.message || 'Email confirmed successfully!');
                        setTimeout(() => navigate('/login'), 2000);
                    }
                );
            } catch (error) {
                console.error('Error confirming email:', error);
                setMessage('An error occurred while confirming your email. Please try again later.');
            } finally {
                setIsLoading(false);
            }
        };
        confirmEmail();
    }, [userId, token, navigate]);


    return (
        <section>
            <h1>Email Confirmation</h1>
            <p>Please wait while we confirm your email...</p>

            {isLoading && (
                <div>
                    <LoadingSpinner />
                    <p>Confirming your email...</p>
                </div>
            )}

            {message && <p>{message}</p>}
            <FormErrorMessage message={errors?.userId} />
            <FormErrorMessage message={errors?.token} />
        </section>
    );
}

export default ConfirmEmail;