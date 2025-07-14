import { useSearchParams } from "react-router-dom";
import ResetPasswordForm from "../components/forms/ResetPasswordForm";

function ResetPassword() {
    const [searchParams] = useSearchParams();
    const userId = searchParams.get('userId');
    const token = searchParams.get('token');

    if (!userId || !token) {
        return (
            <div>
                <h1>Reset Password</h1>
                <p>Invalid reset link.</p>
            </div>
        );
    }

    return (
        <div>
            <h1>Reset Password</h1>
            <ResetPasswordForm />
        </div>
    );
}

export default ResetPassword;