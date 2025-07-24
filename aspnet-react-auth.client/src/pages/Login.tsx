import { useState } from 'react';
import { LoginForm } from '../components/forms/LoginForm';
import TwoFactorForm from '../components/forms/TwoFactorForm';
import API_ROUTES, { CLIENT_URL } from '../lib/constants/routes';

function Login() {
    const [step, setStep] = useState<'login' | '2fa'>('login');
    const [username, setUsername] = useState('');

    const handleGoogleLogin = () => {
        window.location.href = `${API_ROUTES.auth.googleLogin}?returnUrl=${CLIENT_URL}`; 
    }
    
    return (
        <div>
            {/* Render the login form or 2FA form based on the current step */}
            {step === 'login' && (
                <LoginForm 
                    on2FA={(user) => {
                        setUsername(user);
                        setStep('2fa');
                    }}
                />
            )}
            <button onClick={handleGoogleLogin}>Login with Google</button>

            {step === '2fa' && (
                <TwoFactorForm username={username} />
            )}
        </div>
    );
}

export default Login;
