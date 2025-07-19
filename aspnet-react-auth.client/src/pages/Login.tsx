import { useState } from 'react';
import { LoginForm } from '../components/forms/LoginForm';
import TwoFactorForm from '../components/forms/TwoFactorForm';

function Login() {
    const [step, setStep] = useState<'login' | '2fa'>('login');
    const [username, setUsername] = useState('');
    
    return (
        <div>
            {step === 'login' && (
                <LoginForm 
                    on2FA={(user) => {
                        setUsername(user);
                        setStep('2fa');
                    }}
                />
            )}

            {step === '2fa' && (
                <TwoFactorForm username={username} />
            )}
        </div>
    );
}

export default Login;
