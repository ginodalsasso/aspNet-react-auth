import { useState, type ChangeEvent, type FormEvent } from 'react';
import FormErrorMessage from './FormErrorMessage';

type FormData = {
    username: string;
    password: string;
};

type Errors = {
    username?: string;
    password?: string;
};

export default function RegisterForm() {
    const [formData, setFormData] = useState<FormData>({
        username: '',
        password: ''
    });

    const [errors, setErrors] = useState<Errors>({});
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

    const validateForm = (): boolean => {
        const newErrors: Errors = {};
        // Provisory 
        if (!formData.username.trim()) {
            newErrors.username = 'Username is needed';
        }

        if (!formData.password.trim()) {
            newErrors.password = 'Password is needed';
        }

        setErrors(newErrors);
        return Object.keys(newErrors).length === 0; 
    }

    const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();

        if (!validateForm()) {
            return;
        }

        setIsLoading(true);
        setMessage('');
        setErrors({});

        try {
            const response = await fetch('https://localhost:7067/api/Auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    username: formData.username,
                    password: formData.password
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                const errorMessage = data.message || `Error ${response.status}`;
                setMessage(errorMessage);
                return;
            }

            setMessage('Registration successful! You can now log in.');
            setFormData({
                username: '',
                password: ''
            });
        } catch (error) {
            console.error('Network error:', error);
            setMessage('Internal server error');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div>
            <h1>Register</h1>

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
                    {isLoading ? 'Inscription en cours...' : 'S\'inscrire'}
                </button>
            </form>
        </div>
    );
}
