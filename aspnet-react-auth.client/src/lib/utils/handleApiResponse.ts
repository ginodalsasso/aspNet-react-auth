type Errors = Record<string, string>;

export default async function handleApiResponse<T>(
    inputs: Array<string>,
    response: Response,
    setErrors: (errors: Errors) => void,
    setMessage: (message: string) => void,
    onSuccess?: (data: T) => void,
): Promise<void> {

    const data = await response.json();
    const generalErrorMessage = data.details || data.message || `Error ${response.status}`;

    if (response.ok) {
        if (onSuccess) {
            onSuccess(data as T);
        }
    } else {
        switch (response.status) {
            // Get model state errors from ASP.NET
            case 400:
                if (data.errors) {
                    const backendErrors: Errors = {};
                    Object.keys(data.errors).forEach(field => {
                        const fieldName = field.toLowerCase(); // Username -> username
                        if (inputs.includes(fieldName)) {
                            // Only include errors for fields that are in the inputs array
                            backendErrors[fieldName as keyof Errors] = data.errors[field][0];
                        }
                    });
                    setErrors(backendErrors);
                } else {
                    setMessage(generalErrorMessage);
                }
                break;
            case 401:
                setMessage("Unauthorized access.");
                break;
            default:
                setMessage(generalErrorMessage);
        }
    }
}
// Use example:
// handleApiResponse(['username', 'password'], response, setErrors, setMessage, (data) => {
//     // Handle success, ex: redirect or update state, emptying the form...