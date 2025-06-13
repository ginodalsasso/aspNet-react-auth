type Errors = Record<string, string>;
type BackendErrors = Record<string, string[]>; // Each field can have multiple errors, array of strings

// Extracts backend error messages for specific fields from the response and sets them in the errors state
function getBackendErrorMessage(
    inputs: Array<string>,
    errorFields: BackendErrors,
    setErrors: (errors: Errors) => void
) {
    const backendErrors: Errors = {};
    Object.keys(errorFields).forEach(field => {
        const fieldName = field.toLowerCase(); // Username -> username
        if (inputs.includes(fieldName)) {
            // Only include errors for fields that are in the inputs array
            backendErrors[fieldName as keyof Errors] = errorFields[field][0];
        }
    });
    setErrors(backendErrors);
}

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
            onSuccess(data as T); // Call the success handler with the data
        }
    } else {
        switch (response.status) {
            // Get model state errors from ASP.NET
            case 400:
                if (data.errors) {
                    getBackendErrorMessage(inputs, data.errors, setErrors);
                } else {
                    setMessage(generalErrorMessage);
                }
                break;
            case 401:
                if (data.errors) {
                    getBackendErrorMessage(inputs, data.errors, setErrors);
                } else {
                    setMessage(generalErrorMessage);
                }                break;
            case 403:
                setMessage("Access denied. You don't have the necessary permissions.");
                break;
            case 404:
                setMessage("Resource not found.");
                break;
            case 409:
                setMessage("Conflict - This resource already exists.");
                break;
            case 422:
                setMessage("Invalid data.");
                break;

            default:
                setMessage(generalErrorMessage);
        }
    }
}
// Use example:
// handleApiResponse(['username', 'password'], response, setErrors, setMessage, (data) => {
//     // Handle success, ex: redirect or update state, emptying the form...