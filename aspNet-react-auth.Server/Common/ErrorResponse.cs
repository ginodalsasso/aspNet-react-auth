using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace aspNet_react_auth.Server.Common
{
    public class ErrorResponse
    {
        public string Message { get; set; } = string.Empty;
        public Dictionary<string, string[]>? Errors { get; set; } // Dictionary to hold validation errors with field names as keys and error messages as values
        public string? Details { get; set; }
    }

    // Represents a response for validation errors, inheriting from ErrorResponse
    public class ValidationErrorResponse : ErrorResponse
    {
        public ValidationErrorResponse(ModelStateDictionary modelState) // ModelStateDictionary contains the state of model validation
        {
            Message = "Validation failed";
            Errors = modelState
                .Where(x => x.Value?.Errors.Count > 0) // Filter out entries with no errors
                .ToDictionary( 
                    kvp => kvp.Key, // Key is the field name
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>() // Value is an array of error messages for that field
                );
        }
    }
}