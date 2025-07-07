namespace aspNet_react_auth.Server.Common

{
    /// <summary>
        /// Represents a generic result response with success status, data, and error message.
        /// This class is used to standardize API responses across the application.
        /// ex: Result<string> result = Result<string>.Ok("Success message");
        /// Result<string> errorResult = Result<string>.Fail("Error message");
    /// </summary>
    public class ResultResponse<T>
    {
        public bool Success { get; set; }
        public T? Data { get; set; }
        public string? Error { get; set; }

        public static ResultResponse<T> Ok(T data) => new() { Success = true, Data = data };
        public static ResultResponse<T> Fail(string error) => new() { Success = false, Error = error };
    }
}


