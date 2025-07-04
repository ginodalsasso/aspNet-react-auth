namespace aspNet_react_auth.Server.Models
{
    public class LogoutRequestDto
    {
        public string UserId { get; set; } = string.Empty;
        public required string RefreshToken { get; set; } // The refresh token to be invalidated
    }
}