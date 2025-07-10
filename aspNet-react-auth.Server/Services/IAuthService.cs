using aspNet_react_auth.Server.Common;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;

namespace aspNet_react_auth.Server.Services
{
    public interface IAuthService
    {
        // Registers a new user and returns the user object
        Task<ResultResponse<bool>> RegisterAsync(RegisterRequestDto request);
        // Confirms the user's email address
        Task<bool> ConfirmEmailAsync(ConfirmEmailRequestDto request);
        // Authenticates the user and returns a JWT token
        Task<ResultResponse<TokenResponseDto>> LoginAsync(LoginRequestDto request);
        // Logs out the user by invalidating the refresh token
        Task<bool> LogoutAsync(LogoutRequestDto request);
        // Sends a password reset email to the user
        Task<ResultResponse<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request);
        // Creates a JWT token for the user
        Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken);
    }
}
