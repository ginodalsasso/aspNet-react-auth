using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;

namespace aspNet_react_auth.Server.Services
{
    public interface IAuthService
    {
        // Registers a new user and returns the user object
        Task<(bool isSuccess, string? error, User? user)> RegisterAsync(UserDto request);
        // Authenticates the user and returns a JWT token
        Task<TokenResponseDto?> LoginAsync(UserDto request);
        // Logs out the user by invalidating the refresh token
        Task<bool> LogoutAsync(LogoutRequestDto request);
        // Creates a JWT token for the user
        Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken);
    }
}
