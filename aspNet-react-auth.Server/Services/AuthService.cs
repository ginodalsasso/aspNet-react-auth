using aspNet_react_auth.Server.Data;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace aspNet_react_auth.Server.Services
{
    public class AuthService(AppDbContext context, IConfiguration configuration, RSA rsa) : IAuthService
    {
        public async Task<TokenResponseDto?> LoginAsync(UserDto request) // Authenticates the user and returns a JWT token
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
            {
                return null;
            }

            var passwordVerificationResult = new PasswordHasher<User>()
                .VerifyHashedPassword(user, user.PasswordHash, request.Password);

            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                return null;
            }

            TokenResponseDto response = await CreateTokenResponse(user);

            return response;
        }

        public async Task<User?> RegisterAsync(UserDto request) // Registers a new user and returns the user object
        {
            if (await context.Users.AnyAsync(u => u.Username == request.Username))
            {
                return null; // User already exists  
            }

            var user = new User();
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            user.Username = request.Username
                .ToLower()
                .Trim();
            user.PasswordHash = hashedPassword;

            context.Users.Add(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<bool> LogoutAsync(LogoutRequestDto request) // Logs out the user by invalidating the refresh token
        {
            var user = await context.Users.FindAsync(request.UserId);
            if (user is null || user.RefreshToken != request.RefreshToken)
            {
                return false; // Invalid user or refresh token
            }
            user.RefreshToken = null; // Invalidate the refresh token
            user.RefreshTokenExpiryTime = null; // Reset expiry time

            await context.SaveChangesAsync();

            return true;
        }

        public async Task<TokenResponseDto?> RefreshTokenAsync(RefreshTokenRequestDto request) // Creates a JWT token for the user using a refresh token
        {
            var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
            if (user is null)
            {
                return null;
            }

            return await CreateTokenResponse(user);
        }

        private async Task<User?> ValidateRefreshTokenAsync(Guid userId, string refreshToken) // Validates the refresh token for the user
        {
            var user = await context.Users.FindAsync(userId);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return null; // Invalid or expired refresh token
            }
            return user;
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User? user) // Creates a JWT token for the user
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };
        }

        private string GenerateRefreshToken() // Generates a secure random refresh token
        {
            var randomBytes = new byte[32]; // 32 bytes = 256 bits
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes); // Convert to Base64 string for storage
        }

        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken; // Save the refresh token to the user entity
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // 7 days expiry

            await context.SaveChangesAsync();

            return refreshToken;
        }


        private string CreateToken(User user) // Creates a JWT token for the user
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            // Create claims for the user (e.g., username, roles)
            var claims = new List<Claim>
            {
                new Claim("userId", user.Id.ToString()),
                new Claim("username", user.Username),
                new Claim("role", user.Role),
            };

            // Create a symmetric security key using the secret key from configuration
            var key = new RsaSecurityKey(rsa);

            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            var tokenDescriptor = new JwtSecurityToken(
                issuer: configuration.GetValue<string>("AppSettings:Issuer"),       // Issuer = the entity that issues the token
                audience: configuration.GetValue<string>("AppSettings:Audience"),   // Audience = the entity that the token is intended for
                claims: claims,                                                     // Claims = the claims associated with the token
                expires: DateTime.UtcNow.AddDays(1),                                // Expiration of the token
                signingCredentials: credentials                                     // Signing credentials to sign the token
               );

            // returns the token as a string
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
