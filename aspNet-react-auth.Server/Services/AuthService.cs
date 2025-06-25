using aspNet_react_auth.Server.Data;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace aspNet_react_auth.Server.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly RSA _rsa;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            AppDbContext context,
            IConfiguration configuration,
            RSA rsa,
            ILogger<AuthService> logger)
        {
            _context = context;
            _configuration = configuration;
            _rsa = rsa;
            _logger = logger;
        }

        // LOGIN ASYNC _________________________________________________________________
        public async Task<TokenResponseDto?> LoginAsync(UserDto request) // Authenticates the user and returns a JWT token
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return null;
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
            if (user is null)
            {
                _logger.LogWarning("Login failed: no user found with username '{Username}'", request.Username);
                return null;
            }

            var passwordVerificationResult = new PasswordHasher<User>()
                .VerifyHashedPassword(user, user.PasswordHash, request.Password);

            if (passwordVerificationResult == PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Login failed: incorrect username or password for username '{Username}'", request.Username);
                return null;
            }

            TokenResponseDto response = await CreateTokenResponse(user);

            return response;
        }

        // REGISTER ASYNC _________________________________________________________________
        public async Task<(bool isSuccess, string? error, User? user)> RegisterAsync(UserDto request) // Registers a new user and returns the user object
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return (false, "Bot detected", null);
            }

            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                _logger.LogWarning("Registration failed: username '{Username}' is already taken", request.Username);
                return (false, "Username is taken", null); // User already exists  
            }

            var user = new User();
            var hashedPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            user.Username = request.Username
                .ToLower()
                .Trim();
            user.PasswordHash = hashedPassword;

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            _logger.LogInformation("New user: {Username}", user.Username);

            // return true if registration is successful, the error message is null, and the user object
            return (true, null, user);
        }

        // LOGOUT ASYNC _________________________________________________________________
        public async Task<bool> LogoutAsync(LogoutRequestDto request) // Logs out the user by invalidating the refresh token
        {
            var user = await _context.Users.FindAsync(request.UserId);
            if (user is null || user.RefreshToken != request.RefreshToken)
            {
                _logger.LogWarning("Logout failed: invalid user or refresh token for user ID '{UserId}'", request.UserId);
                return false; // Invalid user or refresh token
            }
            user.RefreshToken = null; // Invalidate the refresh token
            user.RefreshTokenExpiryTime = null; // Reset expiry time

            await _context.SaveChangesAsync();

            return true;
        }


        // TOKEN 
        // CREATE JWT TOKEN _________________________________________________________________
        private JwtSecurityToken CreateJwtToken(List<Claim> claims, TimeSpan validityDuration, SigningCredentials credentials)
        {
            return new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
                audience: _configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.Add(validityDuration),
                signingCredentials: credentials
            );
        }

        // CREATE TOKEN _________________________________________________________________
        private string CreateToken(User user) // Creates a JWT token for the user
        {
            if (user == null)
            {
                _logger.LogError("CreateToken failed: user is null");
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
            var key = new RsaSecurityKey(_rsa);

            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            var tokenDescriptor = CreateJwtToken(
                claims,
                TimeSpan.FromMinutes(15), // 15 minutes validity for access token
                credentials
            );

            // returns the token as a string
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        // GENERATE REFRESH TOKEN _________________________________________________________________
        private string GenerateRefreshToken(User user) // Generates a secure random refresh token
        {
            var claims = new List<Claim>
            {
                new Claim("userId", user.Id.ToString()),
                new Claim("type", "refresh"),
            };

            var key = new RsaSecurityKey(_rsa);
            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            var refreshTokenDescriptor = CreateJwtToken(
                claims,
                TimeSpan.FromDays(7), // 7 days validity for refresh token
                credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(refreshTokenDescriptor);
        }

        // GENERATE AND SAVE REFRESH TOKEN ASYNC _________________________________________________________________
        private async Task<string> GenerateAndSaveRefreshTokenAsync(User user)
        {
            var refreshToken = GenerateRefreshToken(user);
            user.RefreshToken = refreshToken; // Save the refresh token to the user entity
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7); // 7 days expiry

            await _context.SaveChangesAsync();

            return refreshToken;
        }

        // CREATE TOKEN RESPONSE _________________________________________________________________
        private async Task<TokenResponseDto> CreateTokenResponse(User? user) // Creates a JWT token for the user
        {
            if (user == null)
            {
                _logger.LogError("CreateTokenResponse failed: user is null");
                throw new ArgumentNullException(nameof(user), "User cannot be null.");
            }

            return new TokenResponseDto
            {
                AccessToken = CreateToken(user),
                RefreshToken = await GenerateAndSaveRefreshTokenAsync(user)
            };
        }
        // REFRESH TOKEN ASYNC _________________________________________________________________
        public async Task<TokenResponseDto?> RefreshTokenAsync(string refreshToken) // Creates a JWT token for the user using a refresh token
        {
            //var user = await ValidateRefreshTokenAsync(request.UserId, request.RefreshToken);
            var user = await _context.Users.FirstOrDefaultAsync(u =>
                u.RefreshToken == refreshToken &&
                u.RefreshTokenExpiryTime > DateTime.UtcNow);
            if (user is null)
            {
                _logger.LogWarning("Refresh token failed: no user found with valid refresh token '{RefreshToken}'", refreshToken);
                return null;
            }

            return await CreateTokenResponse(user);
        }
    }

}
