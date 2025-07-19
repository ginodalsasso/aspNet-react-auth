using aspNet_react_auth.Server.Common;
using aspNet_react_auth.Server.Data;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using aspNetReactAuth.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace aspNet_react_auth.Server.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly UserManager<User> _userManager;
        private readonly IEmailService _emailService;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly RSA _rsa;
        private readonly ILogger<AuthService> _logger;

        public AuthService(
            AppDbContext context,
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            IEmailService emailService,
            IConfiguration configuration,
            RSA rsa,
            ILogger<AuthService> logger
            )
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _configuration = configuration;
            _rsa = rsa;
            _logger = logger;
        }
        
        // PROCESS USER EMAIL ASYNC _________________________________________________________________
        private async Task ProcessUserEmailAsync(User user, Func<User, Task<string>> generateTokenAsync, string redirectPath, Func<string, string, Task> sendEmailAsync)
        {
            if (string.IsNullOrWhiteSpace(user.Email))
            {
                _logger.LogError("Cannot send email: user email is null or empty for user '{UserName}'", user.UserName);
                throw new ArgumentException("User email cannot be null or empty.", nameof(user.Email));
            }

            try
            {
                var token = await generateTokenAsync(user);
                var encodedToken = Uri.EscapeDataString(token); // Encode the token to ensure it's safe for URLs
                var confirmationLink = $"{_configuration["AppSettings:ClientUrl"]}/{redirectPath}?userId={user.Id}&token={encodedToken}";

                await sendEmailAsync(user.Email, confirmationLink);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while processing email for user '{UserName}'", user.UserName);
                throw;
            }
        }

        // LOGIN ASYNC _________________________________________________________________
        public async Task<ResultResponse<TokenResponseDto>> LoginAsync(LoginRequestDto request) // Authenticates the user and returns a JWT token
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return ResultResponse<TokenResponseDto>.Fail("Bot detected");
            }

            var user = await _userManager.FindByNameAsync(request.Username);
            if (user is null)
            {
                _logger.LogWarning("Login failed: no user found with username '{Username}'", request.Username);
                return ResultResponse<TokenResponseDto>.Fail("Invalid credentials");
            }

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (!isEmailConfirmed)
            {
                _logger.LogWarning("Login failed: email not confirmed for user '{Username}'", user.UserName);
                return ResultResponse<TokenResponseDto>.Fail("Email not confirmed");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
            if (!result.Succeeded)
            {
                _logger.LogWarning("Login failed: incorrect username or password for username '{Username}'", request.Username);
                return ResultResponse<TokenResponseDto>.Fail("Invalid credentials");
            }

            if (user.TwoFactorEnabled)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
                if (string.IsNullOrEmpty(token))
                {
                    _logger.LogError("Failed to generate 2FA token for user '{Username}'", user.UserName);
                    return ResultResponse<TokenResponseDto>.Fail("Failed to generate 2FA token");
                }

                await _emailService.SendEmailAsync(user.Email!, "Two-Factor Authentication Code",
                    $"Your two-factor authentication code is: {token}. Please enter this code to complete your login.");

                return ResultResponse<TokenResponseDto>.Fail("2FA Required. A verification code has been sent to your email.");
            }

            TokenResponseDto response = await CreateTokenResponse(user);

            return ResultResponse<TokenResponseDto>.Ok(response);
        }

        // REGISTER ASYNC _________________________________________________________________
        public async Task<ResultResponse<bool>> RegisterAsync(RegisterRequestDto request) // Registers a new user and returns the user object
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return ResultResponse<bool>.Fail("Bot detected");
            }

            var existingUsername = await _userManager.FindByNameAsync(request.Username);
            if (existingUsername != null)
            {
                _logger.LogWarning("Registration failed: username '{Username}' is already taken", request.Username);
                return ResultResponse<bool>.Fail("Username is already taken"); // if user already exist
            }

            var existingEmail = await _userManager.FindByEmailAsync(request.Email);
            if (existingEmail != null)
            {
                _logger.LogWarning("Registration failed: email '{Email}' is already registered", request.Email);
                return ResultResponse<bool>.Fail("Email is already registered"); // if email already exist
            }

            var passwordMatches = request.Password == request.ConfirmPassword;
            if (!passwordMatches)
            {
                _logger.LogWarning("Registration failed: password and confirm password do not match for username '{Username}'", request.Username);
                return ResultResponse<bool>.Fail("Password and confirm password do not match");
            }

            var user = new User
            {
                UserName = request.Username.ToLower().Trim(),
                Email = request.Email.ToLower().Trim(),
                Role = "User" // Default role
            };

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Registration failed for username '{Username}': {Errors}", request.Username, errors);
                return ResultResponse<bool>.Fail(errors);
            }

            await ProcessUserEmailAsync(
                user,
                _userManager.GenerateEmailConfirmationTokenAsync, // Generate email confirmation token
                "confirm-email", // Redirect path for email confirmation
                _emailService.SendConfirmationEmailAsync // Send confirmation email
            );

            _logger.LogInformation("New user registered: {Username}", user.UserName);

            return ResultResponse<bool>.Ok(true);
        }

        // CONFIRM EMAIL ASYNC _________________________________________________________________
        public async Task<bool> ConfirmEmailAsync(ConfirmEmailRequestDto request) // Confirms the user's email
        {
            _logger.LogInformation("ConfirmEmailAsync {request}", request);

            if (request is null)
            {
                _logger.LogWarning("ConfirmEmailAsync failed: request is null");
                return false;
            }

            var user = await _userManager.FindByIdAsync(request.UserId.ToString());
            if (user is null)
            {
                _logger.LogWarning("ConfirmEmailAsync failed: user not found for user ID '{UserId}'", request.UserId);
                return false;
            }

            var result = await _userManager.ConfirmEmailAsync(user, request.Token);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("ConfirmEmailAsync failed for user ID '{UserId}': {Errors}", request.UserId, errors);
                return false;
            }

            _logger.LogInformation("Email confirmed successfully for user ID '{UserId}'", request.UserId);
            return true;
        }

        // LOGOUT ASYNC _________________________________________________________________
        public async Task<bool> LogoutAsync(LogoutRequestDto request) // Logs out the user by invalidating the refresh token
        {
            _logger.LogInformation("LogoutAsync {request}", request);

            var user = await _userManager.FindByIdAsync(request.UserId.ToString());
            if (user is null)
            {

                _logger.LogWarning("Logout failed: user not found for user ID '{UserId}'", request.UserId);
                return false;
            }

            if (user.RefreshToken != request.RefreshToken) // if the refresh token does not match
            {
                _logger.LogInformation("Refresh token already invalid or mismatched for user ID '{UserId}'", request.UserId);
            }

            user.RefreshToken = null; // Invalidate the refresh token
            user.RefreshTokenExpiryTime = null; // Reset expiry time

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to update user during logout for user ID '{UserId}'", request.UserId);
                return false;
            }

            await _signInManager.SignOutAsync();

            return true;
        }


        // FORGOT PASSWORD ASYNC _________________________________________________________________
        public async Task<ResultResponse<bool>> ForgotPasswordAsync(ForgotPasswordRequestDto request) // Sends a password reset email to the user
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return ResultResponse<bool>.Fail("Bot detected");
            }

            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user is null)
            {
                _logger.LogWarning("Forgot password failed: no user found with email '{Email}'", request.Email);
                return ResultResponse<bool>.Fail("User not found");
            }

            var isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (!isEmailConfirmed)
            {
                _logger.LogWarning("Forgot password failed: email not confirmed for user '{Email}'", request.Email);
                return ResultResponse<bool>.Fail("Email not confirmed");
            }

            // Process the user's email for password reset
            await ProcessUserEmailAsync(
                user,
                _userManager.GeneratePasswordResetTokenAsync, // Generate password reset token
                "reset-password", // Redirect path for password reset
                _emailService.SendPasswordResetEmailAsync // Send password reset email
            );

            _logger.LogInformation("Password reset email sent to {Email}", user.Email);

            return ResultResponse<bool>.Ok(true);
        }

        // RESET PASSWORD ASYNC _________________________________________________________________
        public async Task<ResultResponse<bool>> ResetPasswordAsync(ResetPasswordRequestDto request)
        {
            if (!string.IsNullOrWhiteSpace(request.Website)) // Honeypot field check
            {
                _logger.LogWarning("Bot detected: honeypot field filled (Website: '{Website}')", request.Website);
                return ResultResponse<bool>.Fail("Bot detected");
            }

            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user is null)
            {
                _logger.LogWarning("Reset password failed: no user found with ID '{UserId}'", request.UserId);
                return ResultResponse<bool>.Fail("User not found");
            }

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.NewPassword);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Reset password failed for user ID '{UserId}': {Errors}", request.UserId, errors);
                return ResultResponse<bool>.Fail(errors);
            }

            _logger.LogInformation("Password reset successfully for user ID '{UserId}'", request.UserId);
            return ResultResponse<bool>.Ok(true);
        }

        // TWO-FACTOR AUTHENTICATION REQUEST ASYNC _________________________________________________________________
        public async Task<ResultResponse<TokenResponseDto>> TwoFactorRequestAsync(TwoFactorRequestDto request)
        {
            var user = await _userManager.FindByNameAsync(request.Username);
            if (user is null)
            {
                _logger.LogWarning("Two-factor authentication failed: no user found with username '{Username}'", request.Username);
                return ResultResponse<TokenResponseDto>.Fail("User not found");
            }

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, request.Token);
            if (!isValid)
            {
                _logger.LogWarning("Two-factor authentication failed: invalid token for user '{Username}'", request.Username);
                return ResultResponse<TokenResponseDto>.Fail("Invalid two-factor authentication token");
            }

            TokenResponseDto response = await CreateTokenResponse(user);

            return ResultResponse<TokenResponseDto>.Ok(response);
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
        private async Task<string> CreateTokenAsync(User user) // Creates a JWT token for the user
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
                new Claim("username", user.UserName ?? ""),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName ?? "")
            };

            // Add role claims from Identity
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            if (!string.IsNullOrEmpty(user.Role)) // Add custom role claim if it exists
            {
                claims.Add(new Claim("role", user.Role));
            }
            
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

            await _userManager.UpdateAsync(user);

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
                AccessToken = await CreateTokenAsync(user),
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

            if (user.RefreshTokenExpiryTime < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token expired for user {UserId}", user.Id);
                return null;
            }

            return await CreateTokenResponse(user);
        }
    }

}
