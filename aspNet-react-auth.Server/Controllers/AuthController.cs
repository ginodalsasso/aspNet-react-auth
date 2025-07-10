using aspNet_react_auth.Server.Common;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace aspNet_react_auth.Server.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService; // handling authentication logic
        private readonly IAntiforgery _antiforgery; // Service for CSRF protection
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailService _emailService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            IAuthService authService,
            IAntiforgery antiforgery,
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            IEmailService emailService,
            ILogger<AuthController> logger
            )
        {
            _authService = authService;
            _antiforgery = antiforgery;
            _userManager = userManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _logger = logger;
        }

        private readonly CookieOptions _refreshTokenCookieOptions = new()
        {
            HttpOnly = true,                // HttpOnly prevents client-side scripts from accessing the cookie
            Secure = true,                  // Secure ensures the cookie is sent only over HTTPS
            SameSite = SameSiteMode.Strict, // Prevents the cookie from being sent in cross-site requests
            MaxAge = TimeSpan.FromDays(7),  // Set the cookie to expire in 7 days
            Path = "/api/Auth"              // Set the path for the cookie to be accessible only under this route 
        };

        [HttpGet("test-email")]
        public async Task<IActionResult> TestEmail()
        {
            await _emailService.SendEmailAsync("dalsasso.gino@gmail.com", "Test", "Ceci est un test !");
            return Ok("Email envoyé !");
        }


        // CSRF TOKEN ENDPOINT _____________________________________________________________________
        [AllowAnonymous]
        [HttpGet("csrf-token")]
        public IActionResult GetCsrfToken()
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            return Ok(new { csrfToken = tokens.RequestToken });
        }

        // TEST ENDPOINT _____________________________________________________________________
        [Authorize(Policy = "AdminOnly")]
        [HttpGet("test-protected-route")]
        public IActionResult TestProtectedRoute()
        {
            return Ok("You're Authenticated!");
        }

        // REGISTER ENDPOINT _____________________________________________________________________
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(RegisterRequestDto request) // Registers a new user and returns the user object
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ValidationErrorResponse(ModelState));
            }

            var result = await _authService.RegisterAsync(request);

            if (!result.Success)
            {
                return BadRequest(new ErrorResponse
                {
                    Message = "Register failed",
                    Details = result.Error
                });
            }

            return Ok(new { message = "Registration successful" });
        }

        // CONFIRM EMAIL ENDPOINT _____________________________________________________________________
        [HttpPost("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(ConfirmEmailRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ValidationErrorResponse(ModelState));
            }

            var result = await _authService.ConfirmEmailAsync(request);
            if (!result)
            {
                return BadRequest(new ErrorResponse
                {
                    Message = "Email confirmation failed",
                    Details = "Invalid token or user ID"
                });
            }

            return Ok(new { message = "Email confirmed successfully" });
        }

        // LOGIN ENDPOINT _____________________________________________________________________
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(LoginRequestDto request) // Authenticates the user and returns a JWT token
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ValidationErrorResponse(ModelState));
            }

            var result = await _authService.LoginAsync(request);
            if (!result.Success)
            {
                return BadRequest(new ErrorResponse
                {
                    Message = "Login failed",
                    Details = result.Error
                });
            }

            Response.Cookies.Append("refreshToken", result.Data!.RefreshToken, _refreshTokenCookieOptions);

            return Ok(new { accessToken = result.Data.AccessToken });
        }

        // LOGOUT ENDPOINT _____________________________________________________________________
        [Authorize]
        [HttpPost("logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("userId")?.Value;
            _logger.LogInformation("Logout attempt for user: {UserId}", userId);

            try
            {
                // Get refresh token from cookie
                var hasRefreshToken = Request.Cookies.TryGetValue("refreshToken", out var refreshToken);

                if (hasRefreshToken && !string.IsNullOrEmpty(refreshToken) && !string.IsNullOrEmpty(userId))
                {
                    _logger.LogDebug("Found refresh token for user: {UserId}, invalidating...", userId);

                    var logoutRequest = new LogoutRequestDto
                    {
                        UserId = userId,
                        RefreshToken = refreshToken
                    };

                    // Invalidate refresh token in database
                    var logoutResult = await _authService.LogoutAsync(logoutRequest);
                    if (!logoutResult)
                    {
                        _logger.LogWarning("Failed to invalidate refresh token for user: {UserId}", userId);
                    }
                }

                // Sign out from Identity (clears authentication cookies)
                await _signInManager.SignOutAsync();

                // Clear refresh token cookie
                Response.Cookies.Delete("refreshToken", new CookieOptions
                {
                    Path = "/api/Auth",
                    Secure = true,
                    SameSite = SameSiteMode.Strict
                });

                // Clear CSRF cookie if it exists
                if (Request.Cookies.ContainsKey("__Host-X-XSRF-TOKEN"))
                {
                    Response.Cookies.Delete("__Host-X-XSRF-TOKEN", new CookieOptions
                    {
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                    _logger.LogDebug("CSRF cookie cleared for user: {UserId}", userId);
                }

                _logger.LogInformation("Logout successful for user: {UserId}", userId);
                return Ok(new { message = "Logged out successfully" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout for user: {UserId}", userId);
                return StatusCode(500, new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "An error occurred during logout"
                });
            }
        }

        // FORGOT PASSWORD ENDPOINT _____________________________________________________________________
        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequestDto request)
        {
            _logger.LogWarning("Forgot password request for email: {Email}", request.Email);
            if (!ModelState.IsValid)
            {
                return BadRequest(new ValidationErrorResponse(ModelState));
            }
            
            var result = await _authService.ForgotPasswordAsync(request);
            if (!result.Success)
            {
                return BadRequest(new ErrorResponse
                {
                    Message = "Forgot password failed",

                    Details = result.Error
                });
            }
            
            return Ok(new { message = "Password reset link sent to your email" });
        }
    
        // REFRESH TOKEN ENDPOINT _____________________________________________________________________
        [HttpPost("refresh-token")]
        public async Task<ActionResult<object>> RefreshToken()
        {
            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken))
            {
                return Unauthorized("No refresh token provided");
            }

            try
            {
                var result = await _authService.RefreshTokenAsync(refreshToken);
                if (result is null || result.AccessToken is null || result.RefreshToken is null)
                {
                    // Delete the cookie if the refresh token is invalid or expired
                    Response.Cookies.Delete("refreshToken", new CookieOptions
                    {
                        Path = "/api/Auth",
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                    return Unauthorized("Invalid or expired refresh token");
                }

                // update the refresh token cookie with the new refresh token
                Response.Cookies.Append("refreshToken", result.RefreshToken, _refreshTokenCookieOptions);

                return Ok(new { accessToken = result.AccessToken });
            }
            catch (Exception)
            {
                var error = new ErrorResponse
                {
                    Message = "Refresh token failed",
                    Details = "Invalid refresh token format or expired"
                };
                return Unauthorized(error);
            }
        }
    }
}
