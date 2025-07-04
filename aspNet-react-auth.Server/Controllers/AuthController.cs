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
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, IAntiforgery antiforgery, UserManager<User> userManager, ILogger<AuthController> logger)  //IAntiforgery antiforgery,
        {
            _authService = authService;
            _antiforgery = antiforgery;
            _userManager = userManager;
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

        // CSRF TOKEN ENDPOINT _____________________________________________________________________
        [AllowAnonymous]
        [HttpGet("csrf-token")]
        public IActionResult GetCsrfToken()
        {
            var tokens = _antiforgery.GetAndStoreTokens(HttpContext);
            return Ok(new { csrfToken = tokens.RequestToken });
        }

        // TEST ENDPOINT _____________________________________________________________________
        [Authorize(Roles = "Admin")]
        [HttpGet("test-protected-route")]
        public IActionResult TestProtectedRoute()
        {
            return Ok("You're Authenticated!");
        }

        // REGISTER ENDPOINT _____________________________________________________________________
        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request) // Registers a new user and returns the user object
        {
            if (!ModelState.IsValid)
            {
                var validationErrors = new ValidationErrorResponse(ModelState);
                return BadRequest(validationErrors); // Return validation errors if the model state is invalid
            }

            var (isSuccess, error, user) = await _authService.RegisterAsync(request);

            if (!isSuccess)
            {
                return BadRequest(new ErrorResponse
                {
                    Message = "Register failed",
                    Details = error
                });
            }

            return Ok(new { message = "Registration successful" });
        }

        // LOGIN ENDPOINT _____________________________________________________________________
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request) // Authenticates the user and returns a JWT token
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ValidationErrorResponse(ModelState));
            }

            var result = await _authService.LoginAsync(request);
            if (result is null)
            {
                var error = new ErrorResponse
                {
                    Message = "Login failed",
                    Details = "Invalid username or password"
                };
                return BadRequest(error);
            }

            Response.Cookies.Append("refreshToken", result.RefreshToken, _refreshTokenCookieOptions);

            return Ok(new { accessToken = result.AccessToken });
        }

        // LOGOUT ENDPOINT _____________________________________________________________________
        [Authorize]
        [HttpPost("logout")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout() // Logs out the user by invalidating the refresh token
        {

            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken)) // get the refresh token from the cookie
            {
                _logger.LogWarning("Logout failed: no refresh token found in cookies");
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "No refresh token found"
                };
                return BadRequest(error);
            }

            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("userId")?.Value; // get first userId claim or NameIdentifier claim
            if (string.IsNullOrEmpty(userIdClaim))
            {
                _logger.LogWarning("Logout failed: user ID not found in claims");
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "Invalid user"
                };
                return BadRequest(error);
            }

            var logoutRequest = new LogoutRequestDto
            {
                UserId = Guid.Parse(userIdClaim), // parse the userId from the claim
                RefreshToken = refreshToken // use the refresh token from the cookie
            };

            var result = await _authService.LogoutAsync(logoutRequest);
            if (!result)
            {
                _logger.LogWarning("Logout failed: invalid logout request for user ID '{UserId}'", userIdClaim);
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "Invalid logout request"
                };
                return Unauthorized(error);
            }

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                Path = "/api/Auth",
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            return Ok(new { message = "Logged out successfully" });
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
