using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;

namespace aspNet_react_auth.Server.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        private readonly CookieOptions _refreshTokenCookieOptions = new()
        {
            HttpOnly = true,                // HttpOnly prevents client-side scripts from accessing the cookie
            Secure = true,                  // Secure ensures the cookie is sent only over HTTPS
            SameSite = SameSiteMode.Strict, // Prevents the cookie from being sent in cross-site requests
            MaxAge = TimeSpan.FromDays(7),  // Set the cookie to expire in 7 days
            Path = "/api/Auth"              // Set the path for the cookie to be accessible only under this route 
        };

        // TEST ENDPOINT _____________________________________________________________________
        [Authorize]
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

            var user = await authService.RegisterAsync(request);
            if (user is null)
            {
                var error = new ErrorResponse
                {
                    Message = "Registration failed",
                    Details = "A user with this username already exists"
                };
                return BadRequest(error);
            }

            return Ok(new { message = "Registration successful" });
        }

        // LOGIN ENDPOINT _____________________________________________________________________
        [HttpPost("login")]
        public async Task<ActionResult<TokenResponseDto>> Login(UserDto request) // Authenticates the user and returns a JWT token
        {
            var result = await authService.LoginAsync(request);
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
        public async Task<IActionResult> Logout() // Logs out the user by invalidating the refresh token
        {
            if (!Request.Cookies.TryGetValue("refreshToken", out var refreshToken)) // get the refresh token from the cookie
                {
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "No refresh token found"
                };
                return BadRequest(error);
            }

            var userId = HttpContext.User.FindFirst("userId")?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "Invalid user"
                };
                return BadRequest(error);
            }

            var logoutRequest = new LogoutRequestDto
            {
                UserId = Guid.Parse(userId),
                RefreshToken = refreshToken
            };

            var result = await authService.LogoutAsync(logoutRequest);
            if (!result)
            {
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "Invalid logout request"
                };
                return Unauthorized(error);
            }

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                Path = "/api/auth",
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
                var tokenHandler = new JwtSecurityTokenHandler();
                var refreshTokenDecoded = tokenHandler.ReadJwtToken(refreshToken);

                var userIdClaim = refreshTokenDecoded.Claims.FirstOrDefault(x => x.Type == "userId")?.Value;
                if (string.IsNullOrEmpty(userIdClaim))
                {
                    return Unauthorized("Invalid refresh token format");
                }

                var request = new RefreshTokenRequestDto
                {
                    UserId = Guid.Parse(userIdClaim),
                    RefreshToken = refreshToken
                };

                var result = await authService.RefreshTokenAsync(refreshToken);
                if (result is null || result.AccessToken is null || result.RefreshToken is null)
                {
                    // Supprimer le cookie invalide
                    Response.Cookies.Delete("refreshToken", new CookieOptions
                    {
                        Path = "/api/auth",
                        Secure = true,
                        SameSite = SameSiteMode.Strict
                    });
                    return Unauthorized("Invalid or expired refresh token");
                }

                // Mettre à jour le cookie avec le nouveau refresh token
                Response.Cookies.Append("refreshToken", result.RefreshToken, _refreshTokenCookieOptions);

                // Retourner seulement le nouvel access token
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

        // AUTHORIZATION ENDPOINTS _____________________________________________________________________
        [Authorize] // This endpoint requires authentication
        [HttpGet]
        public IActionResult AuthenticatedOnlyEndpoint() // This endpoint is accessible only to authenticated users
        {
            return Ok("You're Authenticated!");
        }
 
        [Authorize(Roles = "Admin")] // Can by multiple roles, e.g. Roles = "Admin,User"
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndpoint() // This endpoint is accessible only to users with the "Admin" role
        {
            return Ok("You're Admin!");
        }
    }
}
