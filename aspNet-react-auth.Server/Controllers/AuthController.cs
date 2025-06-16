using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Models;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace aspNet_react_auth.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
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
                return BadRequest(error);            }
            return Ok(result);
        }

        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout([FromBody] LogoutRequestDto request) // Logs out the user by invalidating the refresh token
        {
            var result = await authService.LogoutAsync(request);
            if (result is false)
            {
                var error = new ErrorResponse
                {
                    Message = "Logout failed",
                    Details = "Invalid logout request"
                };
                return Unauthorized(error);
            }

            return Ok(new { message = "Logged out successfully" });
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto request) // Creates a JWT token for the user using a refresh token
        {
            var result = await authService.RefreshTokenAsync(request);
            if (result is null || result.AccessToken is null || result.RefreshToken is null)
            {
                return Unauthorized("Invalid or expired refresh token");
            }
            return Ok(result);
        }

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
