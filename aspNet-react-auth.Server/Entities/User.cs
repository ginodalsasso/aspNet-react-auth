using Microsoft.AspNetCore.Identity;

namespace aspNet_react_auth.Server.Entities
{
    public class User : IdentityUser
    {
        //public Guid Id { get; set; }
        //public string Username { get; set; } = string.Empty;
        //public string PasswordHash { get; set; } = string.Empty;

        public string Role { get; set; } = "User"; // Default role

        public string? RefreshToken { get; set; }

        public DateTime? RefreshTokenExpiryTime { get; set; }

    }
}
