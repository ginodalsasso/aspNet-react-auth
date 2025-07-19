using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class TwoFactorRequestDto
    {
        [Required]
        [StringLength(20, MinimumLength = 3)]
        [RegularExpression("^[a-zA-Z0-9_]+$",
        ErrorMessage = "Username is invalid")] // require alphanumeric characters and underscores only
        public string Username { get; set; } = string.Empty;

        [Required]
        [StringLength(6, ErrorMessage = "Token must be exactly 6 characters long.", MinimumLength = 6)]
        [RegularExpression("^[0-9]{6}$", ErrorMessage = "Token must be a 6-digit number.")]
        public required string Token { get; set; }
    }
}