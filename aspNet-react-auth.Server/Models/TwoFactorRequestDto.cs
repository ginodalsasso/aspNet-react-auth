using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class TwoFactorRequestDto
    {
        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address format.")]
        [StringLength(256, ErrorMessage = "Email address cannot exceed 256 characters.")]
        public required string Email { get; set; }

        [Required]
        [StringLength(6, ErrorMessage = "Token must be exactly 6 characters long.", MinimumLength = 6)]
        [RegularExpression("^[0-9]{6}$", ErrorMessage = "Token must be a 6-digit number.")]
        public required string Token { get; set; }
    }
}