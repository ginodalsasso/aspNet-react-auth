using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class RegisterRequestDto
    {
        [Required]
        [StringLength(20, MinimumLength = 3)]
        [RegularExpression("^[a-zA-Z0-9_]+$",
        ErrorMessage = "Username is invalid")] // require alphanumeric characters and underscores only
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        [MaxLength(256)]
        [RegularExpression(@"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{12,}$",
        ErrorMessage = "Password must be at least 12 characters long, contain at least one uppercase letter, one digit, and one special character")]
        public string Password { get; set; } = string.Empty;

        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;

        // Optional field used for honeypot protection
        public string? Website { get; set; } = string.Empty;
    }
}
