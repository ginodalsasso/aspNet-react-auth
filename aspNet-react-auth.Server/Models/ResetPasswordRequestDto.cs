using System.ComponentModel.DataAnnotations;

namespace aspNetReactAuth.Server.Models
{
    public class ResetPasswordRequestDto
    {
        [Required]
        public required string UserId { get; set; }

        [Required]
        public required string Token { get; set; }

        [Required]
        [MinLength(8)]
        [MaxLength(256)]
        [RegularExpression(@"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{12,}$",
        ErrorMessage = "Password must be at least 12 characters long, contain at least one uppercase letter, one digit, and one special character")]
        public required string NewPassword { get; set; }

        [Required]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match")]
        public required string ConfirmPassword { get; set; }

        public string? Website { get; set; } = string.Empty;
    }
}