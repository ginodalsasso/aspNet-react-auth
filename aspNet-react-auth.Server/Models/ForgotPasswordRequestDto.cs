using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class ForgotPasswordRequestDto
    {
        [Required]
        [EmailAddress(ErrorMessage = "Invalid email address format.")]
        [StringLength(256, ErrorMessage = "Email address cannot exceed 256 characters.")]
        public required string Email { get; set; }
        
        public string? Website { get; set; } = string.Empty;
    }
}