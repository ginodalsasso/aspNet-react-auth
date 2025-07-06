using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class ConfirmEmailRequestDto
    {
        [Required]
        public required string UserId { get; set; } = string.Empty;

        [Required]
        public required string Token { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public required string Email { get; set; } = string.Empty;
    }
}