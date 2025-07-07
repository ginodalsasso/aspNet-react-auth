using System.ComponentModel.DataAnnotations;

namespace aspNet_react_auth.Server.Models
{
    public class ConfirmEmailRequestDto
    {
        [Required]
        public required string UserId { get; set; }

        [Required]
        public required string Token { get; set; }
    }
}