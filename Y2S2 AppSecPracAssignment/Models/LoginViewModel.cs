using System.ComponentModel.DataAnnotations;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, ErrorMessage = "Password must be at least 12 characters.", MinimumLength = 12)]
        public string Password { get; set; }

        public string RecaptchaToken { get; set; }
    }

}
