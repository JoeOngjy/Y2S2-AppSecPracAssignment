using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "Please enter a password.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Please confirm your password.")]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "Please upload your resume.")]
        public IFormFile Resume { get; set; }  // ✅ Resume is now required

        // Other fields
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required(ErrorMessage = "Please enter a valid NRIC.")]
        public string NRIC { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Date)]
        [BirthdateValidation(ErrorMessage = "Birthdate cannot be in the future.")] public DateTime DateOfBirth { get; set; }

        public string? WhoAmI { get; set; }
        [Required(ErrorMessage = "Please enter a YOUR FUCKING RECAPTCHA TOKEN.")]

        public string RecaptchaToken { get; set; }

    }
}
public class BirthdateValidation : ValidationAttribute
{
    protected override ValidationResult IsValid(object value, ValidationContext validationContext)
    {
        if (value is DateTime date && date > DateTime.Today)
        {
            return new ValidationResult("Birthdate cannot be in the future.");
        }
        return ValidationResult.Success;
    }
}