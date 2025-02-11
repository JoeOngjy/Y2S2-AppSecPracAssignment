using System.ComponentModel.DataAnnotations;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class Member
    {
        [Key]
        public Guid UserId { get; set; } // Add GUID for UserId
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required(ErrorMessage = "Please enter a valid NRIC.")]
        public string NRIC { get; set; } // Store encrypted NRIC value

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string PasswordHash { get; set; } // Store hashed password, not plain text

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string WhoAmI { get; set; }  // Special chars allowed, optional field

        public byte[] Resume { get; set; }

        public DateTime PasswordLastChanged { get; set; }

        [MaxLength(6)]
        public string VerificationCode { get; set; } // Stores 6-digit code as a string

        public bool IsVerified { get; set; } = false; // Default to false (not verified)

    }
}
