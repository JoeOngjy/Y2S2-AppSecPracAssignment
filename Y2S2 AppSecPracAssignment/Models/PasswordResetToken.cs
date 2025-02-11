using Microsoft.AspNetCore.Identity;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class PasswordResetToken
    {
        public int Id { get; set; } // Define a primary key (e.g., Id)

        public Guid UserId { get; set; } // The UserId referring to the IdentityUser
        public string Token { get; set; } // The reset token
        public DateTime ExpirationDate { get; set; } // Expiration date for the token

        // Navigation property (optional)
        public IdentityUser User { get; set; } // This allows for a relationship with the IdentityUser
    }
}
