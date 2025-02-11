using System;
using System.ComponentModel.DataAnnotations;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class UserSession
    {
        [Key]
        public int Id { get; set; } // Primary Key for UserSession

        [Required]
        public string SessionId { get; set; }  // Stores the Session ID (string type)

        // Foreign Key to Member table (using GUID for UserId)
        [Required]
        public Guid UserId { get; set; }

        // Navigation property to Member (optional)
        public virtual Member User { get; set; } // Allows loading related user details

        public DateTime CreatedAt { get; set; }  // Optional: to track when the session was created
    }
}
