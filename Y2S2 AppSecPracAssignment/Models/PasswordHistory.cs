namespace Y2S2_AppSecPracAssignment.Models
{
    public class PasswordHistory
    {
        public int Id { get; set; }  // Primary Key
        public Guid UserId { get; set; }  // Foreign Key to IdentityUser (GUID type)
        public string PasswordHash { get; set; }  // Hash of the previous password
        public DateTime CreatedAt { get; set; }  // Date and time of the password change

    }
}
