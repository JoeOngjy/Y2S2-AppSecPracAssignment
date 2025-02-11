using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace Y2S2_AppSecPracAssignment.Models
{
    public class AppDbContext : IdentityDbContext
    {
        private readonly IConfiguration _configuration;

        public AppDbContext(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            string connectionString = _configuration.GetConnectionString("ConnectionString");
            optionsBuilder.UseSqlServer(connectionString);
        }
        public DbSet<Member> Members { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }  // Table for UserSessions

        public DbSet<PasswordResetToken> PasswordResetTokens { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

    }
}
