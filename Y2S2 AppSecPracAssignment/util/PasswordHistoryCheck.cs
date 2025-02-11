using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;
using Y2S2_AppSecPracAssignment.Models; // Update with the actual namespace for your model

namespace Y2S2_AppSecPracAssignment.util
{
    public class PasswordHistoryCheck
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;

        public PasswordHistoryCheck(UserManager<IdentityUser> userManager, AppDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task<bool> PasswordHistoryChecker(string userId, string password)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new InvalidOperationException("User not found");
            }

            // Get last 2 password hashes from the history
            var passwordHistory = await _context.PasswordHistories
                .Where(p => p.UserId.ToString() == userId)
                .OrderByDescending(p => p.CreatedAt)
                .Take(2)
                .ToListAsync();

            // Hash the provided password
            var hashedPassword = _userManager.PasswordHasher.HashPassword(user, password);

            // Check if the password matches any of the last 2 passwords in history
            foreach (var history in passwordHistory)
            {
                if (_userManager.PasswordHasher.VerifyHashedPassword(user, history.PasswordHash, password) == PasswordVerificationResult.Success)
                {
                    return false; // Password exists in history, reject it
                }
            }

            // If password is new, save it to history
            var newHistoryEntry = new PasswordHistory
            {
                UserId = Guid.Parse(userId), // Convert string ID to Guid if necessary
                PasswordHash = hashedPassword,
                CreatedAt = DateTime.UtcNow
            };

            _context.PasswordHistories.Add(newHistoryEntry);
            await _context.SaveChangesAsync();

            return true; // Password is new and successfully saved
        }
    }
}
