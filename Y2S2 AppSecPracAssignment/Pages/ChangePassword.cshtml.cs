using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Y2S2_AppSecPracAssignment.util;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;  // Inject the DbContext to access the Member model
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly PasswordHistoryCheck _passwordHistoryCheck;

        public ChangePasswordModel(UserManager<IdentityUser> userManager, AppDbContext context, ILogger<ChangePasswordModel> logger, PasswordHistoryCheck passwordHistoryCheck)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
            _passwordHistoryCheck = passwordHistoryCheck;
        }

        [BindProperty]
        public ChangePasswordViewModel ChangePasswordViewModel { get; set; }
        public string ErrorMessage { get; set; }
        public string SuccessMessage { get; set; }
        public void OnGet()
        {
            _logger.LogInformation("Accessed the Change Password page.");
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                _logger.LogError("User not found during password change.");
                return RedirectToPage("/Error");
            }

            if (!Guid.TryParse(user.Id, out Guid userId))
            {
                _logger.LogError("Invalid UserId format.");
                return RedirectToPage("/Error");
            }

            _logger.LogInformation("Looking for member with UserId: {UserId}", user.Id);
            var member = await _context.Members.FirstOrDefaultAsync(m => m.UserId.ToString() == user.Id);
            if (member == null)
            {
                _logger.LogError("Member record not found during password change.");
                return RedirectToPage("/Error");
            }

            // Check if the new password has been used recently
            bool isNewPassword = await _passwordHistoryCheck.PasswordHistoryChecker(user.Id, ChangePasswordViewModel.NewPassword);
            if (!isNewPassword)
            {
                ErrorMessage = "This password has been used recently. Please choose a different one.";
                _logger.LogWarning("User {Email} attempted to reuse an old password.", user.Email);
                return Page();
            }

            var result = await _userManager.ChangePasswordAsync(user, ChangePasswordViewModel.OldPassword, ChangePasswordViewModel.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    // Add each error description to the ModelState and return to the page with the error
                    ModelState.AddModelError(string.Empty, error.Description);
                }
                ErrorMessage = "Failed to change the password. Please check the error details and try again.";
                _logger.LogWarning("Password change failed for user {Email}.", user.Email);
                return Page();
            }




            

            var passwordHash = _userManager.PasswordHasher.HashPassword(user, ChangePasswordViewModel.NewPassword);
            member.PasswordHash = passwordHash;

            _context.Members.Update(member);
            await _context.SaveChangesAsync();
            SuccessMessage = "Your password has been changed successfully.";

            _logger.LogInformation("User changed password successfully.");
            return Page();
        }
    }
}
