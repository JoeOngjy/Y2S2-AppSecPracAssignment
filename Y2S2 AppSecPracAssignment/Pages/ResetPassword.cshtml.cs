using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.EntityFrameworkCore;
using Y2S2_AppSecPracAssignment.util; // Include the PasswordHistoryCheck class

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;
        private readonly ILogger<ResetPasswordModel> _logger;
        private readonly PasswordHistoryCheck _passwordHistoryCheck; // Add PasswordHistoryCheck instance

        public ResetPasswordModel(UserManager<IdentityUser> userManager, AppDbContext context, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _context = context;
            _logger = logger;
            _passwordHistoryCheck = new PasswordHistoryCheck(userManager, context); // Initialize the PasswordHistoryCheck
        }

        [BindProperty]
        public string NewPassword { get; set; }
        [BindProperty]
        public string ConfirmPassword { get; set; }

        public string ErrorMessage { get; set; }
        public string SuccessMessage { get; set; }

        public string Token { get; set; }

        public void OnGet(string token)
        {
            Token = token;
            _logger.LogInformation("Password reset initiated for token: {Token}", Token);
        }

        public async Task<IActionResult> OnPostAsync(string token)
        {
            // Step 1: Find the token in the database
            var resetToken = await _context.PasswordResetTokens
                                            .FirstOrDefaultAsync(t => t.Token == token);

            if (resetToken == null)
            {
                ErrorMessage = "Invalid or expired token.";
                _logger.LogWarning("Invalid or expired password reset token.");
                return Page();
            }

            // Step 2: Check if the token has expired
            if (resetToken.ExpirationDate < DateTime.UtcNow)
            {
                ErrorMessage = "The password reset token has expired.";
                _logger.LogWarning("Password reset token expired for token: {Token}", token);
                return Page();
            }

            // Step 3: Find the user by UserId
            var user = await _userManager.FindByIdAsync(resetToken.UserId.ToString());
            if (user == null)
            {
                ErrorMessage = "User not found.";
                return Page();
            }

            // Step 4: Check password history
            bool isNewPassword = await _passwordHistoryCheck.PasswordHistoryChecker(user.Id, NewPassword);
            if (!isNewPassword)
            {
                ErrorMessage = "This password has been used recently. Please choose a different one.";
                _logger.LogWarning("User {Email} attempted to reuse an old password.", user.Email);
                return Page();
            }

            // Step 5: Reset the password
            var resetResult = await _userManager.ResetPasswordAsync(user, token, NewPassword);
            if (resetResult.Succeeded)
            {
                SuccessMessage = "Password has been successfully reset.";
                _logger.LogInformation("Password successfully reset for user: {Email}", user.Email);
                return RedirectToPage("Login");
            }
            else
            {
                ErrorMessage = "Error resetting password.";
                _logger.LogError("Error resetting password for user: {Email}", user.Email);
                return Page();
            }
        }
    }
}
