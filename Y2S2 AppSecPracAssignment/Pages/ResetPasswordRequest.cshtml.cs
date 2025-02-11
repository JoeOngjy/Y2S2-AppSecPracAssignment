using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;
using Y2S2_AppSecPracAssignment.Models;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class ResetPasswordRequestModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<ResetPasswordRequestModel> _logger;
        private readonly AppDbContext _context; // Inject your DbContext here

        // Constructor
        public ResetPasswordRequestModel(UserManager<IdentityUser> userManager, IEmailSender emailSender, ILogger<ResetPasswordRequestModel> logger, AppDbContext context)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
            _context = context; // Initialize the DbContext
        }

        [BindProperty]
        public string Email { get; set; }

        public string ErrorMessage { get; set; }
        public string SuccessMessage { get; set; }

        public void OnGet()
        {
            // This method handles GET requests, you can use it to render the initial page.
        }

        public async Task OnPostAsync()
        {
            // Check if the email is provided.
            if (string.IsNullOrEmpty(Email))
            {
                ErrorMessage = "Email address is required.";
                _logger.LogWarning("No email address provided.");
                return;
            }

            var user = await _userManager.FindByEmailAsync(Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist or the email is not confirmed.
                SuccessMessage = "If an account with that email exists, we have sent a password reset link.";
                _logger.LogInformation("No user found or email is not confirmed for email: {Email}", Email);
                return;
            }

            // Log that we found the user
            _logger.LogInformation("User found for email: {Email}", Email);

            // Generate the password reset token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            // Save the token to the database
            var expirationDate = DateTime.UtcNow.AddHours(1); // Set expiration date (1 hour in this case)
            var resetToken = new PasswordResetToken
            {
                UserId = Guid.Parse(user.Id),
                Token = token,
                ExpirationDate = expirationDate
            };

            // Save the reset token to the database
            _context.PasswordResetTokens.Add(resetToken);
            await _context.SaveChangesAsync();

            // Generate the reset URL
            var resetUrl = Url.Page(
                "/ResetPassword",
                null,
                new { token },
                protocol: Request.Scheme); // This ensures that the URL includes the scheme (http/https)
            _logger.LogInformation("Reset link generated: {resetUrl}", resetUrl); // Fixed logging format

            // Prepare the email message
            var message = $"Please reset your password by clicking the following link: {resetUrl}";

            try
            {
                // Log that we're about to send the email
                _logger.LogInformation("Attempting to send password reset email to: {Email}", Email);

                // Send the reset password email
                await _emailSender.SendEmailAsync(Email, "Reset Password", message);

                // Log success
                SuccessMessage = "If an account with that email exists, we have sent a password reset link.";
                _logger.LogInformation("Password reset email sent to: {Email}", Email);
            }
            catch (Exception ex)
            {
                // Handle errors if the email couldn't be sent
                ErrorMessage = $"There was an error sending the email: {ex.Message}";
                _logger.LogError(ex, "Error sending password reset email to: {Email}", Email);
            }
        }
    }
}
