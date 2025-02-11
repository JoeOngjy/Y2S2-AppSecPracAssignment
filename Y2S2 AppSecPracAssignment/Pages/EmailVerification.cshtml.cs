using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class EmailVerificationModel : PageModel
    {
        private readonly AppDbContext _context;
        private readonly ILogger<EmailVerificationModel> _logger;

        public EmailVerificationModel(AppDbContext context, ILogger<EmailVerificationModel> logger)
        {
            _context = context;
            _logger = logger;
        }

        [BindProperty]
        public string VerificationCode { get; set; }

        [BindProperty]
        public string ErrorMessage { get; set; }

        public async Task<IActionResult> OnPostVerifyAsync()
        {
            _logger.LogInformation("Received verification code: {VerificationCode}", VerificationCode);

            var member = await _context.Members.FirstOrDefaultAsync(m => m.VerificationCode == VerificationCode);

            if (member != null)
            {
                _logger.LogInformation("Verification code matched for member with ID: {MemberId}", member.Email);

                member.IsVerified = true;  // Mark email as verified
                _context.Update(member);

                try
                {
                    await _context.SaveChangesAsync();
                    _logger.LogInformation("Member with ID: {MemberId} has been successfully verified.", member.Email);
                    return RedirectToPage("Index"); // Redirect to home or dashboard after verification
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred while saving member verification status.");
                    ErrorMessage = "An error occurred while processing your request. Please try again later.";
                    return Page();
                }
            }

            _logger.LogWarning("Invalid verification code: {VerificationCode}", VerificationCode);
            ErrorMessage = "Invalid verification code. Please try again.";
            return Page();
        }
    }


}