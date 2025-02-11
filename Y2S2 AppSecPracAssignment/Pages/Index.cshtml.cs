using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.EntityFrameworkCore;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppDbContext _context;
        private readonly EncryptionHelper _encryptionHelper;
        private readonly SignInManager<IdentityUser> _signInManager; // Inject SignInManager for logout functionality

        public IndexModel(ILogger<IndexModel> logger, UserManager<IdentityUser> userManager, AppDbContext context, EncryptionHelper encryptionHelper, SignInManager<IdentityUser> signInManager)
        {
            _logger = logger;
            _userManager = userManager;
            _context = context;
            _encryptionHelper = encryptionHelper;
            _signInManager = signInManager;  // Store the injected SignInManager
        }

        public Member CurrentMember { get; set; }

        public async Task OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User); // Get the current logged-in user

            if (user != null)
            {
                var member = await _context.Members
                    .FirstOrDefaultAsync(m => m.Email == user.Email); // Retrieve member info by email

                if (member != null)
                {
                    member.NRIC = _encryptionHelper.Decrypt(member.NRIC);

                    CurrentMember = member;
                }
            }
        }

        public async Task<IActionResult> OnPostLogoutAsync()
        {
            HttpContext.Session.Clear(); // Clears all session data
            await _signInManager.SignOutAsync();
            return RedirectToPage("Login");
        }
    }
}
