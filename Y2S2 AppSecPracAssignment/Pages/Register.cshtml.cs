using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.DataProtection;
using Y2S2_AppSecPracAssignment.util;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace Y2S2_AppSecPracAssignment.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly AppDbContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAntiforgery _antiforgery;
        private readonly EncryptionHelper _encryptionHelper;
        private readonly PasswordHistoryCheck _passwordHistoryCheck;
        private readonly IEmailSender _emailSender;

        private readonly string _recaptchaSecret = "6Lf93c0qAAAAAIZQAn9E9GT75p_hV2Npixk_hM71"; // Your reCAPTCHA secret key
        public RegisterModel(AppDbContext context, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,
            ILogger<RegisterModel> logger, IHttpClientFactory httpClientFactory, EncryptionHelper encryptionHelper,
            IAntiforgery antiforgery, PasswordHistoryCheck passwordHistoryCheck, IEmailSender emailSender)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _antiforgery = antiforgery;
            _encryptionHelper = encryptionHelper;
            _passwordHistoryCheck = passwordHistoryCheck;
            _emailSender = emailSender;
        }


        [BindProperty]
        public RegisterViewModel RegisterViewModel { get; set; }

        public void OnGet()
        {
            _logger.LogInformation("Accessed the Register page via GET.");
        }

        [ValidateAntiForgeryToken]

        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("Register POST request started.");

            if (!ModelState.IsValid)
            {
                foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                {
                    _logger.LogWarning($"Model validation error: {error.ErrorMessage}");
                }
                return Page();
            }

            if (string.IsNullOrEmpty(RegisterViewModel.RecaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA token is missing.");
                return Page();
            }

            _logger.LogDebug(RegisterViewModel.RecaptchaToken);
            var isCaptchaValid = await VerifyRecaptchaAsync(RegisterViewModel.RecaptchaToken);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid reCAPTCHA. Please try again.");
                _logger.LogWarning("reCAPTCHA validation failed.");
                return Page();
            }

            // Password Complexity Check (Server-side)
            if (!IsPasswordComplexEnough(RegisterViewModel.Password))
            {
                ModelState.AddModelError("RegisterViewModel.Password", "Password must be at least 12 characters long and contain a combination of lower-case, upper-case letters, numbers, and special characters.");
                _logger.LogWarning("Password does not meet the complexity requirements.");
                return Page();
            }

            if (RegisterViewModel.Resume == null || RegisterViewModel.Resume.Length == 0)
            {
                ModelState.AddModelError("RegisterViewModel.Resume", "Resume file is required.");
                _logger.LogWarning("No resume uploaded. Registration failed.");
                return Page();
            }
            if (RegisterViewModel.Resume != null)
            {
                var fileExtension = Path.GetExtension(RegisterViewModel.Resume.FileName).ToLowerInvariant();
                if (fileExtension != ".docx" && fileExtension != ".pdf")
                {
                    ModelState.AddModelError("RegisterViewModel.Resume", "The resume must be in either .docx or .pdf format.");
                    return Page();
                }
            }
            if (RegisterViewModel.DateOfBirth > DateTime.Now)
            {
                ModelState.AddModelError("RegisterViewModel.DateOfBirth", "Date of birth cannot be in the future.");
                _logger.LogWarning("Date of birth is in the future.");
                return Page();
            }

            _logger.LogInformation("Model is valid. Proceeding with registration.");

            var existingUser = await _context.Members.FirstOrDefaultAsync(m => m.Email == RegisterViewModel.Email);
            if (existingUser != null)
            {
                ModelState.AddModelError("RegisterViewModel.Email", "This email is already registered.");
                _logger.LogWarning($"Registration failed: Email {RegisterViewModel.Email} is already in use.");
                return Page();
            }

            var passwordHash = _userManager.PasswordHasher.HashPassword(null, RegisterViewModel.Password);

            // Create the IdentityUser object first
            var identityUser = new IdentityUser
            {
                UserName = RegisterViewModel.Email,
                Email = RegisterViewModel.Email
            };

            // Create the IdentityUser using UserManager
            var result = await _userManager.CreateAsync(identityUser, RegisterViewModel.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("User created in Identity system.");

                // Create the Member object and assign the IdentityUser Id
                var verificationCode = new Random().Next(100000, 999999).ToString(); // Generate 6-digit code

                var member = new Member
                {
                    FirstName = RegisterViewModel.FirstName,
                    LastName = RegisterViewModel.LastName,
                    Gender = RegisterViewModel.Gender,
                    NRIC = _encryptionHelper.Encrypt(RegisterViewModel.NRIC),
                    Email = RegisterViewModel.Email,
                    PasswordHash = passwordHash,
                    DateOfBirth = RegisterViewModel.DateOfBirth,
                    WhoAmI = RegisterViewModel.WhoAmI,
                    UserId = Guid.Parse(identityUser.Id),
                    VerificationCode = verificationCode,
                    IsVerified = false
                };

                string verificationMessage = $"Your verification code is: {verificationCode}";
                await _emailSender.SendEmailAsync(RegisterViewModel.Email, "Email Verification", verificationMessage);


                using (var memoryStream = new MemoryStream())
                {
                    await RegisterViewModel.Resume.CopyToAsync(memoryStream);
                    member.Resume = memoryStream.ToArray();
                }

                _logger.LogInformation("Resume uploaded and stored in the database.");

                try
                {
                    _context.Members.Add(member);  // Add the member to the database
                    await _context.SaveChangesAsync();  // Save the member with the IdentityUser Id
                    _logger.LogInformation("Member registration successful.");


                    // Sign in the user immediately after registration
                    await _signInManager.SignInAsync(identityUser, isPersistent: false);

                    // Redirect to home page or dashboard
                    await SessionMiddleware.CreateSessionAsync(HttpContext, _context, new Guid(identityUser.Id));

                    bool isNewPassword = await _passwordHistoryCheck.PasswordHistoryChecker(identityUser.Id, RegisterViewModel.Password);
                    if (!isNewPassword)
                    {
                        ModelState.AddModelError("RegisterViewModel.Password", "This password has been used recently. Please choose a different one.");
                        return Page();
                    }

                    return RedirectToPage("EmailVerification"); // Redirect to email verification page
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Database error: {ex.Message}");
                    return StatusCode(500, "Internal server error while saving member data.");
                }
            }
            else
            {
                // Add any errors from Identity into the ModelState
                foreach (var error in result.Errors)
                {
                    _logger.LogError($"Identity error: {error.Description}");
                    ModelState.AddModelError("", error.Description);
                }
                return Page();
            }
        }


        public async Task<IActionResult> OnPostClearDatabaseAsync()
        {
            _logger.LogWarning("Clearing all tables from the database.");

            // Clear Members table
            _context.Members.RemoveRange(_context.Members);

            // Clear Identity tables
            _context.Roles.RemoveRange(_context.Roles);
            _context.RoleClaims.RemoveRange(_context.RoleClaims);
            _context.UserClaims.RemoveRange(_context.UserClaims);
            _context.UserLogins.RemoveRange(_context.UserLogins);
            _context.UserRoles.RemoveRange(_context.UserRoles);
            _context.UserTokens.RemoveRange(_context.UserTokens);
            _context.UserSessions.RemoveRange(_context.UserSessions);
            _context.PasswordHistories.RemoveRange(_context.PasswordHistories);

            // Clear application-specific tables
            _context.Users.RemoveRange(_context.Users); // Assuming this is the correct DbSet for users
            _context.Members.RemoveRange(_context.Members);

            // Clear all other tables (if any)
            // Add more RemoveRange statements for any other tables you have in the context

            await _context.SaveChangesAsync();

            return RedirectToPage("Register");
        }


        private bool IsPasswordComplexEnough(string password)
        {
            // Check for minimum length
            if (password.Length < 12)
            {
                return false;
            }

            // Check for a combination of lower-case, upper-case, numbers, and special characters
            if (!password.Any(char.IsLower) || !password.Any(char.IsUpper) || !password.Any(char.IsDigit) || !password.Any(ch => "!@#$%^&*(),.?\":{}|<>".Contains(ch)))
            {
                return false;
            }

            return true;
        }

        private async Task<bool> VerifyRecaptchaAsync(string recaptchaToken)
        {
            var client = _httpClientFactory.CreateClient();
            var response = await client.PostAsync(
                "https://www.google.com/recaptcha/api/siteverify",
                new FormUrlEncodedContent(new[]
                {
            new KeyValuePair<string, string>("secret", _recaptchaSecret),
            new KeyValuePair<string, string>("response", recaptchaToken)
                })
            );

            // Read the JSON response
            var jsonResponse = await response.Content.ReadAsStringAsync();
            _logger.LogInformation($"reCAPTCHA Response: {jsonResponse}");

            try
            {
                // Use JsonDocument for deserialization
                using (var jsonDoc = JsonDocument.Parse(jsonResponse))
                {
                    var root = jsonDoc.RootElement;

                    // Extract relevant fields
                    bool success = root.GetProperty("success").GetBoolean();
                    double score = root.GetProperty("score").GetDouble();
                    string action = root.GetProperty("action").GetString();
                    var errorCodes = root.TryGetProperty("error-codes", out var errorCodesArray)
                        ? errorCodesArray.EnumerateArray().Select(e => e.GetString()).ToArray()
                        : Array.Empty<string>();

                    // Log individual fields
                    _logger.LogInformation($"reCAPTCHA validation success: {success}");
                    _logger.LogInformation($"reCAPTCHA score: {score}");
                    _logger.LogInformation($"reCAPTCHA action: {action}");

                    if (errorCodes.Any())
                    {
                        foreach (var errorCode in errorCodes)
                        {
                            _logger.LogWarning($"reCAPTCHA Error: {errorCode}");
                        }
                    }

                    // Check validation criteria: success, score, and action
                    if (success && score >= 0.5 && action == "register")
                    {
                        _logger.LogInformation("reCAPTCHA validation succeeded.");
                        return true;
                    }

                    _logger.LogWarning("reCAPTCHA validation failed.");
                    return false;
                }
            }
            catch (JsonException ex)
            {
                // Log if there's a deserialization error
                _logger.LogError($"Error during reCAPTCHA JSON deserialization: {ex.Message}");
                return false;
            }
        }

        public class RecaptchaResponse
        {
            public bool Success { get; set; }
            public string ChallengeTs { get; set; }
            public string Hostname { get; set; }
            public double Score { get; set; }
            public string Action { get; set; }
            public string[] ErrorCodes { get; set; }
        }
    }
}
