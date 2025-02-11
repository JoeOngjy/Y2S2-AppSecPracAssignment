using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Y2S2_AppSecPracAssignment.Models;
using Microsoft.AspNetCore.Http;
using System;
using System.Net.Http;
using System.Text.Json;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using Y2S2_AppSecPracAssignment.util;

namespace Y2S2_AppSecPracAssignment.Pages
{
    [Route("account/login")]
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory; // Inject IHttpClientFactory
        private readonly string _recaptchaSecret = "6Lf93c0qAAAAAIZQAn9E9GT75p_hV2Npixk_hM71";  // Your secret key
        private readonly AppDbContext _dbContext;

        public LoginModel(SignInManager<IdentityUser> signInManager,
                          UserManager<IdentityUser> userManager,
                          ILogger<LoginModel> logger,
                          IHttpContextAccessor httpContextAccessor,
                          IHttpClientFactory httpClientFactory,
                          AppDbContext dbContext) // Inject IHttpClientFactory
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _httpClientFactory = httpClientFactory; // Assign IHttpClientFactory to the class variable
            _dbContext = dbContext;
        }

        [BindProperty]
        public LoginViewModel LoginViewModel { get; set; }

        public void OnGet()
        {
            _logger.LogInformation("Accessed the Login page via GET.");
        }

        [ValidateAntiForgeryToken]  // Protects against CSRF

        public async Task<IActionResult> OnPostAsync()
        {
            _logger.LogInformation("Login POST request started.");

            if (!ModelState.IsValid)
            {
                foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                {
                    _logger.LogWarning($"Model validation error: {error.ErrorMessage}");
                }
                return Page();
            }

            // Verify reCAPTCHA token
            var isCaptchaValid = await VerifyRecaptchaAsync(LoginViewModel.RecaptchaToken);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid reCAPTCHA. Please try again.");
                _logger.LogWarning("reCAPTCHA validation failed.");
                return Page();
            }

            // Find user by email
            var user = await _userManager.FindByEmailAsync(LoginViewModel.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                _logger.LogWarning("Login failed: User not found.");
                return Page();
            }

            // Check if the user is locked out
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = user.LockoutEnd?.UtcDateTime.ToString("f") ?? "an unknown time";
                ModelState.AddModelError(string.Empty, $"Your account is locked until {lockoutEnd}.");
                _logger.LogWarning($"User {LoginViewModel.Email} is locked out until {lockoutEnd}.");
                return Page();
            }

            // Attempt to sign in
            var result = await _signInManager.PasswordSignInAsync(LoginViewModel.Email, LoginViewModel.Password, false, lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation($"User {LoginViewModel.Email} logged in successfully.");
                await _userManager.ResetAccessFailedCountAsync(user); // Reset failed attempts on success

                // Store session information
                await SessionMiddleware.CreateSessionAsync(HttpContext, _dbContext, new Guid(user.Id));


                return RedirectToPage("Index");
            }

            // Account locked out due to failed attempts
            if (result.IsLockedOut)
            {
                var lockoutEnd = user.LockoutEnd?.UtcDateTime.ToString("f") ?? "an unknown time";
                ModelState.AddModelError(string.Empty, $"Your account has been locked until {lockoutEnd}.");
                _logger.LogWarning($"User {LoginViewModel.Email} has been locked out until {lockoutEnd}.");
                return Page();
            }

            // Increment failed login attempts
            await _userManager.AccessFailedAsync(user);
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            _logger.LogWarning($"Login failed for user {LoginViewModel.Email}.");
            return Page();
        }

        // Verify reCAPTCHA with Google API
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
                    if (success && score >= 0.5 && action == "login")
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



    }

    // reCAPTCHA response model
    public class RecaptchaResponse
    {
        public bool Success { get; set; }
        public string ChallengeTs { get; set; }
        public string Hostname { get; set; }
        public string[] ErrorCodes { get; set; }
        public double Score { get; set; } // Add this
        public string Action { get; set; } // Add this
    }
}
