using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;
using Y2S2_AppSecPracAssignment.Models;

namespace Y2S2_AppSecPracAssignment.util
{
    public class SessionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionMiddleware> _logger;
        private readonly IServiceProvider _serviceProvider;  // Add IServiceProvider

        public SessionMiddleware(RequestDelegate next, ILogger<SessionMiddleware> logger, IServiceProvider serviceProvider)
        {
            _next = next;
            _logger = logger;
            _serviceProvider = serviceProvider;  // Inject IServiceProvider
        }


        public async Task InvokeAsync(HttpContext context)
        {
            var sessionStart = context.Session.GetString("SessionStart");

            var path = context.Request.Path.ToString().ToLower();

            if (path.Contains("/resetpassword") ||
        path.Contains("/forgotpassword") ||
        path.Contains("/login") ||
        path.Contains("/register"))
            {
                await _next(context);
                return;
            }

            // Check if redirect flag is set, if it is, skip the redirect logic
            if (context.Session.GetString("RedirectOccurred") == "true")
            {
                await _next(context);
                return;
            }

            if (string.IsNullOrEmpty(sessionStart))
            {
                _logger.LogInformation("No session found. Proceeding without redirect.");
                await SignOutandRedirect(context);
                return;
            }

            if (!DateTime.TryParse(sessionStart, out DateTime sessionStartDate))
            {
                _logger.LogWarning("Invalid session start date format.");
                await SignOutandRedirect(context);
                return;
            }

            if (DateTime.UtcNow - sessionStartDate > TimeSpan.FromMinutes(30))
            {
                _logger.LogWarning("Session timed out, redirecting to login.");
                SessionMiddleware.ClearSession(context);
                await SignOutandRedirect(context);
                return;
            }

            RefreshSessionStart(context);
            await _next(context);
        }

        private async Task SignOutandRedirect(HttpContext context)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<IdentityUser>>();
                await signInManager.SignOutAsync();
            }

            // Set the redirect flag to prevent further redirects in the session
            context.Session.SetString("RedirectOccurred", "true");

            context.Response.Redirect("/Login?sessionexpired=true"); // Redirect with query parameter
        }


        private async Task SignOutAndRedirect(HttpContext context)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<IdentityUser>>();
                await signInManager.SignOutAsync();
            }

            context.Response.Redirect("/Login?sessionexpired=true"); // Redirect with query parameter

        }



        // Method to create a new session and store it in the session and database
        public static async Task CreateSessionAsync(HttpContext context, AppDbContext dbContext, Guid userId)
        {
            var sessionId = Guid.NewGuid().ToString(); // Generate a unique session ID
            var userSession = new UserSession
            {
                SessionId = sessionId,
                UserId = userId,
                CreatedAt = DateTime.UtcNow
            };

            // Add the new session to the database
            await dbContext.UserSessions.AddAsync(userSession);
            await dbContext.SaveChangesAsync();

            // Set session information in the HTTP context
            SetSession(context, sessionId, userId);
        }

        // Method to set session details in the HTTP context
        private static void SetSession(HttpContext context, string sessionId, Guid userId)
        {
            context.Session.SetString("SessionId", sessionId);
            context.Session.SetString("UserId", userId.ToString());
            context.Session.SetString("SessionStart", DateTime.UtcNow.ToString());
        }

        // Method to refresh the session start time
        private static void RefreshSessionStart(HttpContext context)
        {
            context.Session.SetString("SessionStart", DateTime.UtcNow.ToString());
        }

        // Method to clear the session (for logout)
        public static void ClearSession(HttpContext context)
        {
            context.Session.Clear();
        }
    }
}
