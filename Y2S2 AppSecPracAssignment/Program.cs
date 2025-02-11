using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Y2S2_AppSecPracAssignment.Models;
using Y2S2_AppSecPracAssignment.util;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Session expires after 30 mins of inactivity
    options.Cookie.HttpOnly = true; // Prevents JavaScript access (Mitigates XSS attacks)
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensures session cookies are sent only over HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Prevents CSRF attacks
});
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login"; // Specify the correct login path
        options.AccessDeniedPath = "/access-denied"; // Specify access denied path, if needed
    });



// Add services to the container.
builder.Services.AddSingleton<IEmailSender, EmailSender>();
builder.Services.AddTransient<PasswordHistoryCheck>();
builder.Services.AddHttpClient();
builder.Services.AddRazorPages();
builder.Services.AddHttpContextAccessor(); // Needed for accessing session in Razor Pages
builder.Services.AddSingleton<EncryptionHelper>();


builder.Services.AddDbContext<AppDbContext>();
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Optional: You can clear other providers, but make sure you have at least one default for password reset
    options.Tokens.ProviderMap.Clear();

    // This will configure the default token provider for password reset
    options.Tokens.PasswordResetTokenProvider = TokenOptions.DefaultProvider; // Use the default provider for password reset
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders(); // Ensure default token providers are added

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts(); // The default HSTS value is 30 days. You may want to change this for production scenarios.
}

// Register the session timeout middleware first

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseSession();

app.UseMiddleware<SessionMiddleware>(); // Register the middleware
                                        // Authentication and authorization should come after session middleware
app.UseStatusCodePagesWithReExecute("/Error{0}", "?code={0}");

app.UseAuthentication();
app.UseAuthorization();


app.MapRazorPages();

app.Run();

//6Lf93c0qAAAAANCiAFzTrvhfjPF4xdlF16OPLxp7 Site
//6Lf93c0qAAAAAIZQAn9E9GT75p_hV2Npixk_hM71 Secret