using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace Y2S2_AppSecPracAssignment.util
{
    public class EmailSender : IEmailSender
    {
        private readonly string _smtpHost;
        private readonly string _smtpUser;
        private readonly string _smtpPassword;
        private readonly int _smtpPort;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
        {
            _smtpHost = configuration["EmailSettings:SmtpHost"];
            _smtpUser = configuration["EmailSettings:SmtpUser"];
            _smtpPassword = configuration["EmailSettings:SmtpPassword"];
            _smtpPort = int.Parse(configuration["EmailSettings:SmtpPort"]);
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            // Configure the SMTP client
            using (var client = new SmtpClient(_smtpHost, _smtpPort))
            {
                client.Credentials = new NetworkCredential(_smtpUser, _smtpPassword);
                client.EnableSsl = true;  // Ensure SSL is enabled for Gmail

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(_smtpUser),
                    Subject = subject,
                    Body = message,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(email);

                // Send the email
                await client.SendMailAsync(mailMessage);
            }
        }
    }
}
