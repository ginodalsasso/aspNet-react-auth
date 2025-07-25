using System.Net.Mail;

namespace aspNet_react_auth.Server.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string htmlMesssage)
    {
        var smtpConfig = _configuration.GetSection("EmailSettings"); // Retrieve email settings from appsettings

        var fromEmail = smtpConfig["FromEmail"] ?? "";
        var fromName = smtpConfig["FromName"] ?? "";
        var host = smtpConfig["Host"] ?? "";
        var port = int.TryParse(smtpConfig["Port"], out var p) ? p : 587;
        var username = smtpConfig["Username"];
        var password = smtpConfig["Password"] ?? Environment.GetEnvironmentVariable("Password");
        Console.WriteLine($"SMTP PASSWORD (env): {(string.IsNullOrEmpty(password) ? "NOT FOUND" : "FOUND")}");

        var enableSsl = bool.TryParse(smtpConfig["EnableSsl"], out var ssl) && ssl;

        if (string.IsNullOrEmpty(fromEmail) || string.IsNullOrEmpty(fromName) || string.IsNullOrEmpty(host) || string.IsNullOrEmpty(username))
        {
            throw new InvalidOperationException("SMTP configuration is incomplete. Please check your appsettings.");
        }

        if (string.IsNullOrEmpty(password))
        {
            throw new InvalidOperationException("SMTP password is not set. Use a secure method to provide it.");
        }

        // Create the email message
        using var mail = new MailMessage
        {
            From = new MailAddress(fromEmail, fromName),
            Subject = subject,
            Body = htmlMesssage,
            IsBodyHtml = true
        };

        mail.To.Add(toEmail);

        using var smtpClient = new SmtpClient(host, port)
        {
            Credentials = new System.Net.NetworkCredential(username, password),
            EnableSsl = enableSsl // Enable SSL if specified in the configuration and valid 
        };

        await smtpClient.SendMailAsync(mail); // Send the email asynchronously
    }

    public async Task SendConfirmationEmailAsync(string toEmail, string confirmationLink)
    {
        var subject = "Please confirm your email address";
        var htmlMessage = $"<p>Thank you for registering! Please confirm your email by clicking the link below:</p><p><a href=\"{confirmationLink}\">Confirm Email</a></p>";
        await SendEmailAsync(toEmail, subject, htmlMessage);
    }

    public async Task SendPasswordResetEmailAsync(string toEmail, string resetLink)
    {
        var subject = "Password Reset Request";
        var htmlMessage = $"<p>We received a request to reset your password. Click the link below to reset it:</p><p><a href=\"{resetLink}\">Reset Password</a></p>";
        await SendEmailAsync(toEmail, subject, htmlMessage);
    }
}