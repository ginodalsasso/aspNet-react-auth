namespace aspNet_react_auth.Server.Services;

public interface IEmailService
{
    Task SendEmailAsync(string toEmail, string subject, string htmlMessage);
    Task SendConfirmationEmailAsync(string toEmail, string confirmationLink);
}