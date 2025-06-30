namespace aspNet_react_auth.Server.Services
{
    public interface ICsrfService
    {
        string GenerateToken(string userId);
        bool ValidateToken(string token, string userId);
        void InvalidateToken(string userId);
    }
}
