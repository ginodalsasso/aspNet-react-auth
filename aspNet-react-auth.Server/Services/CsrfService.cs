using Microsoft.Extensions.Caching.Memory;
using System.Diagnostics.Eventing.Reader;
using System.Security.Cryptography;

namespace aspNet_react_auth.Server.Services
{
    public class CsrfService : ICsrfService
    {
        private readonly IMemoryCache _cache; // Memory cache for storing CSRF tokens
        private readonly ILogger<CsrfService> _logger;
        public CsrfService(IMemoryCache cache, ILogger<CsrfService> logger)
        {
            _cache = cache;
            _logger = logger;
        }

        // Generate and store a CSRF token for a user
        public string GenerateToken(string userId)
        {
            var tokenBytes = new byte[32]; // Generate a 32-byte token
            using var rng = RandomNumberGenerator.Create(); // Use a secure random number generator
            rng.GetBytes(tokenBytes); // Fill the byte array with random bytes

            var token = Convert.ToBase64String(tokenBytes); // Convert the byte array to a Base64 string

            var cacheKey = $"csrf_token_{userId}"; // Create a unique cache key for the user to store the token
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1), // expire in 1 hour
                SlidingExpiration = TimeSpan.FromMinutes(30) // Extend expiration for 30 minutes of inactivity
            };

            _cache.Set(cacheKey, token, cacheOptions); // Store the token in the cache

            _logger.LogInformation("Generated CSRF token for user {UserId}: {Token}", userId, token);
            return token;
        }

        // Validate a CSRF token for a user
        public bool ValidateToken(string token, string userId)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("CSRF token validation failed: token or userId is null or empty.");
                return false;
            }

            var cacheKey = $"csrf_token_{userId}"; // Create the cache key for the user

            if (_cache.TryGetValue(cacheKey, out string? cachedToken))
            {
                return cachedToken == token; // Compare the provided token with the cached token
            }

            _logger.LogWarning("CSRF token validation failed: token not found in cache for user {UserId}", userId);
            return false; // Token not found in cache, validation failed
        }

        // Invalidate a CSRF token for a user
        public void InvalidateToken(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                _logger.LogWarning("CSRF token invalidation failed: userId is null or empty.");
                return;
            }
            var cacheKey = $"csrf_token_{userId}"; // Create the cache key for the user
            _cache.Remove(cacheKey); // Remove the token from the cache
            _logger.LogInformation("Invalidated CSRF token for user {UserId}", userId);
        }
    }
}
