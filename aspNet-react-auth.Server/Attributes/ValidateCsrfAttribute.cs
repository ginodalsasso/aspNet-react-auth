using aspNet_react_auth.Server.Models;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace aspNet_react_auth.Server.Attributes
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
    public class ValidateCsrfAttribute : Attribute, IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            // Get services from the request context
            var csrfService = context.HttpContext.RequestServices.GetRequiredService<ICsrfService>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<ValidateCsrfAttribute>>();

            var userId = GetUserIdFromContext(context);
            if (string.IsNullOrEmpty(userId))
            {
                logger.LogWarning("CSRF validation failed: userId is null or empty.");
                context.Result = new ObjectResult(new
                {
                    error = "UNAUTHORIZED",
                    message = "UserId is null or empty."
                })
                {
                    StatusCode = StatusCodes.Status403Forbidden
                };
                return;
            }

            var csrfToken = GetCsrfTokenFromRequest(context);
            if (string.IsNullOrEmpty(csrfToken))
            {
                logger.LogWarning("CSRF validation failed: CSRF token is null or empty.");
                context.Result = new ObjectResult(new
                {
                    error = "CSRF_TOKEN_MISSING",
                    message = "CSRF token is null or empty."
                })
                {
                    StatusCode = StatusCodes.Status403Forbidden
                };
                return;
            }

            if (!csrfService.ValidateToken(csrfToken, userId))
            {
                logger.LogWarning("CSRF validation failed: Invalid CSRF token for user {UserId}.", userId);
                context.Result = new ObjectResult(new
                {
                    error = "CSRF_TOKEN_INVALID",
                    message = "Invalid CSRF token."
                })
                {
                    StatusCode = StatusCodes.Status403Forbidden
                };
                return;
            }

            logger.LogDebug($"Validate CSRF TOKEN for {userId}");
            await next(); // Proceed to the next action after the attribute call in the controller if validation is successful
        }

        private string? GetUserIdFromContext(ActionExecutingContext context)
        {
            var user = context.HttpContext.User; // Get the user from the HttpContext

            // Check if the user is authenticated and has a userId claim
            return user?.FindFirst("userId")?.Value;

        }

        private string? GetCsrfTokenFromRequest(ActionExecutingContext context)
        {
            var request = context.HttpContext.Request;

            if (request.Headers.TryGetValue("X-XSRF-Token", out var headerToken))
            {
                return headerToken.FirstOrDefault();
            }

            return null;
        }
    }
}

