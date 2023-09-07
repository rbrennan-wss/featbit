using Application.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.Net;
using System.Threading.Tasks;

namespace Api.Middlewares
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class VerifyAccountCreation
    {
        private readonly RequestDelegate _next;

        public VerifyAccountCreation(RequestDelegate next)
        {
            _next = next;
        }

        public Task Invoke(HttpContext httpContext, IIdentityService identityService, IConfiguration configuration)
        {
            if (Convert.ToBoolean(configuration["ExternalAuth:Enabled"])
                && !string.IsNullOrEmpty(httpContext.Request.Headers[HeaderNames.Authorization]))
            {
                // TODO: Update claim to correct value
                //httpContext.User.Claims.FirstOrDefault(c => c.Type.Contains("emailaddress")).Value
                identityService.RegisterUserIfDoesNotExist(httpContext.User.Claims.FirstOrDefault(c => c.Type.Contains("emailaddress"))?.Value);
            }

            return _next(httpContext);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class VerifyAccountCreationExtensions
    {
        public static IApplicationBuilder UseVerifyAccountCreation(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<VerifyAccountCreation>();
        }
    }
}