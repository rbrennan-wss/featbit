using Domain.Identity;
using Domain.Users;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Application.Users;

public class CurrentUser : ICurrentUser
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptionsMonitor<ExternalAuthOptions> _externalAuthOptions;

    public CurrentUser(IHttpContextAccessor httpContextAccessor)
    {
        //_httpContextAccessor = httpContextAccessor;
        new CurrentUser(httpContextAccessor, null);
    }

    public CurrentUser(IHttpContextAccessor httpContextAccessor, IOptionsMonitor<ExternalAuthOptions> extAuth)
    {
        _externalAuthOptions = extAuth;
        _httpContextAccessor = httpContextAccessor;
    }

    public Guid Id
    {
        get
        {
            System.Security.Claims.Claim claim = null;
            if (_externalAuthOptions.CurrentValue.Enabled)
            {
                claim = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == UserClaims.ExternalId);
            }
            else
            {
                claim = _httpContextAccessor.HttpContext?.User.Claims.FirstOrDefault(x => x.Type == UserClaims.Id);
            }

            return claim == null ? Guid.Empty : Guid.Parse(claim.Value);
        }
    }
}