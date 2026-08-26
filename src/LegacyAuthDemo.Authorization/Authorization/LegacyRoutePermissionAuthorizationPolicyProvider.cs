using LegacyAuthDemo.Domain.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

namespace LegacyAuthDemo.Authorization.Authorization;

/// <summary>
/// Mirrors the legacy route-permission policy provider: a dynamic policy
/// provider. Any policy named "PERMISSION_xxx" is resolved AT REQUEST TIME into an
/// authorization policy that checks the legacy permission "xxx" - no policy
/// registration at startup, no ASP.NET roles. Unknown names fall back to the default provider.
/// </summary>
public class LegacyRoutePermissionAuthorizationPolicyProvider : DefaultAuthorizationPolicyProvider
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public LegacyRoutePermissionAuthorizationPolicyProvider(
        IOptions<AuthorizationOptions> options,
        IHttpContextAccessor httpContextAccessor)
        : base(options)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public override Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(LegacyAuthConstants.PolicyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var apPermission = policyName[LegacyAuthConstants.PolicyPrefix.Length..];

            AuthorizationPolicy policy = new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .AddRequirements(new LegacyRoutePermissionRequirement(_httpContextAccessor, apPermission))
                .Build();

            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        return base.GetPolicyAsync(policyName);
    }
}

/// <summary>Named policies used by controllers, mirroring the legacy ApPolicies constants.</summary>
public static class ApPolicies
{
    public const string CanViewDemo = LegacyAuthConstants.PolicyPrefix + "route.demo.view";
    public const string CanManageDemo = LegacyAuthConstants.PolicyPrefix + "route.demo.manage";
    public const string CanManageUsers = LegacyAuthConstants.PolicyPrefix + "route.users.manage";
}
