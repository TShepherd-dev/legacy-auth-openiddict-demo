using LegacyAuthDemo.Domain.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace LegacyAuthDemo.Authorization.Authorization;

/// <summary>
/// Mirrors the legacy route-permission requirement: BOTH the requirement and its own
/// handler in one class. The legacy system has no ASP.NET "policies" - it has
/// named permissions on resources - so this class evaluates the caller's
/// ap_permissions claims (hydrated by LegacyOpenIdDictEventHandler) directly.
/// </summary>
public class LegacyRoutePermissionRequirement :
    AuthorizationHandler<LegacyRoutePermissionRequirement>,
    IAuthorizationRequirement
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    public string Permission { get; }

    public LegacyRoutePermissionRequirement(IHttpContextAccessor httpContextAccessor, string permission)
    {
        _httpContextAccessor = httpContextAccessor;
        Permission = permission;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, LegacyRoutePermissionRequirement requirement)
    {
        // Self-handling requirement: evaluate immediately against HttpContext.
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Fail();
            return;
        }

        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            SetRouteStatus(httpContext, "NotAuthorized");
            context.Fail();
            return;
        }

        // If the OpenIddict validation event attached ap_permissions claims to
        // this principal, they are AUTHORITATIVE: normal tokens carry the
        // user's full set, while PATs carry only their scope-mapped subset.
        // Never widen them from the shared caches - that would let a scoped
        // PAT silently inherit its owner's complete permission set.
        var hydratedPermissions = context.User
            .FindAll(LegacyAuthConstants.ClaimTypes.Permissions)
            .Select(c => c.Value)
            .ToList();

        if (hydratedPermissions.Count > 0)
        {
            if (hydratedPermissions.Contains(requirement.Permission))
            {
                context.Succeed(requirement);
                return;
            }

            SetRouteStatus(httpContext, "NotAllowed");
            context.Fail();
            return;
        }

        // Fallback for routes authenticated WITHOUT an access token (e.g.
        // cookie-authenticated admin pages): use the request-stashed
        // UserContext, or rehydrate it from the shared cache by sub claim.
        var requestUser = httpContext.Items[LegacyOpenIdDictEventHandler.RequestUserContextKey] as UserContext
                          ?? await RehydrateFromCacheAsync(context);

        if (requestUser is not null && requestUser.HasPermission(requirement.Permission))
        {
            httpContext.Items[LegacyOpenIdDictEventHandler.RequestUserContextKey] = requestUser;
            context.Succeed(requirement);
            return;
        }

        SetRouteStatus(httpContext, requestUser is null ? "Failed" : "NotAllowed");
        context.Fail();
    }

    /// <summary>
    /// Fallback for routes that were not authenticated via an OpenIddict access token
    /// (e.g. cookie-authenticated admin pages): rehydrate from the shared cache by sub claim.
    /// </summary>
    private Task<UserContext?> RehydrateFromCacheAsync(AuthorizationHandlerContext context)
    {
        var sUserId = context.User.FindFirst("sub")?.Value
                      ?? context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

        return Task.FromResult(int.TryParse(sUserId, out var userId)
            ? Domain.Caching.ApplicationCaches.GetUserContext(userId)
            : null);
    }

    private static void SetRouteStatus(HttpContext httpContext, string status) =>
        httpContext.Items["ap_route_status"] = status;
}
