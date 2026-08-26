using System.Security.Claims;
using System.Threading;
using LegacyAuthDemo.Authorization.Repositories;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace LegacyAuthDemo.Authorization.Authorization;

/// <summary>
/// Mirrors the legacy OpenIddict validation handler - THE key customisation in the whole design.
///
/// Tokens deliberately carry only identifiers (sub / demo_clientId / demo_siteId).
/// This handler runs AFTER OpenIddict has validated the access token
/// (order = ValidateAccessToken + 1) and re-hydrates the caller's FULL permission
/// set from the legacy caches onto the request principal:
///
///     thisPrincipal.AddIdentity(new ClaimsIdentity(requestUser.PermissionClaimList));
///
/// Because permissions are re-read from the server-side cache on every request,
/// revoking a permission takes effect immediately - no waiting for token expiry,
/// nothing sensitive stored inside the token itself.
/// </summary>
public class LegacyOpenIdDictEventHandler :
    IOpenIddictValidationHandler<OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext>
{
    /// <summary>Guards cache repopulation so a burst of requests triggers one DB read (legacy mutex pattern).</summary>
    private static readonly Mutex CacheMutex = new(false, @"LegacyAuthDemo\UserCacheMutex");

    /// <summary>HttpContext.Items key for the RouteAudit-equivalent per-request context.</summary>
    public const string RequestUserContextKey = "demo_request_user_context";

    private readonly LegacyUserManager _demoUserManager;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<LegacyOpenIdDictEventHandler> _logger;

    public LegacyOpenIdDictEventHandler(
        LegacyUserManager demoUserManager,
        IHttpContextAccessor httpContextAccessor,
        ILogger<LegacyOpenIdDictEventHandler> logger)
    {
        _demoUserManager = demoUserManager;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    public ValueTask HandleAsync(OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        AddDemoPermissionsToRequestIdentity(context);
        return ValueTask.CompletedTask;
    }

    public void AddDemoPermissionsToRequestIdentity(OpenIddict.Validation.OpenIddictValidationEvents.ProcessAuthenticationContext context)
    {
        var httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            context.Reject("DemoPermissionAdd.NoHttpRequest", "No HttpContext available.");
            return;
        }

        if (context.AccessTokenPrincipal?.Identity is not ClaimsIdentity accessTokenIdentity ||
            !accessTokenIdentity.IsAuthenticated)
        {
            context.Reject("DemoPermissionAdd.NoClaims", "Access token principal has no usable claims identity.");
            return;
        }

        // ---- 1. Resolve the legacy user id from the minimal token claims ----
        var sUserId =
            accessTokenIdentity.FindFirst(Claims.Subject)?.Value ??
            accessTokenIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(sUserId) || !int.TryParse(sUserId, out var userId))
        {
            context.Reject("DemoPermissionAdd.NoUserId", "Token carries no resolvable user id.");
            return;
        }

        List<Claim> permissionClaims;

        // ---- 2a. Personal Access Token: map scopes to permissions, REQUEST-LIFETIME ONLY ----
        if (string.Equals(
                accessTokenIdentity.FindFirst(LegacyAuthConstants.Claims.DemoTokenType)?.Value,
                LegacyAuthConstants.AuthenticationTokenTypes.DemoPersonalAccessToken,
                StringComparison.OrdinalIgnoreCase))
        {
            permissionClaims = BuildPermissionClaimsFromScopes(accessTokenIdentity);
            _logger.LogInformation(
                "LegacyOpenIdDictEventHandler.AddDemoPermissionsToRequestIdentity: PAT {UserId} -> {Count} scoped permissions.",
                sUserId, permissionClaims.Count);
        }
        else
        {
            // ---- 2b. Normal user token: hydrate from caches, repopulating on miss ----
            var requestUser = ApplicationCaches.GetUserContext(userId);

            if (requestUser is null || requestUser.PermissionClaimList.Count == 0)
            {
                requestUser = RepopulateWithLock(sUserId, userId);
            }

            if (requestUser is null)
            {
                context.Reject("DemoPermissionAdd.UserNotFound", $"User {sUserId} could not be loaded.");
                return;
            }

            permissionClaims = requestUser.PermissionClaimList;
        }

        // ---- 3. THE money line: inject the permission claims onto the principal ----
        var newAppIdentity = new ClaimsIdentity(permissionClaims);
        context.AccessTokenPrincipal.AddIdentity(newAppIdentity);

        // ---- 4. Stash the hydrated context on the request (RouteAudit equivalent) ----
        httpContext.Items[RequestUserContextKey] =
            ApplicationCaches.GetUserContext(userId) ?? new UserContext();
    }

    /// <summary>
    /// Mirrors the legacy mutex-guarded repopulation: only ONE thread hits the
    /// "database" on a cold cache; everyone else re-checks after acquiring the lock.
    /// </summary>
    private UserContext? RepopulateWithLock(string sUserId, int userId)
    {
        CacheMutex.WaitOne();
        try
        {
            // Double-check: another thread may have repopulated while we waited.
            var cached = ApplicationCaches.GetUserContext(userId);
            if (cached is not null) return cached;

            // Sync-over-async mirrors the legacy call pattern into the UserManager,
            // which reads through the custom store -> DAL and refills both caches.
            var user = _demoUserManager.FindByIdAsync(sUserId).GetAwaiter().GetResult();

            if (user is null)
            {
                _logger.LogWarning(
                    "LegacyOpenIdDictEventHandler.AddDemoPermissionsToRequestIdentity: user {UserId} not found during repopulation.", sUserId);
                return null;
            }

            return ApplicationCaches.GetUserContext(userId);
        }
        finally
        {
            CacheMutex.ReleaseMutex();
        }
    }

    /// <summary>
    /// PAT support: third parties get tokens whose SCOPES map onto route permissions
    /// ("api.dataimport.user" style scopes become "route.dataimport.user" claims),
    /// WITHOUT granting the full user permission set. Deliberately NOT written back
    /// to the shared caches - these permissions live for this request only.
    /// </summary>
    private static List<Claim> BuildPermissionClaimsFromScopes(ClaimsIdentity tokenIdentity)
    {
        return tokenIdentity
            .FindAll(Claims.Scope)
            .SelectMany(scopeClaim => scopeClaim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Select(MapScopeToPermission)
            .Where(permission => !string.IsNullOrEmpty(permission))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(permission => new Claim(LegacyAuthConstants.ClaimTypes.Permissions, permission!))
            .ToList();
    }

    private static string? MapScopeToPermission(string scope)
    {
        // Convention from the legacy codebase: api.* scopes map to route.* permissions.
        if (scope.StartsWith("route.", StringComparison.OrdinalIgnoreCase)) return scope;
        if (scope.StartsWith("api.", StringComparison.OrdinalIgnoreCase)) return $"route.{scope[4..]}";
        return null;
    }
}
