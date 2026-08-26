using System.Security.Claims;
using System.Text;
using LegacyAuthDemo.Authorization.Repositories;
using LegacyAuthDemo.Authorization.Sessions;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace LegacyAuthDemo.WebApi.Controllers;

/// <summary>
/// Mirrors AuthorizationController from the legacy WebApi5 host: the passthrough
/// endpoints where the legacy user model meets the OAuth2/OIDC protocol.
/// </summary>
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly LegacySignInManager _demoSignInManager;
    private readonly LegacyUserManager _demoUserManager;
    private readonly IAuthUserSession _authUserSession;
    private readonly IOptionsMonitor<OpenIddictServerOptions> _serverOptions;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        LegacySignInManager demoSignInManager,
        LegacyUserManager demoUserManager,
        IAuthUserSession authUserSession,
        IOptionsMonitor<OpenIddictServerOptions> serverOptions)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _demoSignInManager = demoSignInManager;
        _demoUserManager = demoUserManager;
        _authUserSession = authUserSession;
        _serverOptions = serverOptions;
    }

    // =====================================================================
    // AUTHORIZE - mirrors Authorize() with prompt=login / prompt=none handling.
    // =====================================================================
    [AllowAnonymous]
    [AcceptVerbs("GET", "POST", Route = "~/ap-auth-server/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var prompts = new HashSet<string>(
            (request.Prompt ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries),
            StringComparer.Ordinal);

        // prompt=login: force a fresh interactive login (legacy behaviour).
        if (prompts.Remove("login"))
        {
            var promptProperties = new AuthenticationProperties
            {
                RedirectUri = Request.Path + Request.QueryString
            };
            promptProperties.Items["prompt"] = prompts.Count switch
            {
                0 => null,
                1 => prompts.Single(),
                _ => string.Join(" ", prompts)
            };

            return Challenge(promptProperties, IdentityConstants.ApplicationScheme);
        }

        // Resolve the browser session via the identity cookie.
        // NOTE: the user-id claim is "sub" (remapped in LegacyOAuthOpenIdStartup), NOT
        // ClaimTypes.NameIdentifier - LegacyUserManager.GetUserAsync resolves by it below.
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded || result.Principal is null)
        {
            if (prompts.Contains("none"))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.LoginRequired,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The user is not logged in."
                    }));
            }

            return Challenge(new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                IdentityConstants.ApplicationScheme);
        }

        var user = await _demoUserManager.GetUserAsync(result.Principal);
        if (user is null)
        {
            return Challenge(new AuthenticationProperties { RedirectUri = Request.Path + Request.QueryString },
                IdentityConstants.ApplicationScheme);
        }

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!) ??
                          throw new InvalidOperationException($"Unknown application: {request.ClientId}");

        // Build the principal and SCOPE its claims down to what the client asked for.
        var principal = await _demoSignInManager.CreateUserPrincipalAsync(user);
        principal.SetScopes(request.GetScopes());
        principal.SetResources(await _scopeManager.ListResourcesAsync(request.GetScopes()).ToListAsync());

        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim, principal));
        }

        AugmentMissingClaims(principal, DateTimeOffset.UtcNow);

        var properties = new AuthenticationProperties
        {
            RedirectUri = request.RedirectUri
        };

        // Session id -> becomes the "session_state" claim via the custom server event.
        properties.Items[IAuthUserSession.SessionIdPropertyName] =
            await _authUserSession.CreateSessionIdAsync(principal, properties);

        return SignIn(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // =====================================================================
    // EXCHANGE - token endpoint. Handles password grant (legacy /api/user/authenticate
    // compatibility), authorization_code and refresh_token grants.
    // =====================================================================
    [AllowAnonymous]
    [HttpPost("~/ap-auth-server/connect/token"), HttpPost("~/api/user/authenticate")]
    [Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
                      throw new InvalidOperationException("The OpenID Connect token request cannot be retrieved.");

        if (request.IsPasswordGrantType())
        {
            return await GenerateTokensForPasswordGrantType(request);
        }

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            return await GenerateTokensForCodeOrRefreshGrantType(request);
        }

        return Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                    "The specified grant type is not supported."
            }));
    }

    /// <summary>
    /// Mirrors GenerateTokensForPasswordGrantType: validate credentials against the
    /// LEGACY store, then mint a MINIMAL principal - only sub/demo_clientId/demo_siteId/
    /// demo_schema ride inside the token ("not secure to add more" - legacy comment).
    /// </summary>
    private async Task<IActionResult> GenerateTokensForPasswordGrantType(OpenIddictRequest request)
    {
        var user = await _demoUserManager.FindUserEntityByNameAsync(request.Username!);
        if (user is null)
        {
            return ForbidError(LegacyAuthConstants.Errors.ErrorLoginBadUserDetails,
                "The username/password couple is invalid.");
        }

        if (!await _demoUserManager.CheckPasswordAsync(user, request.Password!))
        {
            if (await _demoUserManager.IsLockedOutAsync(user))
            {
                await _demoUserManager.AccessFailedAsync(user);
                return ForbidError(LegacyAuthConstants.Errors.ErrorLoginAccountLocked,
                    "The account is temporarily locked.");
            }
            return ForbidError(LegacyAuthConstants.Errors.ErrorLoginBadUserDetails,
                "The username/password couple is invalid.");
        }

        await _demoUserManager.ResetAccessFailedCountAsync(user);

        var identity = new ClaimsIdentity(
            authenticationType: "DemoPasswordGrant",
            nameType: "name",
            roleType: Claims.Role);

        // MINIMAL claims only - everything else stays server-side by design.
        identity.AddClaim(new Claim(Claims.Subject, user.UserId.ToString())
            .SetDestinations(Destinations.AccessToken));
        identity.AddClaim(new Claim(LegacyAuthConstants.Claims.DemoClientId, request.ClientId!)
            .SetDestinations(Destinations.AccessToken));
        identity.AddClaim(new Claim(LegacyAuthConstants.Claims.DemoSiteId, user.SiteId.ToString())
            .SetDestinations(Destinations.AccessToken));
        identity.AddClaim(new Claim(LegacyAuthConstants.Claims.Schema, OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .SetDestinations(Destinations.AccessToken));

        var principal = new ClaimsPrincipal(identity);

        // Keep warm so the first validation event does not need repopulation.
        LegacyAuthDemo.Domain.Caching.ApplicationCaches.SetUserContext(
            new LegacyAuthDemo.Domain.Authentication.UserContext(user));

        principal.SetScopes(Scopes.OfflineAccess);

        principal.SetResources(LegacyAuthConstants.Applications.SpaFrontEnd);

        var properties = new AuthenticationProperties();
        properties.Items["userId"] = user.UserId.ToString();

        return SignIn(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Mirrors the code/refresh branch of Exchange(): re-resolve the legacy user,
    /// re-check they can still sign in, refresh the minimal claims, re-cache the
    /// UserContext (so permission changes flow through immediately).
    /// </summary>
    private async Task<IActionResult> GenerateTokensForCodeOrRefreshGrantType(OpenIddictRequest request)
    {
        var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        var user = await _demoUserManager.GetUserAsync(result.Principal!);
        if (user is null || user.UserId <= 0)
        {
            return ForbidError(LegacyAuthConstants.Errors.ErrorInvalidToken,
                "The token is no longer valid.");
        }

        if (!await _demoSignInManager.CanSignInAsync(user))
        {
            return ForbidError(LegacyAuthConstants.Errors.ErrorLoginNoLongerAllowed,
                "The user is no longer allowed to sign in.");
        }

        var identity = result.Principal!.Identities.First();

        EnsureClaim(identity, Claims.Subject, user.UserId.ToString(), Destinations.AccessToken, Destinations.IdentityToken);
        EnsureClaim(identity, "name", user.UserName, Destinations.AccessToken, Destinations.IdentityToken);
        EnsureClaim(identity, LegacyAuthConstants.Claims.DemoClientId, result.Principal.FindFirstValue(LegacyAuthConstants.Claims.DemoClientId) ?? request.ClientId!, Destinations.AccessToken);
        EnsureClaim(identity, LegacyAuthConstants.Claims.DemoSiteId, user.SiteId.ToString(), Destinations.AccessToken);
        EnsureClaim(identity, LegacyAuthConstants.Claims.Schema, OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme, Destinations.AccessToken);

        // Re-hydrate permissions into cache so the validation event sees fresh data.
        LegacyAuthDemo.Domain.Caching.ApplicationCaches.SetUserContext(
            new LegacyAuthDemo.Domain.Authentication.UserContext(user));

        var principal = result.Principal;
        var properties = new AuthenticationProperties(result.Properties?.Items.ToDictionary(i => i.Key, i => i.Value) ?? []);
        properties.Items["userId"] = user.UserId.ToString();

        return SignIn(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // =====================================================================
    // LOGOUT - mirrors Logout GET/POST: clears caches via the legacy sign-in manager's SignOutAsync.
    // =====================================================================
    [AllowAnonymous]
    [AcceptVerbs("GET", "POST", Route = "~/ap-auth-server/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await _demoSignInManager.SignOutAsync();

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" });
    }

    // =====================================================================
    // USERINFO - serves the userinfo endpoint from the hydrated principal.
    // =====================================================================
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [AcceptVerbs("GET", "POST", Route = "~/ap-auth-server/connect/userinfo")]
    [Produces("application/json")]
    public IActionResult Userinfo()
    {
        // Password-grant tokens deliberately carry no name/email (minimal-claims
        // methodology), so serve profile data from the cache like the legacy
        // UserInfoController does.
        var cachedUser = int.TryParse(User.FindFirstValue(Claims.Subject), out var uid)
            ? ApplicationCaches.GetAuthUser(uid)
            : null;

        var permissions = User.FindAll(LegacyAuthConstants.ClaimTypes.Permissions).Select(c => c.Value).ToList();

        return Ok(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [Claims.Subject] = User.FindFirstValue(Claims.Subject),
            ["name"] = User.FindFirstValue("name") ?? cachedUser?.UserName,
            ["email"] = User.FindFirstValue(Claims.Email) ?? cachedUser?.Email,
            [LegacyAuthConstants.ClaimTypes.Permissions] = permissions
        });
    }

    // =====================================================================
    // PAT - Personal Access Token generation (mirrors GeneratePatToken).
    // Hand-builds a JWT with the server's own signing credentials; the validation
    // event maps its scopes to permissions without touching the user caches.
    // =====================================================================
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    [HttpPost("~/ap-auth-server/connect/getPatToken")]
    [Consumes("application/json"), Produces("application/json")]
    public IActionResult GeneratePatToken([FromBody] PatRequest patRequest)
    {
        var sUserId = User.FindFirstValue(Claims.Subject);
        if (string.IsNullOrEmpty(sUserId))
        {
            return Unauthorized();
        }

        var options = _serverOptions.CurrentValue;
        var signingCredentials = options.SigningCredentials.FirstOrDefault();
        if (signingCredentials is null)
        {
            return StatusCode(500, new { error = "no signing credentials configured" });
        }

        // NOTE: the legacy version additionally stores an OpenIddictTokenDescriptor
        // row (ReferenceId) so issued PATs can be revoked; trimmed for demo brevity.
        // The validation event maps the scope claim to demo_permissions claims
        // (api.X -> route.X) WITHOUT consulting the user's cached permission set,
        // so a scoped PAT can never inherit its owner's full powers.
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer?.AbsoluteUri,
            Audience = options.Issuer?.AbsoluteUri,
            SigningCredentials = signingCredentials,
            TokenType = JsonWebTokenTypes.AccessToken,
            Expires = DateTime.UtcNow.AddYears(1),
            NotBefore = DateTime.UtcNow,
            Claims = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [Claims.Subject] = sUserId,
                [LegacyAuthConstants.Claims.DemoTokenType] =
                    LegacyAuthConstants.AuthenticationTokenTypes.DemoPersonalAccessToken,
                [Claims.Scope] = patRequest.Scopes is null
                    ? string.Empty
                    : string.Join(' ', patRequest.Scopes),
                [LegacyAuthConstants.Claims.DemoClientId] = patRequest.PartnerName ?? "unknown-partner"
            }
        };

        if (!options.DisableAccessTokenEncryption && options.EncryptionCredentials.Count > 0)
        {
            descriptor.EncryptingCredentials = options.EncryptionCredentials.First();
        }

        var token = options.JsonWebTokenHandler.CreateToken(descriptor);

        return Ok(new { access_token = token, token_type = "Bearer", expires_in = (long)TimeSpan.FromDays(365).TotalSeconds });
    }

    // =====================================================================
    // Session check iframe (check_session_iframe metadata target).
    // =====================================================================
    [AllowAnonymous]
    [HttpGet("~/ap-auth-server/session-check")]
    public ContentResult SessionCheck()
    {
        var sessionId = _authUserSession.GetCurrentSessionId();
        var html = """
            <!DOCTYPE html><html><body><script>
            window.addEventListener('message', function(e) {
                if (e.data === 'ap-check-session') {
                    e.source.postMessage('%SESSION_ID%', e.origin);
                }
            }, false);
            setInterval(function() { parent.postMessage('ap-session-check-ready', '*'); }, 2000);
            </script></body></html>
            """.Replace("%SESSION_ID%", sessionId ?? string.Empty, StringComparison.Ordinal);

        return Content(html, "text/html", Encoding.UTF8);
    }

    // ---- helpers ----

    private IActionResult ForbidError(string errorCode, string errorDescription) =>
        Forbid(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = errorDescription
            }));

    private static void EnsureClaim(ClaimsIdentity identity, string type, string value, params string[] destinations)
    {
        if (identity.HasClaim(c => c.Type == type)) return;
        var claim = new Claim(type, value);
        claim.SetDestinations(destinations);
        identity.AddClaim(claim);
    }

    /// <summary>Mirrors AugmentMissingClaims: IdentityServer-style amr/idp/auth_time backfill.</summary>
    private void AugmentMissingClaims(ClaimsPrincipal principal, DateTimeOffset utcNow)
    {
        var identity = principal.Identities.First();

        if (!principal.HasClaim(c => c.Type is ClaimTypes.AuthenticationMethod or "amr"))
        {
            // Local cookie/password logins are "pwd"; only external SSO providers
            // would report a different authentication method (mirrors legacy).
            var amr = identity.AuthenticationType is "DemoExternalSSO" ? "external" : "pwd";
            EnsureClaim(identity, "amr", amr, Destinations.IdentityToken);
            EnsureClaim(identity, "idp", "local", Destinations.IdentityToken);
        }

        if (!principal.HasClaim(c => c.Type is "auth_time" or ClaimTypes.AuthenticationInstant))
        {
            // NOTE: OpenIddict 7.x validates claim VALUE TYPES - auth_time must be a
            // numeric-valued claim (ClaimValueTypes.Integer), not a plain string.
            identity.AddClaim(new Claim(
                "auth_time",
                utcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer)
            {
                Properties = { [OpenIddictConstants.Properties.Destinations] =
                    "[\""+OpenIddictConstants.Destinations.IdentityToken+"\"]" }
            });
        }
    }

    /// <summary>
    /// Mirrors GetDestinations: decide which tokens each claim may be embedded in.
    /// NOTE: demo_permissions are deliberately NOT given any destination - permissions
    /// never leave the server; they are re-hydrated after validation.
    /// </summary>
    private static IEnumerable<string> GetDestinations(Claim claim, ClaimsPrincipal principal)
    {
        return claim.Type switch
        {
            // Identity-only claims:
            Claims.Name or Claims.Email or Claims.Role when
                principal.HasScope(Scopes.Profile) || principal.HasScope(Scopes.Email) || principal.HasScope(Scopes.Roles) =>
                [Destinations.AccessToken, Destinations.IdentityToken],

            // Never leak these:
            "security_stamp" or LegacyAuthConstants.ClaimTypes.Permissions => [],

            _ => [Destinations.AccessToken]
        };
    }
}

public record PatRequest(string PartnerName, List<string> Scopes);
