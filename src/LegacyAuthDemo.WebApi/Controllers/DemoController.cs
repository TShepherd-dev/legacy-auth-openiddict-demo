using System.Text.Json.Serialization;
using LegacyAuthDemo.Authorization.Authorization;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Validation.AspNetCore;

namespace LegacyAuthDemo.WebApi.Controllers;

/// <summary>
/// The protected demo API: every route is gated by a legacy PERMISSION_ policy
/// resolved dynamically against the ap_permissions claims that the OpenIddict
/// validation event hydrated onto the principal. No ASP.NET roles anywhere.
/// </summary>
[ApiController]
[Route("api/demo")]
public class DemoController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public() => Ok(new
    {
        message = "Anonymous endpoint - no token needed.",
        serverTimeUtc = DateTime.UtcNow
    });

    /// <summary>Requires the legacy permission "route.demo.view".</summary>
    [HttpGet("view-data")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
               Policy = ApPolicies.CanViewDemo)]
    public IActionResult ViewData()
    {
        var ctx = GetRequestUserContext();

        return Ok(new
        {
            message = "route.demo.view satisfied - permission was re-hydrated from the server-side cache after token validation.",
            user = new { ctx?.UserId, ctx?.UserName, ctx?.DisplayName },
            data = new[] { "record-1", "record-2", "record-3" }
        });
    }

    /// <summary>Requires the legacy permission "route.demo.manage" (bob gets 403 here).</summary>
    [HttpPost("manage-data")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme,
               Policy = ApPolicies.CanManageDemo)]
    public IActionResult ManageData([FromBody] ManageRequest request)
    {
        var ctx = GetRequestUserContext();

        return Accepted(new
        {
            message = "route.demo.manage satisfied.",
            performedBy = new { ctx?.UserId, ctx?.UserName },
            request.Action
        });
    }

    /// <summary>
    /// Shows the final principal: identifiers from the token + permissions injected
    /// by the validation event handler (they were never in the token itself).
    /// </summary>
    [HttpGet("me")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public IActionResult Me()
    {
        var identities = User.Identities.Select(i => new
        {
            i.AuthenticationType,
            Claims = i.Claims.GroupBy(c => c.Type).ToDictionary(
                g => g.Key,
                g => g.Select(c => c.Value).ToArray())
        });

        return Ok(new
        {
            note = "'ap_permissions' claims come from the cache via LegacyOpenIdDictEventHandler, not from the token.",
            identities
        });
    }

    private UserContext? GetRequestUserContext() =>
        HttpContext.Items.TryGetValue(LegacyOpenIdDictEventHandler.RequestUserContextKey, out var value)
            ? value as UserContext
            : ApplicationCaches.GetUserContext(int.TryParse(User.FindFirst("sub")?.Value, out var id) ? id : 0);
}

public record ManageRequest(string Action);
