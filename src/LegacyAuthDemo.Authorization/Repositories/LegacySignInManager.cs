using System.Security.Claims;
using LegacyAuthDemo.Authorization.Sessions;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LegacyAuthDemo.Authorization.Repositories;

/// <summary>
/// Mirrors the legacy sign-in manager: SignInManager whose SignOutAsync ALSO clears the
/// legacy user caches and the AP session cookie, so a logout truly forgets the
/// hydrated permission state.
/// </summary>
public class LegacySignInManager : SignInManager<LegacyUserIdentity>
{
    private readonly LegacyUserManager _apUserManager;

    public LegacySignInManager(
        UserManager<LegacyUserIdentity> userManager,
        IHttpContextAccessor contextAccessor,
        IUserClaimsPrincipalFactory<LegacyUserIdentity> claimsFactory,
        IOptions<IdentityOptions> optionsAccessor,
        ILogger<SignInManager<LegacyUserIdentity>> logger,
        IAuthenticationSchemeProvider schemes,
        IUserConfirmation<LegacyUserIdentity> confirmation)
        : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
    {
        _apUserManager = (userManager as LegacyUserManager)!;
    }

    /// <summary>
    /// Mirrors the legacy override: evict caches by sub claim, drop the session
    /// cookie ("AP.IdSession" in the legacy codebase), then let Identity sign out.
    /// </summary>
    public override async Task SignOutAsync()
    {
        var result = await Context.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (result.Succeeded &&
            int.TryParse(result.Principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            _apUserManager.ClearApUserCaches(userId);
        }

        Context.Response.Cookies.Delete(IAuthUserSession.SessionCookieName);

        await base.SignOutAsync();
    }
}
