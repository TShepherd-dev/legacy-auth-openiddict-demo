using System.Security.Claims;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace LegacyAuthDemo.Authorization.Repositories;

/// <summary>
/// Mirrors the legacy user manager: UserManager subclass adding legacy-aware helpers -
/// system-context lookups (used before a user is authenticated), principal-to-user
/// resolution via the ap_* claims, and cache eviction.
/// </summary>
public class LegacyUserManager : UserManager<LegacyUserIdentity>
{
    public LegacyUserManager(
        IUserStore<LegacyUserIdentity> store,
        Microsoft.Extensions.Options.IOptions<IdentityOptions> optionsAccessor,
        IPasswordHasher<LegacyUserIdentity> passwordHasher,
        IEnumerable<IUserValidator<LegacyUserIdentity>> userValidators,
        IEnumerable<IPasswordValidator<LegacyUserIdentity>> passwordValidators,
        ILookupNormalizer keyNormalizer,
        IdentityErrorDescriber errors,
        IServiceProvider services,
        ILogger<UserManager<LegacyUserIdentity>> logger)
        : base(store, optionsAccessor, passwordHasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger)
    {
    }

    /// <summary>
    /// Mirrors FindUserEntityByNameAsync(userName, systemUserContext): looks the user
    /// up in the legacy tables with a SYSTEM context, i.e. before any authentication
    /// exists (e.g. during the password grant).
    /// </summary>
    public async Task<LegacyUserIdentity?> FindUserEntityByNameAsync(string userName)
    {
        var user = await FindByNameAsync(userName);
        if (user is null || user.DeletionStatus != 0) return null;
        return user;
    }

    /// <summary>Resolves the legacy user from a token/cookie principal via its sub claim.</summary>
    public override async Task<LegacyUserIdentity?> GetUserAsync(ClaimsPrincipal principal)
    {
        if (principal is null) return null;

        var sub = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? principal.FindFirstValue("sub");
        if (sub is null || !int.TryParse(sub, out var userId)) return null;

        return await FindByIdAsync(userId.ToString());
    }

    /// <summary>Mirrors ClearDemoUserCaches: forces permission re-hydration from source on next request.</summary>
    public void ClearDemoUserCaches(int userId) => ApplicationCaches.ClearUserCaches(userId);
}
