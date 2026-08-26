using System.Security.Claims;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;
using LegacyAuthDemo.Domain.Legacy;
using Microsoft.AspNetCore.Identity;

namespace LegacyAuthDemo.Authorization.Stores;

/// <summary>
/// Mirrors the legacy user store (1600+ lines there, compact here).
///
/// This is the BRIDGE: ASP.NET Identity thinks it is talking to an identity store,
/// but every call is translated into the legacy DAL. On every read the store also
/// loads the user's permission claims from the legacy permission tables and
/// populates the static caches - so downstream (validation events, authorization)
/// never needs to hit the database again.
/// </summary>
public class LegacyUserStore :
    IUserStore<LegacyUserIdentity>,
    IUserPasswordStore<LegacyUserIdentity>,
    IUserEmailStore<LegacyUserIdentity>,
    IUserSecurityStampStore<LegacyUserIdentity>,
    IUserLockoutStore<LegacyUserIdentity>,
    IUserClaimStore<LegacyUserIdentity>
{
    private readonly LegacyUserDal _dal;

    public LegacyUserStore(LegacyUserDal dal) => _dal = dal;

    // ---- IUserStore ----

    public void Dispose() { }

    public Task<string> GetUserIdAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.UserId.ToString());

    public Task<string?> GetUserNameAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(user.UserName);

    public Task SetUserNameAsync(LegacyUserIdentity user, string? userName, CancellationToken cancellationToken)
    {
        user.UserName = userName ?? throw new ArgumentNullException(nameof(userName));
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedUserNameAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.NormalizedUserName);

    public Task SetNormalizedUserNameAsync(LegacyUserIdentity user, string? normalizedName, CancellationToken cancellationToken)
    {
        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public Task<IdentityResult> CreateAsync(LegacyUserIdentity user, CancellationToken cancellationToken)
    {
        _dal.Save(user);
        RepopulateCaches(user);
        return Task.FromResult(IdentityResult.Success);
    }

    /// <summary>Mirrors the legacy Update: persist to DAL then re-cache both caches.</summary>
    public Task<IdentityResult> UpdateAsync(LegacyUserIdentity user, CancellationToken cancellationToken)
    {
        _dal.Save(user);
        RepopulateCaches(user);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(LegacyUserIdentity user, CancellationToken cancellationToken)
    {
        ApplicationCaches.ClearUserCaches(user.UserId);
        return Task.FromResult(IdentityResult.Success);
    }

    /// <summary>
    /// Legacy lookups flow through here: DAL read + permission hydration + cache population,
    /// exactly like the legacy user manager's FindByIdAsync repopulating the legacy caches.
    /// </summary>
    public Task<LegacyUserIdentity?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        if (!int.TryParse(userId, out var id)) return Task.FromResult<LegacyUserIdentity?>(null);

        var cached = ApplicationCaches.GetAuthUser(id);
        if (cached is not null) return Task.FromResult<LegacyUserIdentity?>(cached);

        var user = _dal.FindById(id);
        if (user is null) return Task.FromResult<LegacyUserIdentity?>(null);

        RepopulateCaches(user);
        return Task.FromResult<LegacyUserIdentity?>(user);
    }

    public Task<LegacyUserIdentity?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        var user = _dal.FindByName(normalizedUserName);
        if (user is null) return Task.FromResult<LegacyUserIdentity?>(null);

        RepopulateCaches(user);
        return Task.FromResult<LegacyUserIdentity?>(user);
    }

    // ---- IUserPasswordStore ----

    public Task SetPasswordHashAsync(LegacyUserIdentity user, string? passwordHash, CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.PasswordHash);

    public Task<bool> HasPasswordAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.PasswordHash is not null);

    // ---- IUserEmailStore ----

    public Task SetEmailAsync(LegacyUserIdentity user, string? email, CancellationToken cancellationToken)
    {
        user.Email = email;
        return Task.CompletedTask;
    }

    public Task<string?> GetEmailAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.Email);

    public Task<bool> GetEmailConfirmedAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.EmailConfirmed);

    public Task SetEmailConfirmedAsync(LegacyUserIdentity user, bool confirmed, CancellationToken cancellationToken)
    {
        user.EmailConfirmed = confirmed;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedEmailAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.Email?.ToUpperInvariant());

    public Task SetNormalizedEmailAsync(LegacyUserIdentity user, string? normalizedEmail, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<LegacyUserIdentity?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        // The legacy DAL has no email index; a real port would query tblUser by email.
        return Task.FromResult<LegacyUserIdentity?>(null);
    }

    // ---- IUserSecurityStampStore ----

    public Task SetSecurityStampAsync(LegacyUserIdentity user, string stamp, CancellationToken cancellationToken)
    {
        user.SecurityStamp = stamp;
        return Task.CompletedTask;
    }

    public Task<string?> GetSecurityStampAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.SecurityStamp);

    // ---- IUserLockoutStore ----

    public Task<DateTimeOffset?> GetLockoutEndDateAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.LockoutEnd);

    public Task SetLockoutEndDateAsync(LegacyUserIdentity user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        user.LockoutEnd = lockoutEnd;
        return Task.CompletedTask;
    }

    public Task<int> IncrementAccessFailedCountAsync(LegacyUserIdentity user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount++;
        return Task.FromResult(user.AccessFailedCount);
    }

    public Task ResetAccessFailedCountAsync(LegacyUserIdentity user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount = 0;
        return Task.CompletedTask;
    }

    public Task<int> GetAccessFailedCountAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.AccessFailedCount);

    public Task<bool> GetLockoutEnabledAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult(user.LockoutEnabled);

    public Task SetLockoutEnabledAsync(LegacyUserIdentity user, bool enabled, CancellationToken cancellationToken)
    {
        user.LockoutEnabled = enabled;
        return Task.CompletedTask;
    }

    // ---- IUserClaimStore: serves the permission claims Identity bakes into principals ----

    public Task<IList<Claim>> GetClaimsAsync(LegacyUserIdentity user, CancellationToken cancellationToken) =>
        Task.FromResult<IList<Claim>>(new List<Claim>(
            _dal.GetPermissionClaimsForUser(user.UserId, user.ClientId, user.SiteId)));

    public Task AddClaimsAsync(LegacyUserIdentity user, IEnumerable<Claim> claims, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Permission claims are owned by the legacy permission tables.");

    public Task ReplaceClaimAsync(LegacyUserIdentity user, Claim claim, Claim newClaim, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Permission claims are owned by the legacy permission tables.");

    public Task RemoveClaimsAsync(LegacyUserIdentity user, IEnumerable<Claim> claims, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Permission claims are owned by the legacy permission tables.");

    public Task<IList<LegacyUserIdentity>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken) =>
        Task.FromResult<IList<LegacyUserIdentity>>(new List<LegacyUserIdentity>());

    private static void RepopulateCaches(LegacyUserIdentity user)
    {
        ApplicationCaches.SetAuthUser(user);
        ApplicationCaches.SetUserContext(new UserContext(user));
    }
}
