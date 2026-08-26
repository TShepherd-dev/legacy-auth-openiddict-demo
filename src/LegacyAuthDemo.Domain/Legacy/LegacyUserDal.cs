using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Caching;

namespace LegacyAuthDemo.Domain.Legacy;

/// <summary>
/// Stands in for the 17-year-old DAL (tblUser / tblUserPermission) of the real codebase.
/// In the legacy system this would be ADO.NET / stored procedures; here it is a seeded
/// static store. The SHAPE of the API is what matters: everything above this layer
/// (custom stores, caches, OpenIddict events) talks to the legacy model, not to EF.
///
/// Seeded users:
///   alice - full permissions (view + manage + manage users)
///   bob   - read-only      (view only)
/// </summary>
public class LegacyUserDal
{
    private static readonly Lazy<Dictionary<int, LegacyUserIdentity>> Users = new(SeedUsers);
    private static readonly Lazy<PasswordHasher<LegacyUserIdentity>> Hasher = new();

    /// <summary>
    /// Mirrors AddPermissionClaimsToUser(userId, clientId, siteId): reads the legacy
    /// permission tables and turns each row into an "ap_permissions" claim.
    /// In the demo, permissions are derived from scope-like rows per user.
    /// </summary>
    public List<Claim> GetPermissionClaimsForUser(int userId, int clientId, int siteId)
    {
        if (!Users.Value.TryGetValue(userId, out var user) || user.DeletionStatus != 0)
            return new List<Claim>();

        return user.PermissionClaimList
            .Select(c => new Claim(c.Type, c.Value))
            .ToList();
    }

    public LegacyUserIdentity? FindById(int userId) =>
        Users.Value.TryGetValue(userId, out var user) && user.DeletionStatus == 0 ? Clone(user) : null;

    public LegacyUserIdentity? FindByName(string normalizedUserName) =>
        Users.Value.Values.FirstOrDefault(u =>
            u.NormalizedUserName == normalizedUserName && u.DeletionStatus == 0) is { } found
            ? Clone(found)
            : null;

    /// <summary>Mirrors dal.SaveAsync(userEntity): persists then lets callers re-cache.</summary>
    public void Save(LegacyUserIdentity user)
    {
        Users.Value[user.UserId] = Clone(user);
    }

    private static LegacyUserIdentity Clone(LegacyUserIdentity source) => new()
    {
        UserId = source.UserId,
        UserName = source.UserName,
        NormalizedUserName = source.NormalizedUserName,
        Email = source.Email,
        EmailConfirmed = source.EmailConfirmed,
        PasswordHash = source.PasswordHash,
        SecurityStamp = source.SecurityStamp,
        ConcurrencyStamp = source.ConcurrencyStamp,
        LockoutEnd = source.LockoutEnd,
        LockoutEnabled = source.LockoutEnabled,
        AccessFailedCount = source.AccessFailedCount,
        TwoFactorEnabled = source.TwoFactorEnabled,
        ClientId = source.ClientId,
        SiteId = source.SiteId,
        ForcePasswordChange = source.ForcePasswordChange,
        DeletionStatus = source.DeletionStatus,
        DisplayName = source.DisplayName,
        PermissionClaimList = source.PermissionClaimList
            .Select(c => new Claim(c.Type, c.Value))
            .ToList()
    };

    private const string ViewDemo = "route.demo.view";
    private const string ManageDemo = "route.demo.manage";
    private const string ManageUsers = "route.users.manage";

    private static Dictionary<int, LegacyUserIdentity> SeedUsers()
    {
        var hasher = new PasswordHasher<LegacyUserIdentity>();
        var users = new List<LegacyUserIdentity>
        {
            MakeUser(1, "alice", "Alice Admin", "alice@example.com",
                new[] { ViewDemo, ManageDemo, ManageUsers }),
            MakeUser(2, "bob", "Bob Readonly", "bob@example.com",
                new[] { ViewDemo })
        };

        foreach (var user in users)
        {
            // Hash once at seed time, exactly as the legacy import script would have done.
            user.PasswordHash = hasher.HashPassword(user, "Passw0rd!");
            user.PermissionClaimList = user.PermissionClaimList; // already set by MakeUser
        }

        return users.ToDictionary(u => u.UserId);

        LegacyUserIdentity MakeUser(int id, string userName, string displayName, string email, string[] perms)
        {
            var user = new LegacyUserIdentity
            {
                UserId = id,
                UserName = userName,
                Email = email,
                EmailConfirmed = true,
                DisplayName = displayName,
                ClientId = ApplicationCaches.DefaultClientId,
                SiteId = ApplicationCaches.DefaultSiteId,
                PermissionClaimList = perms
                    .Select(p => new Claim(LegacyAuthConstants.ClaimTypes.Permissions, p))
                    .ToList()
            };
            user.NormalizedUserName = userName.ToUpperInvariant();
            return user;
        }
    }
}
