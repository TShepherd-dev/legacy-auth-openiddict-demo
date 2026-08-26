using System.Security.Claims;

namespace LegacyAuthDemo.Domain.Authentication;

/// <summary>
/// Mirrors the legacy <c>UserContext</c>: the per-user bundle of identity plus the
/// hydrated permission claim list that flows through the request pipeline.
/// This is what gets cached in ApplicationCaches.UserCache and attached to the
/// request after token validation.
/// </summary>
public class UserContext
{
    public int UserId { get; init; }
    public string UserName { get; init; } = string.Empty;
    public int ClientId { get; init; }
    public int SiteId { get; init; }
    public string DisplayName { get; init; } = string.Empty;
    public string? Email { get; init; }

    public List<Claim> PermissionClaimList { get; private set; } = new();

    public UserContext() { }

    public UserContext(LegacyUserIdentity user)
    {
        UserId = user.UserId;
        UserName = user.UserName;
        ClientId = user.ClientId;
        SiteId = user.SiteId;
        DisplayName = user.DisplayName;
        Email = user.Email;
        PermissionClaimList = new List<Claim>(user.PermissionClaimList);
    }

    public UserContext SetPermissionClaimList(List<Claim> claims)
    {
        PermissionClaimList = claims ?? new List<Claim>();
        return this;
    }

    public bool HasPermission(string permission) =>
        PermissionClaimList.Any(c =>
            c.Type == LegacyAuthConstants.ClaimTypes.Permissions &&
            string.Equals(c.Value, permission, StringComparison.OrdinalIgnoreCase));
}
