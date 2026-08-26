using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Claims;

namespace LegacyAuthDemo.Domain.Authentication;

/// <summary>
/// Mirrors <c>AuthenticationUserIdentity</c> from the legacy codebase.
///
/// IMPORTANT: this is NOT an ASP.NET IdentityUser. It is a POCO that mimics the
/// surface ASP.NET Identity needs (password hash, lockout, security stamp...) so
/// that a custom UserStore can bridge Identity over the top of a legacy user
/// table (tblUser) that predates ASP.NET Identity by more than a decade.
///
/// The legacy table is multi-tenant (ClientId/SiteId ints) and carries its own
/// concepts (ForcePasswordChange, DeletionStatus) that have no Identity equivalent.
/// </summary>
public class LegacyUserIdentity
{
    /// <summary>Legacy int primary key from tblUser.UserId. OpenIddict is configured with int keys to match.</summary>
    public int UserId { get; set; }

    public string UserName { get; set; } = string.Empty;
    public string? NormalizedUserName { get; set; }
    public string? Email { get; set; }
    public bool EmailConfirmed { get; set; }
    public string? PasswordHash { get; set; }
    public string? SecurityStamp { get; set; } = Guid.NewGuid().ToString("D");
    public string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString("D");
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool LockoutEnabled { get; set; } = true;
    public int AccessFailedCount { get; set; }
    public bool TwoFactorEnabled { get; set; }

    // ---- Legacy-only columns (no ASP.NET Identity equivalent) ----

    /// <summary>Multi-tenant discriminator #1 (legacy tblUser.ClientId).</summary>
    public int ClientId { get; set; } = 1;

    /// <summary>Multi-tenant discriminator #2 (legacy tblUser.SiteId).</summary>
    public int SiteId { get; set; } = 1;

    /// <summary>Legacy flag forcing a password reset on next sign-in.</summary>
    public int ForcePasswordChange { get; set; }

    /// <summary>Soft-delete flag in the legacy table.</summary>
    public int DeletionStatus { get; set; }

    /// <summary>Display name kept in the legacy table.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>
    /// Permission claims for THIS user, loaded from the legacy permission tables.
    /// Populated by the custom UserStore at login / cache-repopulation time -
    /// never stored in the token itself.
    /// </summary>
    [NotMapped]
    public List<Claim> PermissionClaimList { get; set; } = new();
}
