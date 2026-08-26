using Microsoft.AspNetCore.Identity;

namespace LegacyAuthDemo.Domain.Authentication;

/// <summary>
/// Mirrors the legacy role type (an IdentityRole&lt;int&gt;-shaped POCO). The legacy system has its own role
/// table (tblRole) with int keys; we subclass IdentityRole purely so the generic
/// Identity plumbing accepts it, exactly like the legacy codebase does.
/// </summary>
public class LegacyRole : IdentityRole<int>
{
    public LegacyRole() { }

    public LegacyRole(string roleName) : base(roleName) { }
}
