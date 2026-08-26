using LegacyAuthDemo.Domain.Authentication;
using Microsoft.AspNetCore.Identity;

namespace LegacyAuthDemo.Authorization.Stores;

/// <summary>
/// Mirrors the legacy role store: Identity role operations translated onto the legacy
/// tblRole world (int keys). The demo keeps roles in memory - the point is that
/// Identity accepts a fully custom store.
/// </summary>
public class LegacyRoleStore : IRoleStore<LegacyRole>
{
    private static readonly Dictionary<int, LegacyRole> Roles = new()
    {
        [1] = new LegacyRole("administrator") { Id = 1 },
        [2] = new LegacyRole("user") { Id = 2 }
    };

    public void Dispose() { }

    public Task<IdentityResult> CreateAsync(LegacyRole role, CancellationToken cancellationToken)
    {
        Roles[role.Id] = role;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> UpdateAsync(LegacyRole role, CancellationToken cancellationToken)
    {
        Roles[role.Id] = role;
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<IdentityResult> DeleteAsync(LegacyRole role, CancellationToken cancellationToken)
    {
        Roles.Remove(role.Id);
        return Task.FromResult(IdentityResult.Success);
    }

    public Task<string> GetRoleIdAsync(LegacyRole role, CancellationToken cancellationToken) =>
        Task.FromResult(role.Id.ToString());

    public Task<string?> GetRoleNameAsync(LegacyRole role, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(role.Name);

    public Task SetRoleNameAsync(LegacyRole role, string? roleName, CancellationToken cancellationToken)
    {
        role.Name = roleName;
        return Task.CompletedTask;
    }

    public Task<string?> GetNormalizedRoleNameAsync(LegacyRole role, CancellationToken cancellationToken) =>
        Task.FromResult<string?>(role.Name?.ToUpperInvariant());

    public Task SetNormalizedRoleNameAsync(LegacyRole role, string? normalizedName, CancellationToken cancellationToken) =>
        Task.CompletedTask;

    public Task<LegacyRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken) =>
        Task.FromResult(int.TryParse(roleId, out var id) && Roles.TryGetValue(id, out var role) ? role : null);

    public Task<LegacyRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken) =>
        Task.FromResult<LegacyRole?>(Roles.Values.FirstOrDefault(r =>
            string.Equals(r.Name?.ToUpperInvariant(), normalizedRoleName, StringComparison.Ordinal)));
}
