using LegacyAuthDemo.Domain.Authentication;
using Microsoft.EntityFrameworkCore;

namespace LegacyAuthDemo.Authorization.Data;

/// <summary>
/// Mirrors the legacy DbContext. The EF context exists FOR OPENIDDICT ONLY - it stores
/// clients, authorizations, scopes and tokens (with int primary keys to match the
/// legacy int UserId world). The legacy user/permission data does NOT live here;
/// it is served by the legacy DAL + caches.
/// </summary>
public class LegacyDbContext : DbContext
{
    public LegacyDbContext(DbContextOptions options) : base(options) { }

    /// <summary>Only present so Identity has a users table to point at; backed by the bridge store.</summary>
    public DbSet<LegacyUserIdentity> Users => Set<LegacyUserIdentity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // OpenIddict tables with INT keys - the demo's nod to the legacy schema.
        modelBuilder.UseOpenIddict<int>();

        modelBuilder.Entity<LegacyUserIdentity>(builder =>
        {
            builder.ToTable("tblUser");
            builder.HasKey(user => user.UserId);
            builder.HasIndex(user => user.NormalizedUserName).IsUnique();
            builder.HasIndex(user => user.Email).IsUnique();
            builder.Property(user => user.UserName).HasMaxLength(256);
        });
    }
}
