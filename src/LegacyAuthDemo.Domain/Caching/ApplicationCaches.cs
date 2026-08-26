using System.Collections.Concurrent;
using LegacyAuthDemo.Domain.Authentication;

namespace LegacyAuthDemo.Domain.Caching;

/// <summary>
/// Mirrors the legacy static <c>ApplicationCaches</c>: process-wide in-memory caches
/// that sit in front of the legacy database.
///
/// This is the heart of the legacy performance model: tokens carry only identifiers,
/// while the rich permission data lives here, keyed by user id. The OpenIddict
/// validation event handler re-hydrates permissions from these caches onto the
/// principal AFTER token validation - a cache miss falls back to the "database".
/// </summary>
public static class ApplicationCaches
{
    /// <summary>userId -> full identity (mirrors AuthUserCache).</summary>
    private static readonly ConcurrentDictionary<string, LegacyUserIdentity> AuthUserCache = new();

    /// <summary>userId -> hydrated permission context (mirrors UserCache).</summary>
    private static readonly ConcurrentDictionary<string, UserContext> UserCache = new();

    /// <summary>Legacy lookups are always scoped by ClientId/SiteId; demo pins tenant 1/1.</summary>
    public const int DefaultClientId = 1;
    public const int DefaultSiteId = 1;

    public static LegacyUserIdentity? GetAuthUser(int userId) =>
        AuthUserCache.TryGetValue(userId.ToString(), out var user) ? user : null;

    public static void SetAuthUser(LegacyUserIdentity user) =>
        AuthUserCache[user.UserId.ToString()] = user;

    public static void RemoveAuthUser(int userId) =>
        AuthUserCache.TryRemove(userId.ToString(), out _);

    public static UserContext? GetUserContext(int userId) =>
        UserCache.TryGetValue(userId.ToString(), out var ctx) ? ctx : null;

    public static void SetUserContext(UserContext context) =>
        UserCache[context.UserId.ToString()] = context;

    public static void RemoveUserContext(int userId) =>
        UserCache.TryRemove(userId.ToString(), out _);

    /// <summary>Mirrors the legacy user manager's ClearDemoUserCaches - called on logout/sign-out.</summary>
    public static void ClearUserCaches(int userId)
    {
        RemoveAuthUser(userId);
        RemoveUserContext(userId);
    }
}
