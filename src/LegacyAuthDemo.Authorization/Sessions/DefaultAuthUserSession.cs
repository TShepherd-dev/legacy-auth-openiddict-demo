using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace LegacyAuthDemo.Authorization.Sessions;

/// <summary>
/// Mirrors DefaultAuthUserSession (297 lines in the legacy codebase, compacted):
/// keeps userId -> sessionId in memory and mirrors it into the "ap_session" cookie
/// so the check-session iframe can report session state to RP iframes.
/// </summary>
public class DefaultAuthUserSession : IAuthUserSession
{
    private static readonly ConcurrentDictionary<string, string> Sessions = new();

    private readonly IHttpContextAccessor _httpContextAccessor;

    public DefaultAuthUserSession(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties)
    {
        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier)
                     ?? principal.FindFirstValue("sub");

        if (string.IsNullOrEmpty(userId))
            throw new InvalidOperationException("Cannot create a session without a user id.");

        var sessionId = Sessions.GetOrAdd(userId, _ => Guid.NewGuid().ToString("N"));
        properties.Items[IAuthUserSession.SessionIdPropertyName] = sessionId;

        var response = _httpContextAccessor.HttpContext?.Response;
        if (response is not null && !response.HasStarted)
        {
            response.Cookies.Append(IAuthUserSession.SessionCookieName, sessionId, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Lax,
                IsEssential = true
            });
        }

        return Task.FromResult(sessionId);
    }

    public string? GetCurrentSessionId()
    {
        return _httpContextAccessor.HttpContext?.Request.Cookies.TryGetValue(
            IAuthUserSession.SessionCookieName, out var sessionId) == true ? sessionId : null;
    }

    public void RemoveSession()
    {
        var request = _httpContextAccessor.HttpContext?.Request;
        if (request is not null &&
            request.Cookies.TryGetValue(IAuthUserSession.SessionCookieName, out var sessionId))
        {
            Sessions.TryRemoveByValue(sessionId);
        }
    }
}

file static class DictionaryExtensions
{
    public static bool TryRemoveByValue<TKey, TValue>(this ConcurrentDictionary<TKey, TValue> source, TValue value)
        where TKey : notnull
    {
        foreach (var pair in source)
        {
            if (EqualityComparer<TValue>.Default.Equals(pair.Value, value))
            {
                return ((ICollection<KeyValuePair<TKey, TValue>>)source).Remove(pair);
            }
        }
        return false;
    }
}
