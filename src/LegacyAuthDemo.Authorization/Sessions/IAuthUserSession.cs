using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace LegacyAuthDemo.Authorization.Sessions;

/// <summary>
/// Mirrors IAuthUserSession from the legacy codebase: tracks the browser session id
/// that backs the "session_state" claim / check_session_iframe flow.
/// </summary>
public interface IAuthUserSession
{
    public const string SessionCookieName = "ap_session";
    public const string SessionIdPropertyName = "ap_session_id";

    /// <summary>Creates (or returns) the session id for the current user and records it in the auth properties.</summary>
    Task<string> CreateSessionIdAsync(ClaimsPrincipal principal, AuthenticationProperties properties);

    /// <summary>Returns the session id for the caller's session cookie, if any.</summary>
    string? GetCurrentSessionId();

    void RemoveSession();
}
