namespace LegacyAuthDemo.Domain.Authentication;

/// <summary>
/// Mirrors the legacy authentication constants from the legacy codebase.
/// These constants are the contract between the legacy permission model
/// and the OpenIddict pipeline.
/// </summary>
public static class LegacyAuthConstants
{
    /// <summary>
    /// Policies starting with this prefix are resolved dynamically by
    /// <c>LegacyRoutePermissionAuthorizationPolicyProvider</c> against the legacy
    /// permission store instead of being registered statically at startup.
    /// </summary>
    public const string PolicyPrefix = "PERMISSION_";

    /// <summary>
    /// Well-known application (client) identifiers, mirroring the legacy
    /// Applications constants (Demo.Resource, Demo.AdminResource, ...).
    /// </summary>
    public static class Applications
    {
        public const string SpaFrontEnd = "LegacyAuthDemo.Spa";
        public const string TestClient = "LegacyAuthDemo.Test";
    }

    /// <summary>
    /// Legacy error codes. The legacy codebase never leaks ASP.NET identity errors;
    /// everything is translated into these coarse codes.
    /// </summary>
    public static class Errors
    {
        public const string ErrorLoginBadUserDetails = "ERROR_LOGIN_BAD_USER_DETAILS";
        public const string ErrorLoginAccountLocked = "ERROR_LOGIN_ACCOUNT_LOCKED";
        public const string ErrorInvalidToken = "ERROR_INVALID_TOKEN";
        public const string ErrorLoginNoLongerAllowed = "ERROR_LOGIN_NO_LONGER_ALLOWED";
    }

    /// <summary>
    /// Custom claim types embedded in tokens. Tokens stay MINIMAL:
    /// only these identifiers go over the wire; the rich permission set
    /// never leaves the server (it is re-hydrated after validation).
    /// </summary>
    public static class Claims
    {
        public const string DemoClientId = "demo_clientId";
        public const string DemoSiteId = "demo_siteId";
        public const string Schema = "demo_schema";
        public const string DemoTokenType = "demo_tokentype";
        public const string DemoTokenRefId = "demo_rId";
    }

    /// <summary>The claim type under which every legacy permission is injected.</summary>
    public static class ClaimTypes
    {
        public const string Permissions = "demo_permissions";
    }

    /// <summary>Discriminator values for the demo_tokentype claim.</summary>
    public static class AuthenticationTokenTypes
    {
        public const string DemoPasswordGrant = "DemoPasswordGrant";
        public const string DemoAuthorizationCode = "DemoAuthorizationCode";
        public const string DemoPersonalAccessToken = "DemoPat";
    }
}
