namespace LegacyAuthDemo.Authorization.Startup;

/// <summary>
/// Mirrors the legacy app configuration section consumed by the legacy auth startup.
/// </summary>
public class LegacyAuthOptions
{
    public const string SectionName = "Auth";

    /// <summary>Public base URL of this server - becomes the OIDC issuer.</summary>
    public string AuthorityUrl { get; set; } = "https://localhost:5001";

    public int TokenLifeTimeMins { get; set; } = 60;

    public int RefreshTokenLifeTimeDays { get; set; } = 14;
}
