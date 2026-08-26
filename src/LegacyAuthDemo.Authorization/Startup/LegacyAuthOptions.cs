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

    /// <summary>
    /// Redirect URIs registered on the SPA client (auth code + PKCE).
    /// Defaults cover local Vite; environments append their own (e.g. the
    /// deployed azurewebsites.net URLs).
    /// </summary>
    public List<string> SpaRedirectUris { get; set; } = ["http://localhost:8080/auth-callback"];

    public List<string> SpaPostLogoutRedirectUris { get; set; } = ["http://localhost:8080/auth-logout"];

    /// <summary>
    /// Production-only: persisted self-signed certificates so issued tokens
    /// survive process restarts (dev uses ephemeral keys instead). The certs
    /// are generated on first boot and stored on mounted storage - nothing
    /// secret is committed to the repository.
    /// </summary>
    public string? SigningCertificatePath { get; set; }

    public string? EncryptionCertificatePath { get; set; }

    public string CertificatePassword { get; set; } = "demo-local-cert-password";

    /// <summary>Optional directory for persisted Data Protection key rings.</summary>
    public string? DataProtectionKeyPath { get; set; }

    /// <summary>Optional absolute SQLite file path override for hosted environments.</summary>
    public string? SqlitePath { get; set; }
}
