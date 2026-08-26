using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using LegacyAuthDemo.Authorization.Authorization;
using LegacyAuthDemo.Authorization.Data;
using LegacyAuthDemo.Authorization.Repositories;
using LegacyAuthDemo.Authorization.Sessions;
using LegacyAuthDemo.Authorization.Stores;
using LegacyAuthDemo.Domain.Authentication;
using LegacyAuthDemo.Domain.Legacy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Validation;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using ValidationEvents = OpenIddict.Validation.OpenIddictValidationEvents;

namespace LegacyAuthDemo.Authorization.Startup;

/// <summary>
/// Mirrors the legacy RunAuthStartup - the single place where the
/// modern OpenIddict stack is fitted onto the legacy identity model.
///
/// The wiring, in legacy order:
///   1. EF context for OPENIDDICT ONLY (int-keyed entities, SQLite here / SQL Server in prod)
///   2. ASP.NET Identity over CUSTOM stores (the legacy DAL bridge)
///   3. OpenIddict core/server/validation with the custom endpoint URIs,
///      reference tokens, and the custom pipeline events
/// </summary>
public class LegacyOAuthOpenIdStartup
{
    public static void RunAuthStartup(bool isDevelopment, IServiceCollection services, IConfiguration config)
    {
        var authOptions = config.GetSection(LegacyAuthOptions.SectionName).Get<LegacyAuthOptions>()
                          ?? new LegacyAuthOptions();

        // ------------------------------------------------------------------
        // 1. DbContext - for OpenIddict only, NOT for the entire API.
        //    Int keys everywhere to match the legacy int UserId world.
        // ------------------------------------------------------------------
        var sqlitePath = authOptions.SqlitePath;
        services.AddDbContext<LegacyDbContext>(options =>
        {
            options.UseSqlite(sqlitePath is null
                ? config.GetConnectionString("Default")
                : $"Data Source={sqlitePath}");
            options.UseOpenIddict<int>();
        });

        // ------------------------------------------------------------------
        // 2. ASP.NET Identity as an ABSTRACTION LAYER over the legacy user model.
        //    No EF Identity tables: custom user/role stores translate every call
        //    into the legacy DAL and keep the static caches warm.
        // ------------------------------------------------------------------
        services.AddIdentity<LegacyUserIdentity, LegacyRole>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = "name";
                options.ClaimsIdentity.UserIdClaimType = "sub";
                options.ClaimsIdentity.RoleClaimType = "role";
                options.ClaimsIdentity.EmailClaimType = "email";

                options.Password.RequiredLength = 8;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.User.RequireUniqueEmail = false;
            })
            .AddUserStore<LegacyUserStore>()
            .AddRoleStore<LegacyRoleStore>()
            .AddUserManager<LegacyUserManager>()
            .AddSignInManager<LegacySignInManager>()
            .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options =>
        {
            options.LoginPath = "/account/login";
            options.LogoutPath = "/account/logout";
            options.Cookie.Name = "ap_identity";
            options.Events = new CookieAuthenticationEvents
            {
                OnRedirectToLogin = ctx =>
                {
                    // OIDC/API requests must not be 302'd to HTML silently.
                    if (ctx.Request.Path.StartsWithSegments("/api"))
                    {
                        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return Task.CompletedTask;
                    }
                    ctx.Response.Redirect(ctx.RedirectUri);
                    return Task.CompletedTask;
                }
            };
        });

        var dataProtection = services.AddDataProtection().SetApplicationName("LegacyAuthDemo");
        if (!string.IsNullOrWhiteSpace(authOptions.DataProtectionKeyPath))
        {
            // Hosted environments: persist the key ring so cookies/reference
            // tokens survive restarts and scale-out.
            dataProtection.PersistKeysToFileSystem(new DirectoryInfo(authOptions.DataProtectionKeyPath));
        }

        services.AddSingleton<LegacyUserDal>();
        services.AddHttpContextAccessor();
        services.AddScoped<IAuthUserSession, DefaultAuthUserSession>();

        // ------------------------------------------------------------------
        // 3. OpenIddict - core (stores), server (protocol), validation (tokens).
        // ------------------------------------------------------------------
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<LegacyDbContext>()
                       .ReplaceDefaultEntities<int>();
            })
            .AddServer(options =>
            {
                options
                    .AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .AllowPasswordFlow()          // kept from the legacy API surface (/api/user/authenticate)
                    .AllowClientCredentialsFlow();

                options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5))
                       .SetAccessTokenLifetime(TimeSpan.FromMinutes(authOptions.TokenLifeTimeMins))
                       .SetRefreshTokenLifetime(TimeSpan.FromDays(authOptions.RefreshTokenLifeTimeDays));

                // Custom endpoint URIs - the legacy server does not serve /connect/*.
                options.SetTokenEndpointUris("/ap-auth-server/connect/token", "/api/user/authenticate")
                       .SetAuthorizationEndpointUris("/ap-auth-server/connect/authorize")
                       .SetEndSessionEndpointUris("/ap-auth-server/connect/logout")
                       .SetUserInfoEndpointUris("/ap-auth-server/connect/userinfo")
                       .SetIntrospectionEndpointUris("/ap-auth-server/connect/introspect")
                       .SetRevocationEndpointUris("/ap-auth-server/connect/revocation");

                options.RegisterScopes("email", "profile", "roles", "offline_access");

                // Reference tokens: only an opaque reference goes over the wire -
                // ideal for the cookie-based BFF pattern used by the real frontend.
                options.UseReferenceAccessTokens()
                       .UseReferenceRefreshTokens();

                if (isDevelopment)
                {
                    options.AddEphemeralEncryptionKey()
                           .AddEphemeralSigningKey()
                           .DisableAccessTokenEncryption();   // demo readability; prod keeps tokens encrypted
                }
                else
                {
                    // Hosted/production: stable keys so tokens remain valid across
                    // restarts. Self-signed certs are generated once on first boot
                    // and persisted to mounted storage - no secrets in the repo.
                    var certDir = Path.GetDirectoryName(authOptions.SigningCertificatePath)
                                  ?? throw new InvalidOperationException(
                                      "Auth:SigningCertificatePath must be configured outside Development.");
                    Directory.CreateDirectory(certDir);

                    options.AddSigningCertificate(GetOrCreateCertificate(
                        authOptions.SigningCertificatePath!, authOptions.CertificatePassword, "CN=LegacyAuthDemo Signing"));
                    options.AddEncryptionCertificate(GetOrCreateCertificate(
                        authOptions.EncryptionCertificatePath ?? Path.Combine(certDir, "encryption.pfx"),
                        authOptions.CertificatePassword, "CN=LegacyAuthDemo Encryption"));
                }

                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserInfoEndpointPassthrough()
                       .EnableEndSessionEndpointPassthrough();

                options.SetIssuer(new Uri(authOptions.AuthorityUrl));
                // ---- Custom server event #1: session_state claim ----
                // Runs right after the authorization code principal is prepared:
                // stamps the browser session id into the sign-in principal so RPs
                // can monitor session state via check_session_iframe.
                // NOTE: in OpenIddict 7.x the ASP.NET host stores the AuthenticationProperties
                // in the transaction (not in ctx.Properties like older versions did).
                options.AddEventHandler<ProcessSignInContext>(builder =>
                    builder.UseInlineHandler(ctx =>
                        {
                            var authProps = ctx.Transaction.GetProperty<AuthenticationProperties>(
                                typeof(AuthenticationProperties).FullName!);
                            if (ctx.Principal is not null &&
                                authProps?.Items.TryGetValue(IAuthUserSession.SessionIdPropertyName, out var sessionId) == true &&
                                sessionId is not null)
                            {
                                var claim = new Claim("session_state", sessionId);
                                claim.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken);
                                foreach (var identity in ctx.Principal.Identities.Where(i => !i.HasClaim(c => c.Type == "session_state")))
                                {
                                    identity.AddClaim(claim);
                                }
                            }
                            return ValueTask.CompletedTask;
                        })
                        .SetOrder(OpenIddictServerHandlers.PrepareAuthorizationCodePrincipal.Descriptor.Order + 1));

                // ---- Custom server event #2: advertise check_session_iframe ----
                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(ctx =>
                        {
                            ctx.Metadata["check_session_iframe"] =
                                $"{authOptions.AuthorityUrl.TrimEnd('/')}/ap-auth-server/session-check";
                            return ValueTask.CompletedTask;
                        })
                        .SetOrder(OpenIddictServerHandlers.Discovery.AttachEndpoints.Descriptor.Order + 1));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseSystemNetHttp();
                options.UseAspNetCore();

                // ---- THE key custom validation event ----
                // After OpenIddict validates a token, hydrate the caller's legacy
                // permission claims onto the principal from the server-side caches.
                options.AddEventHandler<ValidationEvents.ProcessAuthenticationContext>(builder =>
                    builder.UseScopedHandler<LegacyOpenIdDictEventHandler>()
                        .SetOrder(OpenIddictValidationHandlers.ValidateAccessToken.Descriptor.Order + 1));
            });

        // Authorization plumbing for the dynamic PERMISSION_ policy provider.
        services.AddSingleton<IAuthorizationPolicyProvider, LegacyRoutePermissionAuthorizationPolicyProvider>();

        // Client seeding (localhost + any environment-configured redirect URIs)
        // and token pruning (Quartz in the legacy codebase).
        services.AddHostedService<ClientAppRegistration>();
        services.AddHostedService<TokenCleanupHostedService>();
    }

    /// <summary>
    /// Loads a self-signed certificate from <paramref name="path"/>, generating
    /// and persisting it on first boot. Keeps the OIDC keys stable across
    /// restarts without committing any secret material to source control.
    /// </summary>
    private static X509Certificate2 GetOrCreateCertificate(string path, string password, string subjectName)
    {
        if (!File.Exists(path))
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest(
                subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
            File.WriteAllBytes(path, certificate.Export(X509ContentType.Pfx, password));
        }

        return new X509Certificate2(path, password);
    }
}
