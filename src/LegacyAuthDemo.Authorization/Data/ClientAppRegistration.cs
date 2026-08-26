using LegacyAuthDemo.Authorization.Startup;
using LegacyAuthDemo.Domain.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;

namespace LegacyAuthDemo.Authorization.Data;

/// <summary>
/// Mirrors the legacy dev-time client seeding: seeds
/// the known clients on startup, with retry-on-concurrency like the original.
/// SPA redirect URIs come from configuration so hosted environments register
/// their own URLs alongside the localhost defaults.
/// </summary>
public class ClientAppRegistration : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public ClientAppRegistration(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var authOptions = scope.ServiceProvider.GetRequiredService<IConfiguration>()
            .GetSection(LegacyAuthOptions.SectionName).Get<LegacyAuthOptions>() ?? new LegacyAuthOptions();

        await UpdateWithRetryAsync(manager, LegacyAuthConstants.Applications.SpaFrontEnd, descriptor =>
        {
            descriptor.DisplayName = "Legacy Auth Demo - Vue SPA";
            descriptor.ApplicationType = OpenIddictConstants.ApplicationTypes.Web;
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
            descriptor.ConsentType = OpenIddictConstants.ConsentTypes.Implicit;
            foreach (var uri in authOptions.SpaRedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(uri));
            }
            foreach (var uri in authOptions.SpaPostLogoutRedirectUris)
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(uri));
            }
            descriptor.Permissions.UnionWith(
            [
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.Endpoints.Introspection,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles
                // Note: no scope permission needed for offline_access - OpenIddict
                // grants it automatically to clients allowed RefreshToken.
            ]);
        }, cancellationToken);

        // Password-grant client kept from the legacy API surface for quick curl demos.
        await UpdateWithRetryAsync(manager, LegacyAuthConstants.Applications.TestClient, descriptor =>
        {
            descriptor.DisplayName = "Legacy Auth Demo - Test (password grant)";
            descriptor.ApplicationType = OpenIddictConstants.ApplicationTypes.Native;
            descriptor.ClientType = OpenIddictConstants.ClientTypes.Public;
            descriptor.ConsentType = OpenIddictConstants.ConsentTypes.Implicit;
            descriptor.Permissions.UnionWith(
            [
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.GrantTypes.Password,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken
            ]);
        }, cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Mirrors the legacy UpdateWithRetryAsync handling ConcurrencyException with 3 attempts.</summary>
    private static async Task UpdateWithRetryAsync(
        IOpenIddictApplicationManager manager,
        string clientId,
        Action<OpenIddictApplicationDescriptor> configure,
        CancellationToken cancellationToken)
    {
        const int maxAttempts = 3;

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var existing = await manager.FindByClientIdAsync(clientId, cancellationToken);
                if (existing is null)
                {
                    var descriptor = new OpenIddictApplicationDescriptor();
                    configure(descriptor);
                    descriptor.ClientId = clientId;
                    await manager.CreateAsync(descriptor, cancellationToken);
                }
                else
                {
                    var descriptor = new OpenIddictApplicationDescriptor();
                    await manager.PopulateAsync(descriptor, existing, cancellationToken);
                    descriptor.ClientId = clientId;
                    descriptor.Permissions.Clear();
                    configure(descriptor);
                    await manager.UpdateAsync(existing, descriptor, cancellationToken);
                }
                return;
            }
            catch (OpenIddictExceptions.ConcurrencyException) when (attempt < maxAttempts)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), cancellationToken);
            }
        }
    }
}
