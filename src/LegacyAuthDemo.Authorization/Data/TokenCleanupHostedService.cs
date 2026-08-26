using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace LegacyAuthDemo.Authorization.Data;

/// <summary>
/// The legacy codebase uses Quartz.NET for token pruning (OpenIddict UseQuartz).
/// To keep the demo dependency-light this is a plain hosted service doing the same
/// job via IOpenIddictTokenManager/AuthorizationManager.PruneAsync.
/// </summary>
public class TokenCleanupHostedService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<TokenCleanupHostedService> _logger;

    public TokenCleanupHostedService(IServiceProvider serviceProvider, ILogger<TokenCleanupHostedService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();

                var tokenManager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
                var authorizationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

                await tokenManager.PruneAsync(DateTimeOffset.UtcNow.AddDays(-14), stoppingToken);
                await authorizationManager.PruneAsync(DateTimeOffset.UtcNow.AddDays(-14), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "TokenCleanupHostedService.ExecuteAsync: prune pass failed.");
            }

            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}
