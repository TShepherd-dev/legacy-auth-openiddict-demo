using LegacyAuthDemo.Authorization.Data;
using LegacyAuthDemo.Authorization.Startup;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

// Everything auth-related lives in the Authorization project's startup class -
// the same layering as the platform WebApi host calling RunAuthStartup.
LegacyOAuthOpenIdStartup.RunAuthStartup(builder.Environment.IsDevelopment(), builder.Services, builder.Configuration);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// CORS for the quick/dirty Vue frontend running on its own dev port.
// (When deployed, the SPA is served from this app itself - same origin.)
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("http://localhost:8080")
          .AllowAnyHeader()
          .AllowAnyMethod()));

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    // Hosted behind a reverse proxy (App Service terminates TLS upstream):
    // trust the forwarded proto so OpenIddict's transport checks see HTTPS.
    app.UseForwardedHeaders(new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    });
}

// Serve the built Vue SPA (copied into wwwroot at publish time). Local dev
// usually has no wwwroot - the Vite dev server plays that role instead.
if (Directory.Exists(Path.Combine(app.Environment.ContentRootPath, "wwwroot")))
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

// The legacy codebase runs against an existing platform database; this demo
// creates its SQLite schema on first boot instead (before hosted services run).
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<LegacyDbContext>();
    db.Database.EnsureCreated();
}

app.UseHttpsRedirection();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapRazorPages();

// Unmatched API/auth paths must 404, not fall through to the SPA shell.
app.Map("/api/{**_}", () => Results.NotFound());
app.Map("/ap-auth-server/{**_}", () => Results.NotFound());
app.Map("/account/{**_}", () => Results.NotFound());

// SPA client-side routing fallback (e.g. /auth-callback deep links).
app.MapFallbackToFile("index.html");

app.Run();
