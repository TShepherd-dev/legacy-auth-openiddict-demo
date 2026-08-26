using LegacyAuthDemo.Authorization.Data;
using LegacyAuthDemo.Authorization.Startup;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Everything auth-related lives in the Authorization project's startup class -
// the same layering as the platform WebApi host calling RunAuthStartup.
LegacyOAuthOpenIdStartup.RunAuthStartup(builder.Environment.IsDevelopment(), builder.Services, builder.Configuration);

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// CORS for the quick/dirty Vue frontend.
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.WithOrigins("http://localhost:8080")
          .AllowAnyHeader()
          .AllowAnyMethod()));

var app = builder.Build();

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

app.Run();
