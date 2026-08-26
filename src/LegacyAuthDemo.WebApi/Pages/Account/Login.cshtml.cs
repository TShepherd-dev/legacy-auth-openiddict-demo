using System.ComponentModel.DataAnnotations;
using LegacyAuthDemo.Authorization.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace LegacyAuthDemo.WebApi.Pages.Account;

/// <summary>
/// The interactive login page the authorize endpoint challenges to (identity cookie
/// scheme). Credentials are validated through LegacySignInManager -> custom stores
/// -> legacy DAL - the same path the legacy login used before OpenIddict existed.
/// </summary>
[AllowAnonymous]
public class LoginModel(LegacySignInManager signInManager) : PageModel
{
    [BindProperty, Required, Display(Name = "Username")]
    public string UserName { get; set; } = string.Empty;

    [BindProperty, Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public void OnGet() { }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var result = await signInManager.PasswordSignInAsync(
            UserName, Password, isPersistent: true, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            return LocalRedirect(string.IsNullOrEmpty(ReturnUrl) ? "/" : ReturnUrl);
        }

        ErrorMessage = result.IsLockedOut ? "Account locked. Try again later." : "Invalid username or password.";
        return Page();
    }
}
