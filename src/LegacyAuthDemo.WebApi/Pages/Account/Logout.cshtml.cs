using LegacyAuthDemo.Authorization.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace LegacyAuthDemo.WebApi.Pages.Account;

/// <summary>Simple logout page - goes through LegacySignInManager so caches + session cookie are cleared.</summary>
[Authorize]
public class LogoutModel(LegacySignInManager signInManager) : PageModel
{
    public async Task<IActionResult> OnGetAsync()
    {
        await signInManager.SignOutAsync();
        return LocalRedirect("/");
    }

    public async Task<IActionResult> OnPostAsync() => await OnGetAsync();
}
