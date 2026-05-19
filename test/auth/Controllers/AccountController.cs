using auth.Models;
using auth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OAuth2NetCore;
using System;
using System.Composition;
using System.Security.Claims;
using System.Threading.Tasks;

namespace auth.Controllers {
    public class AccountController : Controller
    {
        // *******************************************************************************************************************************
        #region -  Property(ies)  -

        [Import]
        public Lazy<IUserService> LazyUserService { get; set; }

        [Import]
        public ILogger<AccountController> Logger { get; set; }

        #endregion
        // *******************************************************************************************************************************
        #region -  Login  -

        [HttpGet]
        public IActionResult Login(string returnUrl)
        {
            return View(new LoginModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model)
        {
            // Verify username & password first
            var isValid = await LazyUserService.Value.VerifyAsync(model.Username, model.Password);
            if (isValid)
            {
                Logger.LogDebug("log in success");
                AuthenticationProperties props = null;
                if (model.RememberLogin)
                {
                    props = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddDays(14),
                    };
                };

                var claims = new Claim[] { new Claim(OAuth2Consts.Claim_Name, model.Username) };
                var identity = new ClaimsIdentity(
                    claims
                    , CookieAuthenticationDefaults.AuthenticationScheme
                    , OAuth2Consts.Claim_Name
                    , OAuth2Consts.Claim_Role
                );
                var principal = new ClaimsPrincipal(identity);
                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props);
            }
            else
            {
                ModelState.AddModelError("a", "incorrect username and password");
            }

            return View(model);
        }

        #endregion
        // *******************************************************************************************************************************
        #region -  Logout  -

        [HttpPost]
        public async Task<ActionResult> Logout(string returnUrl)
        {
            //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync();
            return RedirectToAction(nameof(LoggedOut));
        }

        public ActionResult LoggedOut()
        {
            return View();
        }

        #endregion
    }
}
