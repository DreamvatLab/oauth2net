using client.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuth2NetCore.Store;
using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace client.Controllers {
    public class HomeController : Controller
    {
        private readonly ITokenStore _tokenDTOStore;

        public HomeController(ITokenStore tokenDTOStore)
        {
            _tokenDTOStore = tokenDTOStore;
        }

        public async Task<IActionResult> Index()
        {
            var token = await _tokenDTOStore.GetTokenDTOAsync();
            return View(token);
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize]
        [HttpGet("/testapi")]
        public async Task<IActionResult> TestApi()
        {
            var token = await _tokenDTOStore.GetTokenDTOAsync();
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, new Uri("https://di.syncecom.co/users"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
            var resp = await client.SendAsync(request);
            var rs = await resp.Content.ReadAsStringAsync();

            return Content(rs);
        }

        // Shows whether the API can read the "role" claim by its short type (always returns the
        // diagnostic JSON regardless of role).
        [Authorize]
        [HttpGet("/testrole")]
        public Task<IActionResult> TestRole() => CallApiAsync("https://di.syncecom.co/roleinfo");

        // Hits the role-protected API endpoint: 200 = role authz works, 403 = the bug is back.
        [Authorize]
        [HttpGet("/testroleprotected")]
        public Task<IActionResult> TestRoleProtected() => CallApiAsync("https://di.syncecom.co/roleprotected");

        private async Task<IActionResult> CallApiAsync(string url)
        {
            var token = await _tokenDTOStore.GetTokenDTOAsync();
            var client = new HttpClient();
            var request = new HttpRequestMessage(HttpMethod.Get, new Uri(url));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
            var resp = await client.SendAsync(request);
            var body = await resp.Content.ReadAsStringAsync();

            // Surface the status code so a 403 is visible in the browser (its body is empty).
            return Content($"HTTP {(int)resp.StatusCode} {resp.StatusCode}\n\n{body}", "text/plain");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
