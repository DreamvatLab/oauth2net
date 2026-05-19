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

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
