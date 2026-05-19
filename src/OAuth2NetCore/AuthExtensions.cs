using Microsoft.AspNetCore.Http;
using OAuth2NetCore;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication {
    public static class AuthExtensions
    {
        public static async Task OAuth2SignOutAsync(this HttpContext httpContext)
        {
            httpContext.Response.Cookies.Delete(OAuth2Consts.Cookie_TokenDTO);
            await httpContext.SignOutAsync();
        }
    }
}
