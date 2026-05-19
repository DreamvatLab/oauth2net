using Microsoft.AspNetCore.Http;
using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public interface ITokenGenerator
    {
        Task<string> GenerateAccessTokenAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
        Task<string> GenerateRefreshTokenAsync();
    }
}
