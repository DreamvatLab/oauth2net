using Microsoft.AspNetCore.Http;
using OAuth2NetCore.Model;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public interface ITokenGenerator
    {
        /// <summary>
        /// Issues an access token. A non-success result means the subject was denied by ITokenClaimBuilder.
        /// </summary>
        Task<MessageResult<string>> GenerateAccessTokenAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
        Task<string> GenerateRefreshTokenAsync();
    }
}
