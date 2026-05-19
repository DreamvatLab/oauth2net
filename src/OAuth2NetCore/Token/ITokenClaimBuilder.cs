using Microsoft.AspNetCore.Http;
using OAuth2NetCore.Model;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public interface ITokenClaimBuilder
    {
        Task<IList<Claim>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
    }
}
