using Microsoft.AspNetCore.Http;
using OAuth2NetCore.Model;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace OAuth2NetCore.Token {
    public interface ITokenClaimBuilder
    {
        /// <summary>
        /// Builds the claims of an access token. Return a non-success result (MsgCode = OAuth2Consts.Msg_SubjectDenied)
        /// to refuse issuing it; the server answers invalid_grant (token endpoint) / access_denied (implicit).
        /// Exceptions are treated as server errors.
        /// </summary>
        Task<MessageResult<IList<Claim>>> GenerateAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username);
    }
}
