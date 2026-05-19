using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OAuth2NetCore;
using OAuth2NetCore.Store;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection {
    public class OAuth2Handler : OAuthHandler<OAuthOptions>
    {
        private readonly ITokenStore _tokenDTOStore;

        public OAuth2Handler(IOptionsMonitor<OAuthOptions> options, ILoggerFactory logger, UrlEncoder encoder, ITokenStore tokenDTOStore)
            : base(options, logger, encoder)
        {
            _tokenDTOStore = tokenDTOStore;
        }

        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var tokenRequestParameters = new Dictionary<string, string>()
            {
                { OAuth2Consts.Form_ClientID, Options.ClientId },
                { OAuth2Consts.Form_RedirectUri, context.RedirectUri },
                { OAuth2Consts.Form_ClientSecret, Options.ClientSecret },
                { OAuth2Consts.Form_Code, context.Code },
                { OAuth2Consts.Form_GrantType, OAuth2Consts.GrantType_AuthorizationCode },
            };


            var tokenDTO = await _tokenDTOStore.GetTokenDTOAsync();
            if (!string.IsNullOrWhiteSpace(tokenDTO?.RefreshToken))
            {// send old refresh token to clear it
                tokenRequestParameters[OAuth2Consts.Form_RefreshToken] = tokenDTO.RefreshToken;
            }

            // PKCE https://tools.ietf.org/html/rfc7636#section-4.5, see BuildChallengeUrl
            if (context.Properties.Items.TryGetValue(OAuthConstants.CodeVerifierKey, out var codeVerifier))
            {
                tokenRequestParameters.Add(OAuthConstants.CodeVerifierKey, codeVerifier);
                context.Properties.Items.Remove(OAuthConstants.CodeVerifierKey);
            }

            var requestContent = new FormUrlEncodedContent(tokenRequestParameters);

            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);
            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;
            requestMessage.Version = Backchannel.DefaultRequestVersion;
            var response = await Backchannel.SendAsync(requestMessage, Context.RequestAborted);
            if (response.IsSuccessStatusCode)
            {
                var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                return OAuthTokenResponse.Success(payload);
            }
            else
            {
                var error = "OAuth token endpoint failure: " + await Display(response);
                return OAuthTokenResponse.Failed(new Exception(error));
            }
        }


        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();
            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers.ToString() + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");
            return output.ToString();
        }
    }
}
