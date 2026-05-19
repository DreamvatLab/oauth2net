using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace OAuth2NetCore.Host {
    internal static class LocalRedirectGuard {
        // Returns input only when it is a local (same-origin) relative URL. Falls back to "/" to
        // prevent an attacker from supplying ?returnUrl=https://evil.com on signin/signout.
        public static string SafeLocal(string returnUrl) {
            if (string.IsNullOrEmpty(returnUrl)) return "/";
            // Must start with a single '/', and not '//' or '/\' (protocol-relative).
            if (returnUrl[0] != '/') return "/";
            if (returnUrl.Length > 1 && (returnUrl[1] == '/' || returnUrl[1] == '\\')) return "/";
            return returnUrl;
        }
    }

    public class DefaultClientServer : IClientServer {
        private readonly IStateStore _stateStore;
        private readonly IStateGenerator _stateGenerator;
        private readonly ITokenStore _tokenDTOStore;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<DefaultClientServer> _logger;
        private readonly ClientOptions _options;
        public RequestDelegate SignInRequestHandler { get; }
        public RequestDelegate SignOutRequestHandler { get; }
        public RequestDelegate SignOutCallbackRequestHandler { get; }

        public DefaultClientServer(
            IStateStore stateStore
            , ITokenStore tokenDTOStore
            , IStateGenerator stateGenerator
            , IHttpClientFactory httpClientFactory
            , ILogger<DefaultClientServer> logger
            , ClientOptions options
        ) {
            _stateStore = stateStore;
            _stateGenerator = stateGenerator;
            _tokenDTOStore = tokenDTOStore;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _options = options;

            SignInRequestHandler = HandleSignInRequestAsync;
            SignOutRequestHandler = HandleSignOutRequestAsync;
            SignOutCallbackRequestHandler = HandleSignOutCallbackRequestAsync;
        }

        /// <summary>
        /// handle sign out request
        /// </summary>
        protected virtual async Task HandleSignOutRequestAsync(HttpContext context) {
            // Save return url to state store — guard against open redirect when it gets used.
            var returnUrl = LocalRedirectGuard.SafeLocal(context.Request.Query[OAuth2Consts.Form_ReturnUrl].FirstOrDefault());
            var state = await _stateGenerator.GenerateAsync();
            await _stateStore.SaveAsync(state, returnUrl);

            // This change is to fix https://dw.xxx.com:10032/signout -> https://[dw.xxx.com:10032]/signout
            var callbackUri = new UriBuilder {
                Scheme = context.Request.Scheme,
                Host = context.Request.Host.Host,
                Port = context.Request.Host.Port ?? -1,
                Path = _options.SignOutCallbackPath
            };

            var targetUri = OAuth2Utils.AppendQuery(_options.EndSessionEndpoint, new[] {
                new KeyValuePair<string, string>(OAuth2Consts.Form_ClientID, _options.ClientID),
                new KeyValuePair<string, string>(OAuth2Consts.Form_RedirectUri, callbackUri.ToString()),
                new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
            });
            context.Response.Redirect(targetUri);
        }

        /// <summary>
        ///  handle sign out callback request
        /// </summary>
        protected virtual async Task HandleSignOutCallbackRequestAsync(HttpContext context) {
            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();

            // read return url from store
            var returnUrl = await _stateStore.GetThenRemoveAsync(state);
            if (!string.IsNullOrWhiteSpace(returnUrl)) {
                var endSessionID = context.Request.Query[OAuth2Consts.Form_EndSessionID].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(endSessionID)) {
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                    await context.Response.WriteAsync("missing es_id");
                    return;
                }

                var tokenDTO = await _tokenDTOStore.GetTokenDTOAsync();
                if (tokenDTO != null) {
                    var httpClient = _httpClientFactory.CreateClient();
                    var resp = await httpClient.PostAsync(_options.EndSessionEndpoint, new FormUrlEncodedContent(new KeyValuePair<string, string>[] {
                        new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_EndSessionID, endSessionID),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_ClientID, _options.ClientID),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_ClientSecret, _options.ClientSecret),
                        new KeyValuePair<string, string>(OAuth2Consts.Form_RefreshToken, tokenDTO.RefreshToken),
                    }));
                    if (!resp.IsSuccessStatusCode) {
                        var body = await resp.Content.ReadAsStringAsync();
                        _logger.LogWarning("Post end session request failed [{0}]:\n{1}", resp.StatusCode, body);
                    }
                }

                // sign out & redirect to return url
                await context.OAuth2SignOutAsync();
                // Guard against open redirect — returnUrl is user-supplied at /signout entry.
                context.Response.Redirect(LocalRedirectGuard.SafeLocal(returnUrl));
                return;
            }

            context.Response.StatusCode = (int)HttpStatusCode.NotFound;
        }

        protected virtual async Task HandleSignInRequestAsync(HttpContext context) {
            // Guard against open redirect — returnUrl is user-supplied; only allow local paths.
            var returnUrl = LocalRedirectGuard.SafeLocal(context.Request.Query["returnUrl"]);
            var t = context.Request.Query["t"];
            var authProps = new AuthenticationProperties();
            if (!string.IsNullOrWhiteSpace(t)) {
                authProps.SetParameter("t", t); // Set login token: {1BC05F9A-1971-418B-ABA7-6C623C008D85}
            }
            authProps.RedirectUri = returnUrl;
            await context.ChallengeAsync(OAuthDefaults.DisplayName, authProps);
        }
    }
}
