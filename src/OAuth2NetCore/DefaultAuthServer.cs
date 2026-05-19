using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore {
    public class DefaultAuthServer : IAuthServer {
        private readonly IClientValidator _clientValidator;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly IAuthCodeStore _authCodeStore;
        private readonly IRefreshTokenInfoStore _tokenStore;
        private readonly IStateStore _stateStore;
        private readonly IAuthCodeGenerator _authCodeGenerator;
        private readonly IResourceOwnerValidator _resourceOwnerValidator;
        private readonly ILogger<DefaultAuthServer> _logger;
        private readonly IPkceValidator _pkceValidator;
        private readonly IWellknown _wellknown;

        //private readonly IConfiguration _configuration;
        public RequestDelegate TokenRequestHandler { get; }
        public RequestDelegate AuthorizeRequestHandler { get; }
        public RequestDelegate EndSessionRequestHandler { get; }
        public RequestDelegate ClearTokenRequestHandler { get; }
        public RequestDelegate OpenIDConfigRequestHandler { get; }
        public RequestDelegate OpenIDJwksRequestHandler { get; }

        public AuthServerOptions AuthServerOptions { get; }

        public DefaultAuthServer(
              IClientValidator clientValidator
            , ITokenGenerator tokenGenerator
            , IAuthCodeStore authCodeStore
            , IRefreshTokenInfoStore tokenStore
            , IStateStore stateStore
            , IAuthCodeGenerator authCodeGenerator
            , IResourceOwnerValidator resourceOwnerValidator
            , ILogger<DefaultAuthServer> logger
            , AuthServerOptions options
            , IPkceValidator pkceValidator
            , IWellknown wellknown
        //, IConfiguration configuration
        ) {
            _clientValidator = clientValidator;
            _tokenGenerator = tokenGenerator;
            _resourceOwnerValidator = resourceOwnerValidator;
            _logger = logger;
            _authCodeStore = authCodeStore;
            _tokenStore = tokenStore;
            _stateStore = stateStore;
            _authCodeGenerator = authCodeGenerator;
            _pkceValidator = pkceValidator;
            //_configuration = configuration;
            _wellknown = wellknown;

            TokenRequestHandler = HandleTokenRequestAsync;
            AuthorizeRequestHandler = HandleAuthorizeRequestAsync;
            EndSessionRequestHandler = HandleEndSessionRequestAsync;
            ClearTokenRequestHandler = HandleClearTokenRequestAsync;
            OpenIDConfigRequestHandler = HandleOpenIDConfigRequestAsync;
            OpenIDJwksRequestHandler = HandleOpenIDJwksRequestAsync;
            AuthServerOptions = options;
        }

        /// <summary>
        /// handle authorize request
        /// </summary>
        protected virtual async Task HandleAuthorizeRequestAsync(HttpContext context) {
            var respType = context.Request.Query[OAuth2Consts.Form_ResponseType].FirstOrDefault();
            var clientID = context.Request.Query[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var redirectURI = context.Request.Query[OAuth2Consts.Form_RedirectUri].FirstOrDefault();
            var scopesStr = context.Request.Query[OAuth2Consts.Form_Scope].FirstOrDefault();
            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();

            // RFC 6749 §10.12: state is the client-side CSRF defense. Warn if missing.
            if (string.IsNullOrWhiteSpace(state)) {
                _logger.LogWarning("/authorize request missing 'state' parameter (client_id={ClientID})", clientID);
            }

            // verify client
            var clientVerifyResult = await _clientValidator.VerifyClientAsync(
                  clientID: clientID
                , responseType: respType
                , redirectURI: redirectURI
                , scopesStr: scopesStr
                , state: state
            );
            if (!clientVerifyResult.IsSuccess) {
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, clientVerifyResult.MsgCode, clientVerifyResult.MsgCodeDescription);
                return;
            }

            if (!context.User.Identity.IsAuthenticated) {
                // user not login, redirect to login page
                await context.ChallengeAsync();
                return;
            }

            switch (respType) {
                case OAuth2Consts.ResponseType_Code:
                    // authorization code
                    await AuthorizationCodeRequestHandler(context, clientVerifyResult.Result, scopesStr, redirectURI, state);
                    break;
                case OAuth2Consts.ResponseType_Token:
                    // implicit
                    await ImplicitTokenRequestHandler(context, clientVerifyResult.Result, scopesStr, redirectURI, state);
                    break;
                default:
                    await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_unsupported_response_type);
                    break;
            }
        }

        //private string GetSurferID(HttpContext context)
        //{
        //    var surferID = context.Request.Cookies[OAuth2Consts.Cookie_Surfer];
        //    if (string.IsNullOrWhiteSpace(surferID))
        //    {
        //        surferID = Guid.NewGuid().ToString("n");
        //        // issue a permenant cookie
        //        context.Response.Cookies.Append(OAuth2Consts.Cookie_Surfer, surferID, new CookieOptions
        //        {
        //            Expires = DateTimeOffset.UtcNow.AddYears(100)
        //        });
        //    }
        //    return surferID;
        //}

        /// <summary>
        /// handle authorization code request
        /// </summary>
        protected virtual async Task AuthorizationCodeRequestHandler(HttpContext context, IClient client, string scopesStr, string redirectURI, string state) {
            string code;
            string codeChanllenge = null;
            string codeChanllengeMethod = null;

            if (AuthServerOptions.PKCERequired) {
                codeChanllenge = context.Request.Query[OAuth2Consts.Form_CodeChallenge].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(codeChanllenge)) {
                    await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, "code_challenge is required.");
                    return;
                }

                codeChanllengeMethod = context.Request.Query[OAuth2Consts.Form_CodeChallengeMethod].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(codeChanllengeMethod)) {
                    // Secure default: require S256 when method is omitted (OAuth 2.1 / BCP).
                    codeChanllengeMethod = OAuth2Consts.Pkce_S256;
                } else if (codeChanllengeMethod == OAuth2Consts.Pkce_Plain) {
                    if (!AuthServerOptions.AllowPlainPkce) {
                        await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, "code_challenge_method 'plain' is not allowed, use 'S256'.");
                        return;
                    }
                } else if (codeChanllengeMethod != OAuth2Consts.Pkce_S256) {
                    await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, "transform algorithm not supported");
                    return;
                }
            }

            code = await _authCodeGenerator.GenerateAsync();
            await _authCodeStore.SaveAsync(code,
                new RefreshTokenInfo {
                    ClientID = client.ID,
                    Scopes = scopesStr,
                    RedirectUri = redirectURI,
                    UN = context.User.Identity.Name,
                    cc = codeChanllenge,
                    ccm = codeChanllengeMethod,
                }
            );

            // Per RFC 6749 §4.1.2 the authorization response carries only `code` and `state`.
            // (The code_challenge stays server-side; echoing it serves no purpose and leaks via logs/Referer.)
            var redirect = OAuth2Utils.AppendQuery(redirectURI, new[] {
                new KeyValuePair<string, string>(OAuth2Consts.Form_Code, code),
                new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
            });
            context.Response.Redirect(redirect);
        }

        /// <summary>
        /// handle implicit token request
        /// </summary>
        protected virtual async Task ImplicitTokenRequestHandler(HttpContext context, IClient client, string scopesStr, string redirectURI, string state) {
            var token = await _tokenGenerator.GenerateAccessTokenAsync(
                context: context
                , grantType: GrantType.Implicit
                , client: client
                , scopes: scopesStr.Split(OAuth2Consts.Seperator_Scope)
                , username: context.User.Identity.Name
            );

            // RFC 6749 §4.2.2: implicit grant MUST return tokens in the URL fragment so they
            // never reach server access logs or the Referer header.
            var redirect = OAuth2Utils.AppendFragment(redirectURI, new[] {
                new KeyValuePair<string, string>(OAuth2Consts.Form_AccessToken, token),
                new KeyValuePair<string, string>(OAuth2Consts.Form_TokenType, OAuth2Consts.Token_Type_Bearer),
                new KeyValuePair<string, string>(OAuth2Consts.Form_ExpiresIn, client.AccessTokenExpireSeconds.ToString()),
                new KeyValuePair<string, string>(OAuth2Consts.Form_Scope, scopesStr),
                new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
            });
            context.Response.Redirect(redirect);
        }

        /// <summary>
        /// handle token reqeust
        /// </summary>
        protected virtual async Task HandleTokenRequestAsync(HttpContext context) {
            // get parametes from request
            var grantTypeStr = context.Request.Form[OAuth2Consts.Form_GrantType].FirstOrDefault();
            var scopesStr = context.Request.Form[OAuth2Consts.Form_Scope].FirstOrDefault();

            var clientCredentialsResult = _clientValidator.ExractClientCredentials(context);
            if (!clientCredentialsResult.IsSuccess) {
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, clientCredentialsResult.MsgCode, clientCredentialsResult.MsgCodeDescription);
                return;
            }

            // verify client
            MessageResult<IClient> clientVerifyResult;
            if (grantTypeStr == OAuth2Consts.GrantType_AuthorizationCode) {
                // auth code grant doesn't post scopes 
                clientVerifyResult = await _clientValidator.VerifyClientAsync(clientCredentialsResult.Result, grantTypeStr);
            } else {
                // other scopes must post scopes
                clientVerifyResult = await _clientValidator.VerifyClientAsync(clientCredentialsResult.Result, grantTypeStr, scopesStr);
            }

            if (!clientVerifyResult.IsSuccess) {
                var httpStatusCode = clientVerifyResult.MsgCode == OAuth2Consts.Err_invalid_client ? HttpStatusCode.Unauthorized : HttpStatusCode.BadRequest;
                await ErrorHandler(context.Response, httpStatusCode, clientVerifyResult.MsgCode, clientVerifyResult.MsgCodeDescription);
                return;
            }

            switch (grantTypeStr) {
                case OAuth2Consts.GrantType_Client:
                    await HandleClientCredentialsTokenRequestAsync(context, clientVerifyResult.Result, scopesStr);
                    break;
                case OAuth2Consts.GrantType_AuthorizationCode:
                    await HandleAuthorizationCodeTokenRequestAsync(context, clientVerifyResult.Result);
                    break;
                case OAuth2Consts.GrantType_ResourceOwner:
                    await HandleResourceOwnerTokenRequestAsync(context, clientVerifyResult.Result, scopesStr);
                    break;
                case OAuth2Consts.GrantType_RefreshToken:
                    await HandleRefreshTokenRequestAsync(context, clientVerifyResult.Result);
                    break;
                default:
                    await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_unsupported_grant_type);
                    break;
            }
        }

        /// <summary>
        /// handle end session request
        /// </summary>
        protected virtual async Task HandleEndSessionRequestAsync(HttpContext context) {
            var clientID = context.Request.Query[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var redirectURI = context.Request.Query[OAuth2Consts.Form_RedirectUri].FirstOrDefault();

            var mr = await _clientValidator.VerifyClientAsync(clientID, redirectURI);
            if (!mr.IsSuccess) {
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, mr.MsgCode, mr.MsgCodeDescription);
                return;
            }

            var state = context.Request.Query[OAuth2Consts.Form_State].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(state)) {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync("missing state");
                return;
            }

            var endSessionID = Guid.NewGuid().ToString("n");
            await _stateStore.SaveAsync(clientID + ":" + endSessionID, state);

            // sign out
            await context.OAuth2SignOutAsync();

            var redirect = OAuth2Utils.AppendQuery(redirectURI, new[] {
                new KeyValuePair<string, string>(OAuth2Consts.Form_State, state),
                new KeyValuePair<string, string>(OAuth2Consts.Form_EndSessionID, endSessionID),
            });
            context.Response.Redirect(redirect);
        }

        /// <summary>
        /// handle clear token request
        /// </summary>
        protected virtual async Task HandleClearTokenRequestAsync(HttpContext context) {
            var state = context.Request.Form[OAuth2Consts.Form_State].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(state)) {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync("missing state");
                return;
            }

            var clientID = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var clientSecret = context.Request.Form[OAuth2Consts.Form_ClientSecret].FirstOrDefault();
            var mr = await _clientValidator.VerifyClientAsync(new NetworkCredential(clientID, clientSecret));
            if (!mr.IsSuccess) {
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, mr.MsgCode, mr.MsgCodeDescription);
                return;
            }

            var oldRefreshToken = context.Request.Form[OAuth2Consts.Form_RefreshToken].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(oldRefreshToken)) {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync("missing refresh token");
                return;
            }

            var endSessionID = context.Request.Form[OAuth2Consts.Form_EndSessionID].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(endSessionID)) {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync("missing es_id");
                return;
            }

            // verify state
            var storedState = await _stateStore.GetThenRemoveAsync(clientID + ":" + endSessionID);
            if (storedState != state) {
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                await context.Response.WriteAsync("invalid state");
                return;
            }

            await _tokenStore.RemoveRefreshTokenAsync(oldRefreshToken);
            context.Response.StatusCode = (int)HttpStatusCode.OK;
        }

        /// <summary>
        /// handle client credentials token request
        /// </summary>
        protected virtual async Task HandleClientCredentialsTokenRequestAsync(HttpContext context, IClient client, string scopesStr) {
            // issue token directly
            var token = await _tokenGenerator.GenerateAccessTokenAsync(
                                context: context
                              , grantType: GrantType.ClientCredentials
                              , client: client
                              , scopes: scopesStr.Split(OAuth2Consts.Seperator_Scope)
                              , username: client.ID
                          );

            await WriteTokenAsync(context.Response, token, scopesStr, client);
        }

        /// <summary>
        /// handle authorization code token request
        /// </summary>
        protected virtual async Task HandleAuthorizationCodeTokenRequestAsync(HttpContext context, IClient client) {
            // exchange token by using auhorization code
            var code = context.Request.Form[OAuth2Consts.Form_Code].FirstOrDefault();
            var clientID = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();
            var redirectURI = context.Request.Form[OAuth2Consts.Form_RedirectUri].FirstOrDefault();


            var tokenRequestInfo = await _authCodeStore.GetThenRemoveAsync(code);
            if (null == tokenRequestInfo) {
                var errDetail = "invalid authorization code";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (client.ID != clientID || clientID != tokenRequestInfo.ClientID) {
                var errDetail = $"client id doesn't match, original: '{tokenRequestInfo.ClientID}', current: '{client.ID}'";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (redirectURI != tokenRequestInfo.RedirectUri) {
                var errDetail = $"redirect uri doesn't match, original: '{tokenRequestInfo.RedirectUri}', current: '{redirectURI}'";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            // pkce check
            if (!AuthServerOptions.PKCERequired) {
                // issue token
                await IssueTokenByRequestInfoAsync(context, GrantType.AuthorizationCode, client, tokenRequestInfo);
                return;
            }

            var codeVierifier = context.Request.Form[OAuth2Consts.Form_CodeVerifier].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(codeVierifier)) {
                // client didn't provide code verifier, write error
                var errDetail = "code verifier is missing";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            if (!_pkceValidator.Verify(codeVierifier, tokenRequestInfo.cc, tokenRequestInfo.ccm)) {
                var errDetail = "code verifier is invalid";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, errDetail);
                return;
            }

            // clear old refresh token
            var oldRefreshToken = context.Request.Form[OAuth2Consts.Form_RefreshToken].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(oldRefreshToken)) {
                await _tokenStore.RemoveRefreshTokenAsync(oldRefreshToken);
            }

            // issue token
            await IssueTokenByRequestInfoAsync(context, GrantType.AuthorizationCode, client, tokenRequestInfo);
        }

        /// <summary>
        /// handle resource owner token request
        /// </summary>
        protected virtual async Task HandleResourceOwnerTokenRequestAsync(HttpContext context, IClient client, string scopesStr) {
            // verify username & password
            var username = context.Request.Form[OAuth2Consts.Form_Username].FirstOrDefault();
            var password = context.Request.Form[OAuth2Consts.Form_Password].FirstOrDefault();
            var success = await _resourceOwnerValidator.VerifyAsync(username, password);
            if (success) {// pass, issue token
                await IssueTokenByRequestInfoAsync(context, GrantType.ResourceOwner, client, new RefreshTokenInfo {
                    ClientID = client.ID,
                    Scopes = scopesStr,
                    UN = username,
                });
            } else {
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, "username password doesn't match");
            }
        }

        /// <summary>
        /// handle refresh token request
        /// </summary>
        private async Task HandleRefreshTokenRequestAsync(HttpContext context, IClient client) {
            var refreshToken = context.Request.Form[OAuth2Consts.Form_RefreshToken].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(refreshToken)) {
                var errDetail = "refresh token is missing";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            //var surferID = GetSurferID(context);
            var tokenRequestInfo = await _tokenStore.GetThenRemoveTokenInfoAsync(refreshToken);
            if (null == tokenRequestInfo) {
                var errDetail = "refresh token is invalid or expired or revoked";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_grant, errDetail);
                return;
            }

            if (client.ID != tokenRequestInfo.ClientID) {
                var errDetail = $"client id doesn't match, original: '{tokenRequestInfo.ClientID}', current: '{client.ID}'";
                await ErrorHandler(context.Response, HttpStatusCode.BadRequest, OAuth2Consts.Err_invalid_request, errDetail);
                return;
            }

            // issue token
            await IssueTokenByRequestInfoAsync(context, GrantType.RefreshToken, client, tokenRequestInfo);
        }

        /// <summary>
        /// issue access token and refresh token
        /// </summary>
        protected virtual async Task IssueTokenByRequestInfoAsync(HttpContext context, GrantType grantType, IClient client, RefreshTokenInfo tokenRequestInfo) {
            // issue token
            var token = await _tokenGenerator.GenerateAccessTokenAsync(
                   context: context
                 , grantType: grantType
                 , client: client
                 , scopes: tokenRequestInfo.Scopes.Split(OAuth2Consts.Seperator_Scope)
                 , username: tokenRequestInfo.UN
             );

            if (client.Grants.Contains(OAuth2Consts.GrantType_RefreshToken)) {// allowed to use refresh token
                //var surferID = GetSurferID(context);
                var refreshToken = await _tokenGenerator.GenerateRefreshTokenAsync();
                await _tokenStore.SaveRefreshTokenAsync(refreshToken, tokenRequestInfo, client.RefreshTokenExpireSeconds);
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes, client, refreshToken);
            } else {// not allowed to use refresh token
                await WriteTokenAsync(context.Response, token, tokenRequestInfo.Scopes, client);

            }
        }

        /// <summary>
        /// write token to browser
        /// </summary>
        protected virtual async Task WriteTokenAsync(HttpResponse response, string token, string scopes, IClient client, string refreshToken = null) {
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Append(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Append(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);

            if (string.IsNullOrWhiteSpace(refreshToken)) {
                await response.WriteAsync(GenereateTokenJson(token, scopes, client));
            } else {
                await response.WriteAsync(GenereateTokenJson(token, refreshToken, scopes, client));
            }
        }

        /// <summary>
        /// write error to browser
        /// </summary>
        protected virtual async Task ErrorHandler(HttpResponse response, HttpStatusCode statusCode, string error, string errorDescription = null) {
            errorDescription = errorDescription ?? error;

            _logger.LogWarning(errorDescription);

            response.StatusCode = (int)statusCode;
            response.ContentType = OAuth2Consts.ContentType_Json;
            response.Headers.Append(OAuth2Consts.Header_CacheControl, OAuth2Consts.Header_CacheControl_Value);
            response.Headers.Append(OAuth2Consts.Header_Pragma, OAuth2Consts.Header_Pragma_Value);
            // Use STJ to ensure quotes / control chars in errorDescription cannot break the JSON.
            var json = JsonSerializer.Serialize(new { error, error_description = errorDescription });
            await response.WriteAsync(json);
        }

        /// <summary>
        /// generate token json 
        /// </summary>
        protected virtual string GenereateTokenJson(string token, string scopes, IClient client) {
            var tokenDTO = new Model.Token {
                TokenType = OAuth2Consts.Token_Type_Bearer,
                AccessToken = token,
                AccessTokenExpiresIn = client.AccessTokenExpireSeconds,
                Scopes = scopes,
            };
            return tokenDTO.ToJsonString();
        }

        /// <summary>
        /// generate token json (with refresh token)
        /// </summary>
        protected virtual string GenereateTokenJson(string token, string refreshToken, string scopes, IClient client) {
            var tokenDTO = new Model.Token {
                TokenType = OAuth2Consts.Token_Type_Bearer,
                AccessToken = token,
                RefreshToken = refreshToken,
                AccessTokenExpiresIn = client.AccessTokenExpireSeconds,
                Scopes = scopes,
            };
            return tokenDTO.ToJsonString();
        }

        /// <summary>
        /// handle get wellknown configuration request
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task HandleOpenIDConfigRequestAsync(HttpContext context) {
            var openIDConfig = _wellknown.GetOpenIDCOnfig();
            if (openIDConfig == null) {
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            context.Response.ContentType = OAuth2Consts.ContentType_Json;
            var json = JsonSerializer.Serialize(openIDConfig, _wellknownJsonOptions);
            await context.Response.WriteAsync(json);
        }

        /// <summary>
        /// Handle
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private async Task HandleOpenIDJwksRequestAsync(HttpContext context) {
            var jwk = _wellknown.GetOpenIDJsonWebKey();
            if (jwk == null) {
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            context.Response.ContentType = OAuth2Consts.ContentType_Json;
            var json = JsonSerializer.Serialize(new { keys = new[] { jwk } }, _wellknownJsonOptions);
            await context.Response.WriteAsync(json);
        }

        private static readonly JsonSerializerOptions _wellknownJsonOptions = new JsonSerializerOptions {
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        };
    }
}
