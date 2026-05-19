using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using OAuth2NetCore.Store;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace OAuth2NetCore.Host {
    internal class HttpContextTokenStore : ITokenStore {
        private readonly ILogger<HttpContextTokenStore> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ISecureDataFormat<Model.Token> _tokenDTOProector;
        private readonly ClientOptions _clientOptions;

        public HttpContextTokenStore(IHttpContextAccessor httpContextAccessor, ISecureDataFormat<Model.Token> tokenDTOProector, ClientOptions clientOptions, ILogger<HttpContextTokenStore> logger) {
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
            _tokenDTOProector = tokenDTOProector;
            _clientOptions = clientOptions;
        }

        public Task<JsonWebToken> SaveTokenDTOAsync(string json) {
            if (_httpContextAccessor.HttpContext != null) {
                var tokenDTO = JsonSerializer.Deserialize<Model.Token>(json);
                return SaveTokenDTOAsync(tokenDTO);
            }

            _logger.LogWarning($"{nameof(_httpContextAccessor)}.{_httpContextAccessor.HttpContext} is null");
            return Task.FromResult<JsonWebToken>(null);
        }

        public Task<JsonWebToken> SaveTokenDTOAsync(Model.Token tokenDTO) {
            if (_httpContextAccessor.HttpContext != null) {
                var cookieOptions = new CookieOptions {
                    SameSite = _clientOptions.CookieSameSite,    // RL {3A012FF7-DB5F-4688-8575-B499F51FF4A5}
                    Secure = true,
                    HttpOnly = true,
                };

                var jwt = tokenDTO.GetJwt();
                if (jwt.TryGetPayloadValue<long>(OAuth2Consts.Claim_RefreshTokenExpire, out var rexp)) {
                    cookieOptions.Expires = DateTimeOffset.FromUnixTimeSeconds(rexp);
                }

                _httpContextAccessor.HttpContext.Response.Cookies.Append(OAuth2Consts.Cookie_TokenDTO, _tokenDTOProector.Protect(tokenDTO), cookieOptions);
                return Task.FromResult(jwt);
            }

            _logger.LogWarning($"{nameof(_httpContextAccessor)}.{_httpContextAccessor.HttpContext} is null");
            return Task.FromResult<JsonWebToken>(null);
        }

        public Task<Model.Token> GetTokenDTOAsync() {
            if (_httpContextAccessor.HttpContext != null) {
                var protectedText = _httpContextAccessor.HttpContext.Request.Cookies[OAuth2Consts.Cookie_TokenDTO];
                if (string.IsNullOrWhiteSpace(protectedText))
                    return Task.FromResult<Model.Token>(null);

                var tokenDTO = _tokenDTOProector.Unprotect(protectedText);

                return Task.FromResult(tokenDTO);
            }

            _logger.LogWarning($"{nameof(_httpContextAccessor)}.{_httpContextAccessor.HttpContext} is null");
            return Task.FromResult<Model.Token>(null);
        }
    }
}
