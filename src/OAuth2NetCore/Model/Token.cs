using Microsoft.IdentityModel.JsonWebTokens;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OAuth2NetCore.Model {
    public class Token
    {
        private static readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        private readonly object _locker = new object();
        private volatile JsonWebToken _jwt;

        [JsonPropertyName(OAuth2Consts.Form_AccessToken)]
        public string AccessToken { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_RefreshToken)]
        public string RefreshToken { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_ExpiresIn)]
        public int AccessTokenExpiresIn { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_TokenType)]
        public string TokenType { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_Scope)]
        public string Scopes { get; set; }
        [JsonPropertyName(OAuth2Consts.Form_State)]
        public string State { get; set; }

        public JsonWebToken GetJwt()
        {
            if (string.IsNullOrWhiteSpace(AccessToken))
                return null;

            if (_jwt == null)
            {
                lock (_locker)
                {
                    if (_jwt == null)
                    {
                        _jwt = new JsonWebToken(AccessToken);
                    }
                }
            }

            return _jwt;
        }

        public string ToJsonString() => JsonSerializer.Serialize(this, _jsonOptions);
    }
}
