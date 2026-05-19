using System.Text.Json.Serialization;

namespace OAuth2NetCore.Model {
    public class RefreshTokenInfo
    {
        /// <summary>
        /// ClientID
        /// </summary>
        [JsonPropertyName("ci")]
        public string ClientID { get; set; }
        /// <summary>
        /// Scopes
        /// </summary>
        [JsonPropertyName("sc")]
        public string Scopes { get; set; }
        /// <summary>
        /// RedirectUri
        /// </summary>
        [JsonPropertyName("ru")]
        public string RedirectUri { get; set; }
        /// <summary>
        /// Username
        /// </summary>
        [JsonPropertyName("un")]
        public string UN { get; set; }
        /// <summary>
        /// CodeChanllenge
        /// </summary>
        [JsonPropertyName("cc")]
        public string cc { get; set; }
        /// <summary>
        /// CodeChanllengeMethod
        /// </summary>
        [JsonPropertyName("ccm")]
        public string ccm { get; set; }
    }
}
