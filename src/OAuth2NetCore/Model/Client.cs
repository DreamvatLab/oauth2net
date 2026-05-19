using System.Collections.Generic;

namespace OAuth2NetCore.Model {
    public class Client : IClient
    {
        public string ID { get; set; }
        public string Secret { get; set; }
        public int AccessTokenExpireSeconds { get; set; } = 3600;
        public int RefreshTokenExpireSeconds { get; set; } = 3600 * 2;
        public int? Flags { get; set; }
        public bool IsPublic { get; set; }
        public IList<string> Grants { get; set; }
        public IList<string> Audiences { get; set; }
        public IList<string> Scopes { get; set; }
        public IList<string> RedirectUris { get; set; }
    }

}
