using System.Collections.Generic;

namespace OAuth2NetCore.Model {
    public interface IClient {
        string ID { get; set; }
        string Secret { get; set; }
        int AccessTokenExpireSeconds { get; set; }
        int RefreshTokenExpireSeconds { get; set; }
        int? Flags { get; set; }
        bool IsPublic { get; set; }
        IList<string> Grants { get; set; }
        IList<string> Audiences { get; set; }
        IList<string> Scopes { get; set; }
        IList<string> RedirectUris { get; set; }
    }
}
