using OAuth2NetCore.Model;

namespace OAuth2NetCore.Security {
    public interface IJsonWebKeyProvider {
        JsonWebKey GetJsonWebKey();
    }
}
