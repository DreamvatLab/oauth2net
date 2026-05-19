using OAuth2NetCore.Model;

namespace OAuth2NetCore {
    public interface IWellknown {
        OpenIDConfig GetOpenIDCOnfig();

        JsonWebKey GetOpenIDJsonWebKey();
    }
}