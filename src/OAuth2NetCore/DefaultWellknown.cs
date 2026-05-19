using OAuth2NetCore.Model;

namespace OAuth2NetCore {
    public class DefaultWellknown : IWellknown {
        public OpenIDConfig GetOpenIDCOnfig() {
            return null;
        }

        public JsonWebKey GetOpenIDJsonWebKey() {
            return null;
        }
    }
}