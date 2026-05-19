using Microsoft.IdentityModel.Tokens;

namespace OAuth2NetCore.Security {
    public interface ISecurityKeyProvider {
        SecurityKey GetSecurityKey();
    }
}
