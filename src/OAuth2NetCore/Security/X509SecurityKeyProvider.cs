using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace OAuth2NetCore.Security {
    public class X509SecurityKeyProvider : ISecurityKeyProvider {
        private readonly X509SecurityKey _securityKey;

        // Note: callers on .NET 9+ should prefer the X509Certificate2 overload with a certificate
        // loaded via X509CertificateLoader.LoadPkcs12FromFile (stricter Pkcs12LoaderLimits).
        public X509SecurityKeyProvider(string pfxPath, string pfxPass) : this(new X509Certificate2(pfxPath, pfxPass)) {
        }

        public X509SecurityKeyProvider(X509Certificate2 cert) {
            _securityKey = new X509SecurityKey(cert);
        }

        public SecurityKey GetSecurityKey() => _securityKey;
    }
}
