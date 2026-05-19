using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography.X509Certificates;

namespace OAuth2NetCore.Security {
    public class X509JsonWebKeyProvider : IJsonWebKeyProvider {
        private static readonly object _locker = new object();
        private static volatile Model.JsonWebKey _jsonWebKey;

        private readonly X509Certificate2 _pfx;
        public string KeyType { get; }
        public string Use { get; }
        public string Algorithm { get; }

        public X509JsonWebKeyProvider(X509Certificate2 cert, string keyType = "RSA", string use = "sig", string algorithm = "PS256") {
            _pfx = cert;
            KeyType = keyType;
            Use = use;
            Algorithm = algorithm;
        }

        public Model.JsonWebKey GetJsonWebKey() {
            if (_jsonWebKey == null) {
                lock (_locker) {
                    if (_jsonWebKey == null) {
                        var keyHash = _pfx.GetCertHash();
                        var cert64 = Convert.ToBase64String(_pfx.RawData);
                        var kid = BitConverter.ToString(keyHash).Replace("-", string.Empty);
                        var thumbprint = Base64UrlEncoder.Encode(keyHash);

                        var publicKey = _pfx.GetRSAPublicKey();
                        var publicKeyParameters = publicKey.ExportParameters(false);
                        var exponent = Base64UrlEncoder.Encode(publicKeyParameters.Exponent);
                        var modulus = Base64UrlEncoder.Encode(publicKeyParameters.Modulus);

                        _jsonWebKey = new Model.JsonWebKey {
                            kty = KeyType,
                            use = Use,
                            alg = Algorithm,
                            kid = kid,
                            x5t = thumbprint,
                            e = exponent,
                            n = modulus,
                            x5c = new[] { cert64 },
                        };
                    }
                }
            }

            return _jsonWebKey;
        }
    }
}
