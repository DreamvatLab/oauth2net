using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace OAuth2NetCore.Security {
    /// <summary>
    /// RSA-OAEP-SHA256 secret encryptor. Plaintext length is bounded by the certificate's key size
    /// (e.g. 190 bytes for a 2048-bit RSA key with OAEP-SHA256).
    /// </summary>
    public class X509SecretEncryptor : ISecretEncryptor, IDisposable
    {
        private readonly X509Certificate2 _x509Cert;
        private readonly RSA _publicRsaProvider;
        private readonly RSA _privateRsaProvider;
        private bool _disposed;

        public X509SecretEncryptor(string pfxPath, string pfxPassword)
            : this(new X509Certificate2(pfxPath, pfxPassword))
        {
            // Note: this convenience overload exists for back-compat. Callers on .NET 9+ should
            // prefer the X509Certificate2 overload with a certificate loaded via
            // X509CertificateLoader.LoadPkcs12FromFile, which applies stricter Pkcs12LoaderLimits.
        }

        public X509SecretEncryptor(X509Certificate2 cert)
        {
            _x509Cert = cert;
            _publicRsaProvider = _x509Cert.GetRSAPublicKey();
            _privateRsaProvider = _x509Cert.GetRSAPrivateKey();
        }

        public string Encrypt(string intput)
        {
            var plainBytes = Encoding.UTF8.GetBytes(intput);
            // OAEP-SHA256: PKCS#1 v1.5 (the previous default) is vulnerable to Bleichenbacher's attack.
            var encryptedBytes = _publicRsaProvider.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);

            return Base64UrlEncoder.Encode(encryptedBytes);
        }

        public string Decrypt(string intput)
        {
            var encryptedBytes = Base64UrlEncoder.DecodeBytes(intput);

            var plainBytes = _privateRsaProvider.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);

            var plainText = Encoding.UTF8.GetString(plainBytes);
            return plainText;
        }

        public bool TryDecrypt(string intput, out string output)
        {
            try
            {
                output = Decrypt(intput);
                return true;
            }
            catch
            {
                output = intput;
                return false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _publicRsaProvider?.Dispose();
            _privateRsaProvider?.Dispose();
            _x509Cert?.Dispose();
        }
    }
}
