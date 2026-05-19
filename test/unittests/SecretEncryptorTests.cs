using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using OAuth2NetCore.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UnitTests
{
    [TestFixture]
    public class DefaultSecretEncryptorTests
    {
        [Test]
        public void Encrypt_IsPassthrough()
        {
            var sut = new DefaultSecretEncryptor();
            Assert.That(sut.Encrypt("hello"), Is.EqualTo("hello"));
        }

        [Test]
        public void Decrypt_IsPassthrough()
        {
            var sut = new DefaultSecretEncryptor();
            Assert.That(sut.Decrypt("hello"), Is.EqualTo("hello"));
        }

        [Test]
        public void TryDecrypt_ReturnsTrue_AndOutputsInput()
        {
            var sut = new DefaultSecretEncryptor();

            var ok = sut.TryDecrypt("hello", out var output);

            Assert.That(ok, Is.True);
            Assert.That(output, Is.EqualTo("hello"));
        }
    }

    [TestFixture]
    public class X509SecretEncryptorTests
    {
        private X509Certificate2 _cert;
        private X509SecretEncryptor _sut;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                "CN=oauth2net-unit-tests",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            // Self-signed, valid for one day around "now"
            _cert = req.CreateSelfSigned(
                System.DateTimeOffset.UtcNow.AddMinutes(-5),
                System.DateTimeOffset.UtcNow.AddDays(1));

            // CreateSelfSigned returns a cert tied to the RSA above; export+reimport so
            // the private key is owned by _cert (mirrors loading a real pfx).
            var pfxBytes = _cert.Export(X509ContentType.Pfx, "pwd");
            _cert.Dispose();
            _cert = X509CertificateLoader.LoadPkcs12(pfxBytes, "pwd");

            _sut = new X509SecretEncryptor(_cert);
        }

        [OneTimeTearDown]
        public void OneTimeTearDown() => _cert?.Dispose();

        [Test]
        public void Encrypt_Then_Decrypt_RoundTrips()
        {
            const string plaintext = "super-secret-value-42";

            var cipher = _sut.Encrypt(plaintext);
            var roundtrip = _sut.Decrypt(cipher);

            Assert.That(roundtrip, Is.EqualTo(plaintext));
        }

        [Test]
        public void Encrypt_ProducesCiphertext_DifferentFromInput()
        {
            const string plaintext = "hello";

            var cipher = _sut.Encrypt(plaintext);

            Assert.That(cipher, Is.Not.EqualTo(plaintext));
            // OAEP-SHA256 ciphertext is Base64Url-encoded — alphabet is [A-Za-z0-9_-].
            Assert.That(cipher, Does.Match("^[A-Za-z0-9_-]+$"));
        }

        [Test]
        public void Encrypt_IsNonDeterministic()
        {
            // OAEP includes a random seed; two encryptions of the same plaintext should
            // produce different ciphertexts.
            var a = _sut.Encrypt("same");
            var b = _sut.Encrypt("same");
            Assert.That(a, Is.Not.EqualTo(b));
        }

        // ---- C-4 algorithm lockdown ----

        [Test]
        public void Decrypt_RejectsCiphertextEncryptedWithPkcs1Padding()
        {
            // Regression for C-4 — if someone reverts the encryptor to PKCS#1 v1.5 padding,
            // OAEP-SHA256 Decrypt should NOT silently succeed on the old ciphertext.
            using var rsa = _cert.GetRSAPublicKey();
            var legacyCipher = rsa.Encrypt(Encoding.UTF8.GetBytes("payload"), RSAEncryptionPadding.Pkcs1);
            var legacyBase64Url = Base64UrlEncoder.Encode(legacyCipher);

            Assert.Throws<CryptographicException>(() => _sut.Decrypt(legacyBase64Url));
        }

        [Test]
        public void Decrypt_AcceptsCiphertextEncryptedWithOaepSha256()
        {
            // Positive control matching the negative test above — explicit OAEP-SHA256 cipher
            // from a side-channel encrypt must round-trip.
            using var rsa = _cert.GetRSAPublicKey();
            var cipher = rsa.Encrypt(Encoding.UTF8.GetBytes("payload"), RSAEncryptionPadding.OaepSHA256);
            var base64Url = Base64UrlEncoder.Encode(cipher);

            var plain = _sut.Decrypt(base64Url);

            Assert.That(plain, Is.EqualTo("payload"));
        }

        [Test]
        public void TryDecrypt_ValidCipher_ReturnsTrue()
        {
            var cipher = _sut.Encrypt("payload");

            var ok = _sut.TryDecrypt(cipher, out var output);

            Assert.That(ok, Is.True);
            Assert.That(output, Is.EqualTo("payload"));
        }

        [Test]
        public void TryDecrypt_InvalidCipher_ReturnsFalse_AndOutputsInput()
        {
            var ok = _sut.TryDecrypt("not-a-valid-cipher", out var output);

            Assert.That(ok, Is.False);
            Assert.That(output, Is.EqualTo("not-a-valid-cipher"));
        }
    }
}
