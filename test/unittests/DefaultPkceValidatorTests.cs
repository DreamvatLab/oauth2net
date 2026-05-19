using NUnit.Framework;
using OAuth2NetCore;
using OAuth2NetCore.Security;

namespace UnitTests
{
    [TestFixture]
    public class DefaultPkceValidatorTests
    {
        private DefaultPkceValidator _sut;

        [SetUp]
        public void SetUp() => _sut = new DefaultPkceValidator();

        [Test]
        public void Plain_Match_ReturnsTrue()
        {
            var ok = _sut.Verify("abc123", "abc123", OAuth2Consts.Pkce_Plain);
            Assert.That(ok, Is.True);
        }

        [Test]
        public void Plain_Mismatch_ReturnsFalse()
        {
            var ok = _sut.Verify("abc123", "xyz999", OAuth2Consts.Pkce_Plain);
            Assert.That(ok, Is.False);
        }

        [Test]
        public void S256_Match_ReturnsTrue()
        {
            const string verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

            var ok = _sut.Verify(verifier, challenge, OAuth2Consts.Pkce_S256);

            Assert.That(ok, Is.True);
        }

        [Test]
        public void S256_Mismatch_ReturnsFalse()
        {
            var ok = _sut.Verify("verifier-A", "not-the-real-challenge", OAuth2Consts.Pkce_S256);
            Assert.That(ok, Is.False);
        }

        [Test]
        public void UnknownMethod_ReturnsFalse()
        {
            var ok = _sut.Verify("anything", "anything", "MD5");
            Assert.That(ok, Is.False);
        }

        [Test]
        public void NullMethod_ReturnsFalse()
        {
            var ok = _sut.Verify("anything", "anything", null);
            Assert.That(ok, Is.False);
        }
    }
}
