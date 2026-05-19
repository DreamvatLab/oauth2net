using NUnit.Framework;
using OAuth2NetCore.Host;

namespace UnitTests
{
    [TestFixture]
    public class LocalRedirectGuardTests
    {
        // Regression for C-5 — must reject anything that could leave the local origin.

        [Test]
        public void Null_FallsBackToRoot() =>
            Assert.That(LocalRedirectGuard.SafeLocal(null), Is.EqualTo("/"));

        [Test]
        public void Empty_FallsBackToRoot() =>
            Assert.That(LocalRedirectGuard.SafeLocal(string.Empty), Is.EqualTo("/"));

        [Test]
        public void SimpleLocalPath_IsPreserved() =>
            Assert.That(LocalRedirectGuard.SafeLocal("/dashboard"), Is.EqualTo("/dashboard"));

        [Test]
        public void LocalPathWithQuery_IsPreserved() =>
            Assert.That(LocalRedirectGuard.SafeLocal("/dashboard?tab=settings"), Is.EqualTo("/dashboard?tab=settings"));

        [Test]
        public void AbsoluteHttpUrl_IsRejected() =>
            Assert.That(LocalRedirectGuard.SafeLocal("http://evil.com/phish"), Is.EqualTo("/"));

        [Test]
        public void AbsoluteHttpsUrl_IsRejected() =>
            Assert.That(LocalRedirectGuard.SafeLocal("https://evil.com/phish"), Is.EqualTo("/"));

        [Test]
        public void ProtocolRelativeForwardSlash_IsRejected()
        {
            // "//evil.com" reads as protocol-relative to the user's browser.
            Assert.That(LocalRedirectGuard.SafeLocal("//evil.com/phish"), Is.EqualTo("/"));
        }

        [Test]
        public void ProtocolRelativeBackSlash_IsRejected()
        {
            // Some browsers normalize "/\evil.com" the same way as "//evil.com".
            Assert.That(LocalRedirectGuard.SafeLocal("/\\evil.com/phish"), Is.EqualTo("/"));
        }

        [Test]
        public void RelativePathWithoutLeadingSlash_IsRejected()
        {
            // "javascript:..." or other schemes start without "/".
            Assert.That(LocalRedirectGuard.SafeLocal("javascript:alert(1)"), Is.EqualTo("/"));
        }

        [Test]
        public void JustSlash_IsPreserved() =>
            Assert.That(LocalRedirectGuard.SafeLocal("/"), Is.EqualTo("/"));
    }
}
