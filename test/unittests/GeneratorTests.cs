using NUnit.Framework;
using OAuth2NetCore.Security;
using OAuth2NetCore.Token;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestFixture]
    public class DefaultStateGeneratorTests
    {
        [Test]
        public async Task GenerateAsync_Returns_32CharHexString()
        {
            var sut = new DefaultStateGenerator();

            var s = await sut.GenerateAsync();

            // Guid "n" format: 32 lowercase hex chars
            Assert.That(s, Is.Not.Null);
            Assert.That(s.Length, Is.EqualTo(32));
            Assert.That(s, Does.Match("^[0-9a-f]{32}$"));
        }

        [Test]
        public async Task GenerateAsync_Returns_UniqueValues()
        {
            var sut = new DefaultStateGenerator();
            var seen = new HashSet<string>();

            for (int i = 0; i < 100; i++)
            {
                seen.Add(await sut.GenerateAsync());
            }

            Assert.That(seen.Count, Is.EqualTo(100));
        }
    }

    [TestFixture]
    public class DefaultAuthCodeGeneratorTests
    {
        [Test]
        public async Task GenerateAsync_Returns_NonEmpty_Base64Url()
        {
            var sut = new DefaultAuthCodeGenerator();

            var code = await sut.GenerateAsync();

            Assert.That(code, Is.Not.Null.And.Not.Empty);
            // Base64Url alphabet only (no padding, no +/)
            Assert.That(code, Does.Match("^[A-Za-z0-9_-]+$"));
        }

        [Test]
        public async Task GenerateAsync_Returns_UniqueValues()
        {
            var sut = new DefaultAuthCodeGenerator();
            var seen = new HashSet<string>();

            for (int i = 0; i < 100; i++)
            {
                seen.Add(await sut.GenerateAsync());
            }

            Assert.That(seen.Count, Is.EqualTo(100));
        }

        [Test]
        public async Task GenerateAsync_HasEnoughEntropy()
        {
            // 64 bytes => 86 base64url chars (no padding)
            var sut = new DefaultAuthCodeGenerator();

            var code = await sut.GenerateAsync();

            Assert.That(code.Length, Is.GreaterThanOrEqualTo(80));
        }
    }
}
