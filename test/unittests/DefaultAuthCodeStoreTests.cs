using NUnit.Framework;
using OAuth2NetCore.Model;
using OAuth2NetCore.Store;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestFixture]
    public class DefaultAuthCodeStoreTests
    {
        [Test]
        public async Task SaveThenGet_ReturnsSavedValue()
        {
            var sut = new DefaultAuthCodeStore();
            var info = new RefreshTokenInfo { ClientID = "c1", Scopes = "read", UN = "alice" };

            await sut.SaveAsync("code-1", info);
            var loaded = await sut.GetThenRemoveAsync("code-1");

            Assert.That(loaded, Is.Not.Null);
            Assert.That(loaded.ClientID, Is.EqualTo("c1"));
            Assert.That(loaded.Scopes, Is.EqualTo("read"));
            Assert.That(loaded.UN, Is.EqualTo("alice"));
        }

        [Test]
        public async Task GetThenRemove_IsSingleUse()
        {
            var sut = new DefaultAuthCodeStore();
            await sut.SaveAsync("code-2", new RefreshTokenInfo { ClientID = "c1" });

            var first = await sut.GetThenRemoveAsync("code-2");
            var second = await sut.GetThenRemoveAsync("code-2");

            Assert.That(first, Is.Not.Null);
            Assert.That(second, Is.Null);
        }

        [Test]
        public async Task GetThenRemove_UnknownCode_ReturnsNull()
        {
            var sut = new DefaultAuthCodeStore();

            var loaded = await sut.GetThenRemoveAsync("never-saved");

            Assert.That(loaded, Is.Null);
        }
    }
}
