using NUnit.Framework;
using OAuth2NetCore.Redis.Token;

namespace UnitTests
{
    [TestFixture]
    public class RedisRefreshTokenInfoStoreTests
    {
        // The Redis key must be the prefix plus the SHA-256 (base64url) digest of the refresh token,
        // never the token itself. The expected value is shared with oauth2go's test.

        [Test]
        public void Key_IsPrefixPlusSha256OfRefreshToken() =>
            Assert.That(new KeyProbe().Key("abc"), Is.EqualTo("t:ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"));

        [Test]
        public void Key_DoesNotContainRawRefreshToken()
        {
            const string token = "not-a-real-refresh-token-0123456789-abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTU";
            Assert.That(new KeyProbe().Key(token), Does.Not.Contain(token));
        }

        // The Redis connection is lazy, so constructing the store does not touch Redis.
        private sealed class KeyProbe : RedisRefreshTokenInfoStore
        {
            public KeyProbe() : base("localhost:0", prefix: "t:") { }
            public string Key(string refreshToken) => GetKey(refreshToken);
        }
    }
}
