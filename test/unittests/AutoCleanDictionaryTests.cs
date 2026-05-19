using NUnit.Framework;
using OAuth2NetCore.Store;
using System.Threading;

namespace UnitTests
{
    [TestFixture]
    public class AutoCleanDictionaryTests
    {
        [Test]
        public void TryRemove_WithinTtl_ReturnsValue()
        {
            // Long TTL so the payload has not expired.
            var dic = new AutoCleanDictionary<string, string>(timerIntervalSeconds: 60, payloadDurationSeconds: 60);
            dic.TryAdd("k", "v");

            var ok = dic.TryRemove("k", out var value);

            Assert.That(ok, Is.True);
            Assert.That(value, Is.EqualTo("v"));
        }

        [Test]
        public void TryRemove_Twice_IsSingleUse()
        {
            var dic = new AutoCleanDictionary<string, string>(timerIntervalSeconds: 60, payloadDurationSeconds: 60);
            dic.TryAdd("k", "v");

            var first = dic.TryRemove("k", out _);
            var second = dic.TryRemove("k", out _);

            Assert.That(first, Is.True);
            Assert.That(second, Is.False);
        }

        [Test]
        public void TryRemove_PastExpiry_ReturnsFalse()
        {
            // Regression for H-4 — payload past its TTL must not be returned even if the timer
            // sweep hasn't fired yet.
            // 1-second TTL + a long sweep interval so the timer doesn't clean the entry first.
            var dic = new AutoCleanDictionary<string, string>(timerIntervalSeconds: 3600, payloadDurationSeconds: 1);
            dic.TryAdd("k", "v");

            Thread.Sleep(1100); // sleep just past the 1s TTL

            var ok = dic.TryRemove("k", out var value);

            Assert.That(ok, Is.False);
            Assert.That(value, Is.Null);
        }

        [Test]
        public void TryRemove_UnknownKey_ReturnsFalse()
        {
            var dic = new AutoCleanDictionary<string, string>(timerIntervalSeconds: 60, payloadDurationSeconds: 60);

            var ok = dic.TryRemove("missing", out var value);

            Assert.That(ok, Is.False);
            Assert.That(value, Is.Null);
        }
    }
}
