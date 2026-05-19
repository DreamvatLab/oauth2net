using NUnit.Framework;
using OAuth2NetCore;
using System.Collections.Generic;

namespace UnitTests
{
    [TestFixture]
    public class OAuth2UtilsTests
    {
        // RFC 7636, Appendix B: code_verifier -> code_challenge (S256)
        [Test]
        public void ToSHA256Base64URL_Matches_RFC7636_Example()
        {
            const string codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

            var actual = OAuth2Utils.ToSHA256Base64URL(codeVerifier);

            Assert.That(actual, Is.EqualTo(expectedChallenge));
        }

        [Test]
        public void ToSHA256Base64URL_IsDeterministic()
        {
            const string input = "the quick brown fox";
            var a = OAuth2Utils.ToSHA256Base64URL(input);
            var b = OAuth2Utils.ToSHA256Base64URL(input);

            Assert.That(a, Is.EqualTo(b));
        }

        [Test]
        public void ToSHA256Base64URL_Output_HasNoBase64Padding()
        {
            var encoded = OAuth2Utils.ToSHA256Base64URL("anything");

            Assert.That(encoded, Does.Not.Contain("="));
            Assert.That(encoded, Does.Not.Contain("+"));
            Assert.That(encoded, Does.Not.Contain("/"));
        }

        [Test]
        public void ToSHA256Base64URL_Output_Is43Chars()
        {
            // SHA256 produces 32 bytes -> Base64Url length 43 (no padding)
            var encoded = OAuth2Utils.ToSHA256Base64URL(string.Empty);
            Assert.That(encoded.Length, Is.EqualTo(43));
        }

        // ---------- AppendQuery ----------

        [Test]
        public void AppendQuery_NoExistingQuery_UsesQuestionMark()
        {
            var result = OAuth2Utils.AppendQuery("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("code", "abc"),
                new KeyValuePair<string, string>("state", "xyz"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb?code=abc&state=xyz"));
        }

        [Test]
        public void AppendQuery_ExistingQuery_UsesAmpersand()
        {
            // Regression for H-5 — must not produce a second '?'.
            var result = OAuth2Utils.AppendQuery("https://example.com/cb?source=a", new[] {
                new KeyValuePair<string, string>("code", "abc"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb?source=a&code=abc"));
            Assert.That(result.Split('?').Length, Is.EqualTo(2), "must contain exactly one '?'");
        }

        [Test]
        public void AppendQuery_EncodesValueSpecialChars()
        {
            // Regression for H-5 — must URL-encode &, =, space, /, etc.
            var result = OAuth2Utils.AppendQuery("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("state", "a b&c=d/e"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb?state=a%20b%26c%3Dd%2Fe"));
        }

        [Test]
        public void AppendQuery_SkipsNullValues()
        {
            var result = OAuth2Utils.AppendQuery("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("a", "1"),
                new KeyValuePair<string, string>("b", null),
                new KeyValuePair<string, string>("c", "3"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb?a=1&c=3"));
        }

        [Test]
        public void AppendQuery_EmptyParameters_ReturnsUriUnchanged()
        {
            var result = OAuth2Utils.AppendQuery("https://example.com/cb", new KeyValuePair<string, string>[0]);
            Assert.That(result, Is.EqualTo("https://example.com/cb"));
        }

        // ---------- AppendFragment ----------

        [Test]
        public void AppendFragment_UsesHash_NotQuestionMark()
        {
            // Regression for C-1 — implicit flow tokens MUST go in URL fragment, not query.
            var result = OAuth2Utils.AppendFragment("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("access_token", "tok"),
                new KeyValuePair<string, string>("token_type", "Bearer"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb#access_token=tok&token_type=Bearer"));
            Assert.That(result, Does.Not.Contain("?"));
        }

        [Test]
        public void AppendFragment_ExistingFragment_UsesAmpersand()
        {
            var result = OAuth2Utils.AppendFragment("https://example.com/cb#foo=1", new[] {
                new KeyValuePair<string, string>("access_token", "tok"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb#foo=1&access_token=tok"));
        }

        [Test]
        public void AppendFragment_EncodesValueSpecialChars()
        {
            var result = OAuth2Utils.AppendFragment("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("state", "a b&c"),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb#state=a%20b%26c"));
        }

        [Test]
        public void AppendFragment_SkipsNullValues()
        {
            var result = OAuth2Utils.AppendFragment("https://example.com/cb", new[] {
                new KeyValuePair<string, string>("a", "1"),
                new KeyValuePair<string, string>("b", null),
            });

            Assert.That(result, Is.EqualTo("https://example.com/cb#a=1"));
        }
    }
}
