using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using OAuth2NetCore;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestFixture]
    public class DefaultClientValidatorTests
    {
        private FakeClientStore _store;
        private DefaultClientValidator _sut;

        [SetUp]
        public void SetUp()
        {
            _store = new FakeClientStore();
            _sut = new DefaultClientValidator(_store, NullLogger<DefaultClientValidator>.Instance);
        }

        private static HttpContext CreateContextWithHeader(string authorization)
        {
            var ctx = new DefaultHttpContext();
            if (authorization != null)
            {
                ctx.Request.Headers[OAuth2Consts.Header_Authorization] = authorization;
            }
            // Pre-assign an empty form so the body-fallback path doesn't throw when the
            // header parse fails — DefaultHttpContext otherwise tries to read a missing body.
            ctx.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>());
            return ctx;
        }

        private static HttpContext CreateContextWithForm(IDictionary<string, Microsoft.Extensions.Primitives.StringValues> form)
        {
            var ctx = new DefaultHttpContext();
            ctx.Request.ContentType = "application/x-www-form-urlencoded";
            ctx.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>(form));
            return ctx;
        }

        private static string BuildBasicAuthHeader(string user, string pass)
        {
            // RFC 7617 requires STANDARD base64 (not base64url) — the validator was updated
            // accordingly in H-3.
            return "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass));
        }

        // ----- ExractClientCredentials (header) -----

        [Test]
        public void ExractCreds_ValidHeader_Succeeds()
        {
            var ctx = CreateContextWithHeader(BuildBasicAuthHeader("client1", "secret1"));

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.UserName, Is.EqualTo("client1"));
            Assert.That(mr.Result.Password, Is.EqualTo("secret1"));
        }

        [Test]
        public void ExractCreds_HeaderMalformedSplit_FallsBackToBody_AndFails()
        {
            // Single token (no space) — header parse fails, body has nothing -> invalid_request
            var ctx = CreateContextWithHeader("BasicOnly");

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public void ExractCreds_HeaderEncodedMissingColon_FallsBackToBody_AndFails()
        {
            // Decoded value has no colon -> second-stage validation fails
            var bad = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("noColonHere"));
            var ctx = CreateContextWithHeader(bad);

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        // ---- H-3 regression: scheme validation, password-with-colon, +/= characters ----

        [Test]
        public void ExractCreds_NonBasicScheme_Rejected()
        {
            // Regression for H-3 — "Bearer xxx" / "Negotiate xxx" must NOT be parsed as Basic.
            var ctx = CreateContextWithHeader("Bearer " + Convert.ToBase64String(Encoding.UTF8.GetBytes("c:s")));

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public void ExractCreds_BasicSchemeCaseInsensitive_Accepted()
        {
            // RFC 7617 — auth-scheme matching is case-insensitive.
            var ctx = CreateContextWithHeader("basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("c1:s1")));

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.UserName, Is.EqualTo("c1"));
            Assert.That(mr.Result.Password, Is.EqualTo("s1"));
        }

        [Test]
        public void ExractCreds_PasswordContainingColon_SplitOnFirstColon()
        {
            // Regression for H-3 — password may legitimately contain ':' per RFC 7617;
            // we must split on the FIRST colon only.
            var ctx = CreateContextWithHeader(BuildBasicAuthHeader("c1", "p:a:s:s"));

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.UserName, Is.EqualTo("c1"));
            Assert.That(mr.Result.Password, Is.EqualTo("p:a:s:s"));
        }

        [Test]
        public void ExractCreds_StandardBase64WithPlusOrSlash_Decoded()
        {
            // Regression for H-3 — credential whose base64 contains '+' / '/' (standard alphabet)
            // must decode correctly. The previous Base64UrlEncoder path would silently mishandle
            // these characters since they don't appear in the URL-safe alphabet.
            //
            // Construct a credential whose base64 encoding is guaranteed to contain '+' and '/'.
            // Bytes 0xFB, 0xFF produce "+/" in standard base64.
            var raw = new byte[] { 0xFB, 0xFF, (byte)':', (byte)'x' }; // "<two non-ASCII>:x"
            // But the validator UTF-8 decodes the bytes — 0xFB 0xFF isn't valid UTF-8.
            // Use a simpler pattern: pad to force "+/" in the output.
            var user = "ab??cd";
            var pass = "p1";
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pass));
            // Sanity: ensure base64 chosen above actually contains a special char we care about.
            Assume.That(encoded, Does.Contain("=").Or.Contain("+").Or.Contain("/"),
                "Test setup expects encoding to exercise base64 padding/alphabet edge cases");
            var ctx = CreateContextWithHeader("Basic " + encoded);

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.UserName, Is.EqualTo(user));
            Assert.That(mr.Result.Password, Is.EqualTo(pass));
        }

        [Test]
        public void ExractCreds_InvalidBase64_Rejected()
        {
            // Regression for H-3 — malformed base64 should yield invalid_request, not crash.
            var ctx = CreateContextWithHeader("Basic !!!not-base64!!!");

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        // ---- C-2 regression: constant-time compare correctness (timing property itself not unit-testable) ----

        [Test]
        public async Task VerifyClient_SecretsDifferentLength_Rejected()
        {
            // C-2 fix uses byte-length-aware fixed-time compare. Confirm length-mismatch is still rejected.
            _store.Add(new Client { ID = "c1", Secret = "longer-secret-12345" });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("c1", "short"));

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_client));
        }

        // ----- ExractClientCredentials (body fallback) -----

        [Test]
        public void ExractCreds_NoHeader_UsesBody()
        {
            var ctx = CreateContextWithForm(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
            {
                [OAuth2Consts.Form_ClientID] = "client1",
                [OAuth2Consts.Form_ClientSecret] = "secret1",
            });

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.UserName, Is.EqualTo("client1"));
            Assert.That(mr.Result.Password, Is.EqualTo("secret1"));
        }

        [Test]
        public void ExractCreds_NoHeader_NoBody_Fails()
        {
            var ctx = CreateContextWithForm(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>());

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public void ExractCreds_BodyHasIdButNoSecret_Fails()
        {
            var ctx = CreateContextWithForm(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
            {
                [OAuth2Consts.Form_ClientID] = "client1",
            });

            var mr = _sut.ExractClientCredentials(ctx);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        // ----- VerifyClientAsync(NetworkCredential) -----

        [Test]
        public async Task VerifyClient_UnknownClient_ReturnsInvalidClient()
        {
            var mr = await _sut.VerifyClientAsync(new NetworkCredential("nope", "x"));

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_client));
        }

        [Test]
        public async Task VerifyClient_WrongSecret_ReturnsInvalidClient()
        {
            _store.Add(new Client { ID = "c1", Secret = "right" });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("c1", "wrong"));

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_client));
        }

        [Test]
        public async Task VerifyClient_CorrectSecret_ReturnsClient()
        {
            _store.Add(new Client { ID = "c1", Secret = "right" });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("c1", "right"));

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.ID, Is.EqualTo("c1"));
        }

        [Test]
        public async Task VerifyClient_PublicClient_AllowsEmptySecret()
        {
            _store.Add(new Client { ID = "pub", Secret = "ignored", IsPublic = true });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("pub", string.Empty));

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.ID, Is.EqualTo("pub"));
        }

        [Test]
        public async Task VerifyClient_NonPublicClient_RejectsEmptySecret()
        {
            _store.Add(new Client { ID = "c1", Secret = "right", IsPublic = false });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("c1", string.Empty));

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_client));
        }

        // ----- VerifyClientAsync with grant type -----

        [Test]
        public async Task VerifyClient_GrantMissing_ReturnsInvalidRequest()
        {
            _store.Add(new Client { ID = "c1", Secret = "s" });

            var mr = await _sut.VerifyClientAsync(new NetworkCredential("c1", "s"), grantType: " ");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public async Task VerifyClient_GrantNotAllowed_ReturnsUnauthorizedClient()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Secret = "s",
                Grants = new List<string> { OAuth2Consts.GrantType_Client },
            });

            var mr = await _sut.VerifyClientAsync(
                new NetworkCredential("c1", "s"),
                OAuth2Consts.GrantType_AuthorizationCode);

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_unauthorized_client));
        }

        [Test]
        public async Task VerifyClient_GrantAllowed_Succeeds()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Secret = "s",
                Grants = new List<string> { OAuth2Consts.GrantType_Client },
            });

            var mr = await _sut.VerifyClientAsync(
                new NetworkCredential("c1", "s"),
                OAuth2Consts.GrantType_Client);

            Assert.That(mr.IsSuccess, Is.True);
        }

        // ----- VerifyClientAsync with scopes -----

        [Test]
        public async Task VerifyClient_ScopesMissing_ReturnsInvalidRequest()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Secret = "s",
                Grants = new List<string> { OAuth2Consts.GrantType_Client },
                Scopes = new List<string> { "read" },
            });

            var mr = await _sut.VerifyClientAsync(
                new NetworkCredential("c1", "s"),
                OAuth2Consts.GrantType_Client,
                scopesStr: " ");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public async Task VerifyClient_ScopeNotAllowed_ReturnsInvalidScope()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Secret = "s",
                Grants = new List<string> { OAuth2Consts.GrantType_Client },
                Scopes = new List<string> { "read" },
            });

            var mr = await _sut.VerifyClientAsync(
                new NetworkCredential("c1", "s"),
                OAuth2Consts.GrantType_Client,
                "read write");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_scope));
        }

        [Test]
        public async Task VerifyClient_AllScopesAllowed_Succeeds()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Secret = "s",
                Grants = new List<string> { OAuth2Consts.GrantType_Client },
                Scopes = new List<string> { "read", "write" },
            });

            var mr = await _sut.VerifyClientAsync(
                new NetworkCredential("c1", "s"),
                OAuth2Consts.GrantType_Client,
                "read write");

            Assert.That(mr.IsSuccess, Is.True);
        }

        // ----- VerifyClientAsync with response type + redirect uri -----

        [Test]
        public async Task VerifyClient_AuthCodeFlow_MissingRedirect_Fails()
        {
            var mr = await _sut.VerifyClientAsync("c1", OAuth2Consts.ResponseType_Code, redirectURI: "", "read", "state");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public async Task VerifyClient_AuthCodeFlow_RedirectNotInWhitelist_AccessDenied()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Grants = new List<string> { OAuth2Consts.GrantType_AuthorizationCode },
                Scopes = new List<string> { "read" },
                RedirectUris = new List<string> { "https://app.example.com/cb" },
            });

            var mr = await _sut.VerifyClientAsync(
                "c1",
                OAuth2Consts.ResponseType_Code,
                "https://evil.example.com/cb",
                "read",
                "state");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_access_denied));
        }

        [Test]
        public async Task VerifyClient_AuthCodeFlow_HappyPath()
        {
            _store.Add(new Client
            {
                ID = "c1",
                Grants = new List<string> { OAuth2Consts.GrantType_AuthorizationCode },
                Scopes = new List<string> { "read" },
                RedirectUris = new List<string> { "https://app.example.com/cb" },
            });

            var mr = await _sut.VerifyClientAsync(
                "c1",
                OAuth2Consts.ResponseType_Code,
                "https://app.example.com/cb",
                "read",
                "state");

            Assert.That(mr.IsSuccess, Is.True);
            Assert.That(mr.Result.ID, Is.EqualTo("c1"));
        }

        [Test]
        public async Task VerifyClient_AuthCodeFlow_ResponseTypeNotPermitted_Unauthorized()
        {
            // Client only has implicit grant — code response type maps to "authorization_code"
            // requirement which is missing.
            _store.Add(new Client
            {
                ID = "c1",
                Grants = new List<string> { OAuth2Consts.GrantType_Implicit },
                Scopes = new List<string> { "read" },
                RedirectUris = new List<string> { "https://app.example.com/cb" },
            });

            var mr = await _sut.VerifyClientAsync(
                "c1",
                OAuth2Consts.ResponseType_Code,
                "https://app.example.com/cb",
                "read",
                "state");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_unauthorized_client));
        }

        // ----- VerifyClientAsync(clientID, logoutRedirectURI) -----

        [Test]
        public async Task VerifyClient_Logout_MissingClientID_Fails()
        {
            var mr = await _sut.VerifyClientAsync("", "https://app.example.com/signout");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_request));
        }

        [Test]
        public async Task VerifyClient_Logout_UnknownClient_InvalidClient()
        {
            var mr = await _sut.VerifyClientAsync("nope", "https://app.example.com/signout");

            Assert.That(mr.IsSuccess, Is.False);
            Assert.That(mr.MsgCode, Is.EqualTo(OAuth2Consts.Err_invalid_client));
        }

        [Test]
        public async Task VerifyClient_Logout_AllowedUri_Succeeds()
        {
            _store.Add(new Client
            {
                ID = "c1",
                RedirectUris = new List<string> { "https://app.example.com/signout" },
            });

            var mr = await _sut.VerifyClientAsync("c1", "https://app.example.com/signout");

            // Note: this overload validates only — it does NOT populate mr.Result on success.
            Assert.That(mr.IsSuccess, Is.True);
        }

        private sealed class FakeClientStore : IClientStore
        {
            private readonly Dictionary<string, IClient> _clients = new();

            public void Add(IClient client) => _clients[client.ID] = client;

            public Task<IClient> GetClientAsync(string clientID)
            {
                _clients.TryGetValue(clientID, out var c);
                return Task.FromResult(c);
            }
        }
    }
}
