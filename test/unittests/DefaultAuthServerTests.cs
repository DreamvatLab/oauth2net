using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using OAuth2NetCore;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace UnitTests
{
    [TestFixture]
    public class DefaultAuthServerTests
    {
        // ---------- C-1: implicit flow must return token in URL fragment ----------

        [Test]
        public async Task Implicit_ReturnsAccessTokenInFragment_NotQuery()
        {
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_Implicit });
            var validator = new FakeClientValidator(client);
            var tokenGen = new FakeTokenGenerator("the-access-token");
            var sut = NewSut(validator, tokenGen);

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Token,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                [OAuth2Consts.Form_State] = "st-1",
            });

            await sut.AuthorizeRequestHandler(ctx);

            var location = ctx.Response.Headers["Location"].ToString();
            Assert.That(location, Does.StartWith("https://app.example/cb#"),
                "implicit grant MUST return tokens in the URL fragment (RFC 6749 §4.2.2)");
            Assert.That(location, Does.Not.Contain("?"));
            Assert.That(location, Does.Contain("access_token=the-access-token"));
            Assert.That(location, Does.Contain("token_type=Bearer"));
            Assert.That(location, Does.Contain("state=st-1"));
        }

        // ---------- H-1: PKCE — default method is S256, redirect omits code_challenge ----------

        [Test]
        public async Task AuthCode_PkceMethodMissing_DefaultsToS256()
        {
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_AuthorizationCode });
            var validator = new FakeClientValidator(client);
            var codeGen = new FakeAuthCodeGenerator("the-code");
            var codeStore = new FakeAuthCodeStore();
            var sut = NewSut(validator, tokenGen: null, codeGen: codeGen, codeStore: codeStore);

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Code,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                [OAuth2Consts.Form_State] = "st-1",
                [OAuth2Consts.Form_CodeChallenge] = "the-challenge",
                // code_challenge_method intentionally omitted
            });

            await sut.AuthorizeRequestHandler(ctx);

            Assert.That(codeStore.Saved.TryGetValue("the-code", out var info), Is.True);
            Assert.That(info.ccm, Is.EqualTo(OAuth2Consts.Pkce_S256),
                "missing code_challenge_method must default to S256 (OAuth 2.1 / BCP)");
        }

        [Test]
        public async Task AuthCode_PkcePlain_RejectedByDefault()
        {
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_AuthorizationCode });
            var validator = new FakeClientValidator(client);
            var sut = NewSut(validator);

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Code,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                [OAuth2Consts.Form_State] = "st-1",
                [OAuth2Consts.Form_CodeChallenge] = "the-challenge",
                [OAuth2Consts.Form_CodeChallengeMethod] = OAuth2Consts.Pkce_Plain,
            });

            await sut.AuthorizeRequestHandler(ctx);

            Assert.That(ctx.Response.StatusCode, Is.EqualTo((int)HttpStatusCode.BadRequest));
            var body = ReadBody(ctx);
            Assert.That(body, Does.Contain("invalid_request"));
            Assert.That(body, Does.Contain("plain"));
        }

        [Test]
        public async Task AuthCode_PkcePlain_AcceptedWhenAllowPlainPkceTrue()
        {
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_AuthorizationCode });
            var validator = new FakeClientValidator(client);
            var codeGen = new FakeAuthCodeGenerator("the-code");
            var codeStore = new FakeAuthCodeStore();
            var opts = new AuthServerOptions { PKCERequired = true, AllowPlainPkce = true };
            var sut = NewSut(validator, tokenGen: null, codeGen: codeGen, codeStore: codeStore, options: opts);

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Code,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                [OAuth2Consts.Form_State] = "st-1",
                [OAuth2Consts.Form_CodeChallenge] = "the-challenge",
                [OAuth2Consts.Form_CodeChallengeMethod] = OAuth2Consts.Pkce_Plain,
            });

            await sut.AuthorizeRequestHandler(ctx);

            Assert.That(codeStore.Saved.ContainsKey("the-code"), Is.True);
        }

        [Test]
        public async Task AuthCode_RedirectOmitsCodeChallenge()
        {
            // Regression for H-1 — authorization response carries ONLY code + state.
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_AuthorizationCode });
            var validator = new FakeClientValidator(client);
            var codeGen = new FakeAuthCodeGenerator("the-code");
            var sut = NewSut(validator, tokenGen: null, codeGen: codeGen, codeStore: new FakeAuthCodeStore());

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Code,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                [OAuth2Consts.Form_State] = "st-1",
                [OAuth2Consts.Form_CodeChallenge] = "the-challenge-secret",
                [OAuth2Consts.Form_CodeChallengeMethod] = OAuth2Consts.Pkce_S256,
            });

            await sut.AuthorizeRequestHandler(ctx);

            var location = ctx.Response.Headers["Location"].ToString();
            Assert.That(location, Does.Contain("code=the-code"));
            Assert.That(location, Does.Contain("state=st-1"));
            Assert.That(location, Does.Not.Contain("the-challenge-secret"),
                "code_challenge must NOT be echoed to the client redirect");
            Assert.That(location, Does.Not.Contain(OAuth2Consts.Form_CodeChallenge));
            Assert.That(location, Does.Not.Contain(OAuth2Consts.Form_CodeChallengeMethod));
        }

        // ---------- M-1: missing state logs a warning ----------

        [Test]
        public async Task Authorize_MissingState_LogsWarning()
        {
            var client = NewClient(grants: new[] { OAuth2Consts.GrantType_Implicit });
            var validator = new FakeClientValidator(client);
            var tokenGen = new FakeTokenGenerator("tok");
            var logger = new CapturingLogger<DefaultAuthServer>();
            var sut = NewSut(validator, tokenGen, logger: logger);

            var ctx = NewContext(authenticated: true, query: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ResponseType] = OAuth2Consts.ResponseType_Token,
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_RedirectUri] = "https://app.example/cb",
                [OAuth2Consts.Form_Scope] = "read",
                // state intentionally omitted
            });

            await sut.AuthorizeRequestHandler(ctx);

            Assert.That(logger.Messages.Any(m => m.level == LogLevel.Warning && m.message.Contains("state")),
                Is.True, "missing 'state' parameter must produce a warning");
        }

        // ---------- M-3: clear_token endpoint writes 200 on success ----------

        [Test]
        public async Task ClearToken_HappyPath_WritesOkStatus()
        {
            var client = NewClient();
            var validator = new FakeClientValidator(client);
            var stateStore = new FakeStateStore();
            await stateStore.SaveAsync(client.ID + ":es-1", "st-1");
            var tokenStore = new FakeRefreshTokenInfoStore();
            var sut = NewSut(validator, tokenGen: null, tokenStore: tokenStore, stateStore: stateStore);

            var ctx = NewContext(authenticated: false, form: new Dictionary<string, string>
            {
                [OAuth2Consts.Form_ClientID] = client.ID,
                [OAuth2Consts.Form_ClientSecret] = client.Secret,
                [OAuth2Consts.Form_State] = "st-1",
                [OAuth2Consts.Form_EndSessionID] = "es-1",
                [OAuth2Consts.Form_RefreshToken] = "rt-abc",
            });

            await sut.ClearTokenRequestHandler(ctx);

            Assert.That(ctx.Response.StatusCode, Is.EqualTo((int)HttpStatusCode.OK));
            Assert.That(tokenStore.Removed, Does.Contain("rt-abc"));
        }

        // ============================================================
        //   helpers
        // ============================================================

        private static DefaultAuthServer NewSut(
            IClientValidator clientValidator,
            ITokenGenerator tokenGen = null,
            IAuthCodeGenerator codeGen = null,
            IAuthCodeStore codeStore = null,
            IRefreshTokenInfoStore tokenStore = null,
            IStateStore stateStore = null,
            AuthServerOptions options = null,
            ILogger<DefaultAuthServer> logger = null)
        {
            return new DefaultAuthServer(
                clientValidator,
                tokenGen ?? new FakeTokenGenerator("tok"),
                codeStore ?? new FakeAuthCodeStore(),
                tokenStore ?? new FakeRefreshTokenInfoStore(),
                stateStore ?? new FakeStateStore(),
                codeGen ?? new FakeAuthCodeGenerator("code"),
                new FakeResourceOwnerValidator(),
                logger ?? new CapturingLogger<DefaultAuthServer>(),
                options ?? new AuthServerOptions { PKCERequired = true, AllowPlainPkce = false },
                new DefaultPkceValidator(),
                new FakeWellknown()
            );
        }

        private static DefaultHttpContext NewContext(
            bool authenticated,
            IDictionary<string, string> query = null,
            IDictionary<string, string> form = null)
        {
            var ctx = new DefaultHttpContext();
            if (query != null)
            {
                var qb = new QueryBuilder(query);
                ctx.Request.QueryString = qb.ToQueryString();
            }
            if (form != null)
            {
                ctx.Request.ContentType = "application/x-www-form-urlencoded";
                ctx.Request.Form = new FormCollection(
                    form.ToDictionary(kv => kv.Key, kv => new Microsoft.Extensions.Primitives.StringValues(kv.Value)));
            }
            else
            {
                ctx.Request.Form = new FormCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>());
            }
            if (authenticated)
            {
                var identity = new ClaimsIdentity(authenticationType: "test");
                identity.AddClaim(new Claim(ClaimTypes.Name, "alice"));
                ctx.User = new ClaimsPrincipal(identity);
            }
            ctx.Response.Body = new MemoryStream();
            return ctx;
        }

        private static string ReadBody(HttpContext ctx)
        {
            ctx.Response.Body.Seek(0, SeekOrigin.Begin);
            return new StreamReader(ctx.Response.Body, Encoding.UTF8).ReadToEnd();
        }

        private static Client NewClient(string id = "c1", string secret = "s1", string[] grants = null, bool isPublic = false)
            => new Client
            {
                ID = id,
                Secret = secret,
                IsPublic = isPublic,
                AccessTokenExpireSeconds = 3600,
                RefreshTokenExpireSeconds = 7200,
                Grants = grants?.ToList() ?? new List<string>(),
                Scopes = new List<string> { "read", "write" },
                RedirectUris = new List<string> { "https://app.example/cb" },
            };

        // --- fakes ---

        private sealed class QueryBuilder
        {
            private readonly IDictionary<string, string> _parts;
            public QueryBuilder(IDictionary<string, string> parts) => _parts = parts;
            public QueryString ToQueryString()
            {
                var sb = new StringBuilder("?");
                bool first = true;
                foreach (var kv in _parts)
                {
                    if (!first) sb.Append('&');
                    sb.Append(Uri.EscapeDataString(kv.Key)).Append('=').Append(Uri.EscapeDataString(kv.Value ?? ""));
                    first = false;
                }
                return new QueryString(sb.ToString());
            }
        }

        private sealed class FakeClientValidator : IClientValidator
        {
            private readonly IClient _client;
            public FakeClientValidator(IClient client) => _client = client;

            public MessageResult<NetworkCredential> ExractClientCredentials(HttpContext context)
            {
                var id = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();
                var sec = context.Request.Form[OAuth2Consts.Form_ClientSecret].FirstOrDefault();
                return new MessageResult<NetworkCredential> { Result = new NetworkCredential(id, sec) };
            }

            public Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential)
                => Task.FromResult(new MessageResult<IClient> { Result = _client });
            public Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType)
                => VerifyClientAsync(credential);
            public Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType, string scopesStr)
                => VerifyClientAsync(credential);
            public Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string responseType, string redirectURI, string scopesStr, string state)
                => Task.FromResult(new MessageResult<IClient> { Result = _client });
            public Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string logoutRedirectURI)
                => Task.FromResult(new MessageResult<IClient>());
        }

        private sealed class FakeTokenGenerator : ITokenGenerator
        {
            private readonly string _token;
            public FakeTokenGenerator(string token) => _token = token;
            public Task<string> GenerateAccessTokenAsync(HttpContext context, GrantType grantType, IClient client, string[] scopes, string username)
                => Task.FromResult(_token);
            public Task<string> GenerateRefreshTokenAsync() => Task.FromResult("refresh");
        }

        private sealed class FakeAuthCodeGenerator : IAuthCodeGenerator
        {
            private readonly string _code;
            public FakeAuthCodeGenerator(string code) => _code = code;
            public Task<string> GenerateAsync() => Task.FromResult(_code);
        }

        private sealed class FakeAuthCodeStore : IAuthCodeStore
        {
            public Dictionary<string, RefreshTokenInfo> Saved { get; } = new();
            public Task SaveAsync(string code, RefreshTokenInfo info) { Saved[code] = info; return Task.CompletedTask; }
            public Task<RefreshTokenInfo> GetThenRemoveAsync(string code)
            {
                Saved.TryGetValue(code, out var v); Saved.Remove(code);
                return Task.FromResult(v);
            }
        }

        private sealed class FakeRefreshTokenInfoStore : IRefreshTokenInfoStore
        {
            public HashSet<string> Removed { get; } = new();
            public Task SaveRefreshTokenAsync(string rt, RefreshTokenInfo info, int exp) => Task.CompletedTask;
            public Task<RefreshTokenInfo> GetThenRemoveTokenInfoAsync(string rt) => Task.FromResult<RefreshTokenInfo>(null);
            public Task RemoveRefreshTokenAsync(string rt) { Removed.Add(rt); return Task.CompletedTask; }
        }

        private sealed class FakeStateStore : IStateStore
        {
            private readonly Dictionary<string, string> _data = new();
            public Task SaveAsync(string key, string value, int expireSeconds = 60) { _data[key] = value; return Task.CompletedTask; }
            public Task<string> GetThenRemoveAsync(string key)
            {
                _data.TryGetValue(key, out var v); _data.Remove(key);
                return Task.FromResult(v);
            }
        }

        private sealed class FakeResourceOwnerValidator : IResourceOwnerValidator
        {
            public Task<bool> VerifyAsync(string u, string p) => Task.FromResult(false);
        }

        private sealed class FakeWellknown : IWellknown
        {
            public OpenIDConfig GetOpenIDCOnfig() => null;
            public JsonWebKey GetOpenIDJsonWebKey() => null;
        }

        internal sealed class CapturingLogger<T> : ILogger<T>
        {
            public List<(LogLevel level, string message)> Messages { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => NullDisposable.Instance;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
            {
                Messages.Add((logLevel, formatter(state, exception)));
            }
            private sealed class NullDisposable : IDisposable
            {
                public static readonly NullDisposable Instance = new();
                public void Dispose() { }
            }
        }
    }
}
