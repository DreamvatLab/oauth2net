using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using OAuth2NetCore;
using OAuth2NetCore.Host;
using OAuth2NetCore.Model;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using System;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using ClientOptions = OAuth2NetCore.ClientOptions;

namespace Microsoft.Extensions.DependencyInjection {
    public static class ClientServerExtensions {
        public static IServiceCollection AddOAuth2Client(this IServiceCollection services, Action<ClientOptions> configOptions, ClientOptions options = null) {
            options = options ?? new ClientOptions();
            configOptions(options);
            CheckOptions(services, options);

            services.AddSingleton(options);

            services.AddHttpClient();
            services.AddHttpContextAccessor();
            services.AddTransient<IDataSerializer<Token>, JsonDataSerializer<Token>>();
            services.AddTransient<ISecureDataFormat<Token>, SecureDataFormat<Token>>();
            services.AddTransient(c => {
                var dpp = c.GetService<IDataProtectionProvider>();
                return dpp.CreateProtector(nameof(Token));
            });
            services.AddTransient<ITokenStore, HttpContextTokenStore>();

            // Resolve services lazily from HttpContext.RequestServices at event time —
            // calling services.BuildServiceProvider() here would prematurely create a second
            // container and lock singleton handles out of the real DI container.
            services.AddAuthentication(authOptions => {
                authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                authOptions.DefaultChallengeScheme = OAuthDefaults.DisplayName;
            })
                .AddCookie(o => {
                    o.Cookie.SameSite = options.CookieSameSite; // RL {3A012FF7-DB5F-4688-8575-B499F51FF4A5}
                    if (options.AutoRefreshToken) {
                        o.Events.OnValidatePrincipal = ctx => {
                            var sp = ctx.HttpContext.RequestServices;
                            return ValidatePrincipal(ctx, sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<ITokenStore>(), options);
                        };
                    }
                })
                .AddOAuth<OAuthOptions, OAuth2Handler>(OAuthDefaults.DisplayName, o => {
                    if (options.Scopes != null) {
                        foreach (var scope in options.Scopes) {
                            o.Scope.Add(scope);
                        }
                    }
                    o.ClientId = options.ClientID;
                    o.ClientSecret = options.ClientSecret;
                    o.AuthorizationEndpoint = options.AuthorizationEndpoint;
                    o.TokenEndpoint = options.TokenEndpoint;
                    o.CallbackPath = options.SignInCallbackPath;
                    //o.SaveTokens = options.SaveTokens;    // Use customized token store
                    o.UsePkce = options.UsePkce;


                    ////////// Events
                    // OnAccessDenied
                    //o.Events.OnAccessDenied = options.OnAccessDenied;
                    // OnCreatingTicket
                    if (options.OnCreatingTicket != null) {
                        o.Events.OnCreatingTicket = options.OnCreatingTicket;
                    } else {
                        o.Events.OnCreatingTicket = async context => {
                            var json = context.TokenResponse.Response.ToJsonString();
                            var tokenDTO = JsonSerializer.Deserialize<Token>(json);

                            if (options.PreCreatingTicket != null) {
                                var canContinue = await options.PreCreatingTicket?.Invoke(context, tokenDTO);
                                if (!canContinue) return;
                                // ^^^^^^^^^^
                            }

                            context.Principal = new ClaimsPrincipal(new ClaimsIdentity(OAuthDefaults.DisplayName, OAuth2Consts.Claim_Name, OAuth2Consts.Claim_Role));

                            // Resolve the token store from the live DI container, not a captured singleton.
                            var tokenStore = context.HttpContext.RequestServices.GetRequiredService<ITokenStore>();
                            var jwt = await tokenStore.SaveTokenDTOAsync(tokenDTO);
                            if (jwt != null) {
                                var claims = await options.IdentityClaimsBuilder(jwt);
                                foreach (var claim in claims) {
                                    context.Identity.AddClaim(claim);
                                }
                            }
                        };
                    }
                    // OnRedirectToAuthorizationEndpoint
                    if (options.OnRedirectToAuthorizationEndpoint != null)
                        o.Events.OnRedirectToAuthorizationEndpoint = options.OnRedirectToAuthorizationEndpoint;
                    else
                        o.Events.OnRedirectToAuthorizationEndpoint = (ctx) => {
                            if (ctx.Properties.Parameters.ContainsKey("t")) {   // Login token RL: {1BC05F9A-1971-418B-ABA7-6C623C008D85}
                                ctx.RedirectUri += "&t=" + ctx.Properties.Parameters["t"];
                            }
                            ctx.Response.Redirect(ctx.RedirectUri);
                            return Task.CompletedTask;
                        };
                    // OnRemoteFailure
                    if (options.OnRemoteFailure != null)
                        o.Events.OnRemoteFailure = options.OnRemoteFailure;
                    // OnTicketReceived
                    if (options.OnTicketReceived != null)
                        o.Events.OnTicketReceived = options.OnTicketReceived;
                });

            return services;
        }

        private static async Task ValidatePrincipal(CookieValidatePrincipalContext context, IHttpClientFactory httpClientFactory, ITokenStore tokenDTOStore, ClientOptions options) {
            var tokenDTO = await tokenDTOStore.GetTokenDTOAsync();
            if (tokenDTO == null) {
                return;
            }

            var jwt = tokenDTO.GetJwt();

            //if (!jwt.TryGetPayloadValue<long>(OAuth2Consts.Claim_AccessTokenExpire, out var exp))
            //{// expStr format invalid
            //    // reject principal
            //    context.RejectPrincipal();
            //    // sign user out
            //    await context.HttpContext.SignOutAsync();
            //    return;
            //}

            if (DateTimeOffset.UtcNow > jwt.ValidTo) {// access token expired
                if (!string.IsNullOrWhiteSpace(tokenDTO.RefreshToken)) {// refresh token exists

                    // send refresh token request
                    var httpClient = httpClientFactory.CreateClient();
                    var refreshTokenResp = await httpClient.RequestRefreshTokenAsync(new RefreshTokenRequest {
                        Address = options.TokenEndpoint,
                        ClientId = options.ClientID,
                        ClientSecret = options.ClientSecret,
                        RefreshToken = tokenDTO.RefreshToken,
                        Scope = string.Join(OAuth2Consts.Seperator_Scope, options.Scopes)
                    });

                    if (!refreshTokenResp.IsError) {// refresh success
                        await tokenDTOStore.SaveTokenDTOAsync(refreshTokenResp.Raw);
                        //context.Properties.UpdateTokenValue(OAuth2Consts.Token_Access, refreshTokenResp.AccessToken);
                        //context.Properties.UpdateTokenValue(OAuth2Consts.Token_Refresh, refreshTokenResp.RefreshToken);
                        //var expireAt = DateTimeOffset.UtcNow.AddSeconds(refreshTokenResp.ExpiresIn).ToString(OAuth2Consts.UtcTimesamp);
                        //context.Properties.UpdateTokenValue(OAuth2Consts.Token_ExpiresAt, expireAt);
                        //context.ShouldRenew = true;
                        return;
                    }
                }

                // reject principal
                context.RejectPrincipal();
                // sign user out
                await context.HttpContext.OAuth2SignOutAsync();
            }
        }

        private static void CheckOptions(IServiceCollection services, ClientOptions options) {
            if (options.IdentityClaimsBuilder == null)
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.IdentityClaimsBuilder)}");
            if (string.IsNullOrWhiteSpace(options.ClientID))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientID)}");
            if (string.IsNullOrWhiteSpace(options.ClientSecret))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientSecret)}");
            if (string.IsNullOrWhiteSpace(options.AuthorizationEndpoint))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.AuthorizationEndpoint)}");
            if (string.IsNullOrWhiteSpace(options.TokenEndpoint))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.TokenEndpoint)}");
            if (string.IsNullOrWhiteSpace(options.SignInCallbackPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignInCallbackPath)}");
            if (string.IsNullOrWhiteSpace(options.SignOutCallbackPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignOutCallbackPath)}");
            if (string.IsNullOrWhiteSpace(options.SignOutPath))
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SignOutPath)}");

            // StateStore
            if (options.StateStoreFactory != null)
                services.AddSingleton(options.StateStoreFactory);
            else
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.StateStoreFactory)}");

            if (options.StateGeneratorFactory != null)
                services.AddSingleton(options.StateGeneratorFactory);
            else
                // use default
                services.AddSingleton<IStateGenerator, DefaultStateGenerator>();

            if (options.ClientServerFactory != null)
                services.AddSingleton(options.ClientServerFactory);
            else
                // use default
                services.AddSingleton<IClientServer, DefaultClientServer>();
        }

        private static string ToJsonString(this JsonDocument jdoc) {
            using (var stream = new MemoryStream())
            using (var writer = new Utf8JsonWriter(stream)) {
                jdoc.WriteTo(writer);
                writer.Flush();
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }
    }
}
