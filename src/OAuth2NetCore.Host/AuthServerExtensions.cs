using OAuth2NetCore;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;

namespace Microsoft.Extensions.DependencyInjection {
    public static class AuthServerExtensions {
        public static IServiceCollection AddOAuth2AuthServer(this IServiceCollection services, Action<AuthServerOptions> configOptions, AuthServerOptions options = null) {
            options = options ?? new AuthServerOptions();

            configOptions(options);

            services.AddSingleton(options);

            CheckOptions(services, options);

            return services;
        }

        private static void CheckOptions(IServiceCollection services, AuthServerOptions options) {
            // AuthServer
            if (options.AuthServerFactory != null)
                services.AddSingleton(options.AuthServerFactory);
            else
                // use default
                services.AddSingleton<IAuthServer, DefaultAuthServer>();

            // ClientValidator
            if (options.ClientValidatorFactory != null)
                services.AddSingleton(options.ClientValidatorFactory);
            else
                // use default
                services.AddSingleton<IClientValidator, DefaultClientValidator>();

            // ResourceOwnerValidator
            if (options.ResourceOwnerValidatorFactory != null)
                services.AddSingleton(options.ResourceOwnerValidatorFactory);
            else
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ResourceOwnerValidatorFactory)}");

            // TokenGenerator
            if (options.TokenGeneratorFactory != null)
                services.AddSingleton(options.TokenGeneratorFactory);
            else
                // use default
                services.AddSingleton<ITokenGenerator, DefaultTokenGenerator>();

            // AuthCodeStore
            if (options.AuthCodeStoreFactory != null)
                services.AddSingleton(options.AuthCodeStoreFactory);
            else
                // use default
                services.AddSingleton<IAuthCodeStore, DefaultAuthCodeStore>();

            // AuthCodeGenerator
            if (options.AuthCodeGeneratorFactory != null)
                services.AddSingleton(options.AuthCodeGeneratorFactory);
            else
                // use default
                services.AddSingleton<IAuthCodeGenerator, DefaultAuthCodeGenerator>();

            // PkceValidator
            if (options.PkceValidatorFactory != null)
                services.AddSingleton(options.PkceValidatorFactory);
            else
                // use default
                services.AddSingleton<IPkceValidator, DefaultPkceValidator>();

            // Wellknown open id config
            if (options.WellknownFactory != null)
                services.AddSingleton(options.WellknownFactory);
            else
                // no default, must provde
                services.AddSingleton<IWellknown, DefaultWellknown>();

            // ClaimGenerator
            if (options.TokenClaimBuilderFactory != null)
                services.AddSingleton(options.TokenClaimBuilderFactory);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.TokenClaimBuilderFactory)}");

            // SecurityKeyProvider
            if (options.SecurityKeyProviderFactory != null)
                services.AddSingleton(options.SecurityKeyProviderFactory);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.SecurityKeyProviderFactory)}");

            // ClientStore
            if (options.ClientStoreFactory != null)
                services.AddSingleton(options.ClientStoreFactory);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.ClientStoreFactory)}");

            // TokenStore
            if (options.RefreshTokenInfoStore != null)
                services.AddSingleton(options.RefreshTokenInfoStore);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.RefreshTokenInfoStore)}");

            // TokenStore
            if (options.StateStoreFactory != null)
                services.AddSingleton(options.StateStoreFactory);
            else
                // no default, must provde
                throw new ArgumentNullException($"{nameof(options)}.{nameof(options.StateStoreFactory)}");
        }
    }
}
