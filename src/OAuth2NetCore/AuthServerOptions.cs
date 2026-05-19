using Microsoft.IdentityModel.Tokens;
using OAuth2NetCore.Security;
using OAuth2NetCore.Store;
using OAuth2NetCore.Token;
using System;

namespace OAuth2NetCore {
    public class AuthServerOptions {
        /// <summary>
        /// Required (has default)
        /// </summary>
        public string SigningAlgorithm { get; set; } = SecurityAlgorithms.RsaSsaPssSha256;
        /// <summary>
        /// Required (has default)
        /// </summary>
        public bool PKCERequired { get; set; } = true;
        /// <summary>
        /// If true, accept "plain" code_challenge_method. Default false — only S256 is accepted.
        /// </summary>
        public bool AllowPlainPkce { get; set; } = false;
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, ITokenClaimBuilder> TokenClaimBuilderFactory { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, ISecurityKeyProvider> SecurityKeyProviderFactory { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, IResourceOwnerValidator> ResourceOwnerValidatorFactory { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, IClientStore> ClientStoreFactory { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, IRefreshTokenInfoStore> RefreshTokenInfoStore { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, IStateStore> StateStoreFactory { get; set; }
        /// <summary>
        /// Required
        /// </summary>
        public Func<IServiceProvider, IWellknown> WellknownFactory { get; set; }


        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, IAuthServer> AuthServerFactory { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, IClientValidator> ClientValidatorFactory { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, ITokenGenerator> TokenGeneratorFactory { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, IAuthCodeGenerator> AuthCodeGeneratorFactory { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, IAuthCodeStore> AuthCodeStoreFactory { get; set; }
        /// <summary>
        /// Optional
        /// </summary>
        public Func<IServiceProvider, IPkceValidator> PkceValidatorFactory { get; set; }

    }
}