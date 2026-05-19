using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OAuth2NetCore.Model;
using OAuth2NetCore.Store;
using System;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace OAuth2NetCore.Security {
    public class DefaultClientValidator : IClientValidator {
        private readonly IClientStore _clientStore;
        private readonly ILogger<DefaultClientValidator> _logger;

        public DefaultClientValidator(IClientStore clientStore, ILogger<DefaultClientValidator> logger) {
            _clientStore = clientStore;
            _logger = logger;
        }

        /// <summary>
        /// extract client credential from request
        /// </summary>
        public MessageResult<NetworkCredential> ExractClientCredentials(HttpContext context) {
            var mr = ExractClientCredentialsFromHeader(context);
            if (mr.IsSuccess) return mr;

            // didn't find client credential in header, find it in request body instead
            mr = ExractClientCredentialsFromBody(context);
            return mr;
        }

        /// <summary>
        /// extract client credential from request header
        /// </summary>
        protected virtual MessageResult<NetworkCredential> ExractClientCredentialsFromHeader(HttpContext context) {
            var authorzation = context.Request.Headers[OAuth2Consts.Header_Authorization].FirstOrDefault();

            var mr = new MessageResult<NetworkCredential>();

            if (string.IsNullOrWhiteSpace(authorzation)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "no authorization header";
                //_logger.LogWarning(mr.MsgCodeDescription);    // ignore log, because credential may sent in request body, see 'ExractClientCredentials' method
                return mr;
            }

            // RFC 7617: only "Basic <base64>" is supported here.
            const string basicPrefix = "Basic ";
            if (!authorzation.StartsWith(basicPrefix, StringComparison.OrdinalIgnoreCase)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "authorization scheme must be 'Basic'";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }
            var encoded = authorzation.Substring(basicPrefix.Length).Trim();
            if (string.IsNullOrEmpty(encoded)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header format";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            string authStr;
            try {
                // RFC 7617 mandates STANDARD base64, not base64url.
                authStr = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            } catch (FormatException) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "authorization header base64 decode failed";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            // RFC 7617: split on the FIRST colon only — the password may legitimately contain ':'.
            var colonIdx = authStr.IndexOf(':');
            if (colonIdx <= 0 || colonIdx == authStr.Length - 1) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "invalid authorization header segments length";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            var user = authStr.Substring(0, colonIdx);
            var pass = authStr.Substring(colonIdx + 1);
            mr.Result = new NetworkCredential(user, pass);
            return mr;
        }

        /// <summary>
        /// extract client credential from request body
        /// </summary>
        protected virtual MessageResult<NetworkCredential> ExractClientCredentialsFromBody(HttpContext context) {
            var id = context.Request.Form[OAuth2Consts.Form_ClientID].FirstOrDefault();

            var mr = new MessageResult<NetworkCredential>();

            if (string.IsNullOrWhiteSpace(id)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client id is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            var secret = context.Request.Form[OAuth2Consts.Form_ClientSecret].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(secret)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client secret is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            mr.Result = new NetworkCredential(id, secret);
            return mr;
        }

        /// <summary>
        /// Verify client id & secret 
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential) {
            var mr = new MessageResult<IClient>();

            var client = await _clientStore.GetClientAsync(credential.UserName);
            if (client == null) {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "client not exists";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            // Didn't provide Secret, but client is public
            if (string.IsNullOrEmpty(credential.Password) && client.IsPublic) {
                // allow public clients to skip secret validation
                mr.Result = client;
                return mr;
            }

            if (!FixedTimeEquals(credential.Password, client.Secret)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            mr.Result = client;
            return mr;
        }

        // Constant-time string comparison — protects client_secret check from timing attacks.
        // netstandard2.0 lacks CryptographicOperations.FixedTimeEquals; implement equivalent here.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool FixedTimeEquals(string a, string b) {
            if (a == null || b == null) return a == b;
            var ab = Encoding.UTF8.GetBytes(a);
            var bb = Encoding.UTF8.GetBytes(b);
            var min = Math.Min(ab.Length, bb.Length);
            int diff = ab.Length ^ bb.Length;
            for (int i = 0; i < min; i++) {
                diff |= ab[i] ^ bb[i];
            }
            return diff == 0;
        }

        /// <summary>
        /// Verify client id & secret, grant type
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType) {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(grantType)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "grant type is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            mr = await VerifyClientAsync(credential);
            if (!mr.IsSuccess) return mr;

            ValidateGrants(mr, mr.Result, grantType);
            if (!mr.IsSuccess) return mr;

            return mr;
        }

        /// <summary>
        /// Verify client id & secret, grant type, scopes
        /// </summary>
        public virtual async Task<MessageResult<IClient>> VerifyClientAsync(NetworkCredential credential, string grantType, string scopesStr) {
            var mr = new MessageResult<IClient>();

            if (string.IsNullOrWhiteSpace(scopesStr)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            mr = await this.VerifyClientAsync(credential, grantType);
            if (!mr.IsSuccess) return mr;

            ValidateScopes(mr, mr.Result, scopesStr);
            if (!mr.IsSuccess) return mr;

            return mr;
        }

        /// <summary>
        /// Verify client id & secret, response type, scopes, redirect uri
        /// </summary>
        public async Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string responseType, string redirectURI, string scopesStr, string state) {
            var mr = new MessageResult<IClient>();
            if (string.IsNullOrWhiteSpace(clientID)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client id is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(responseType)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "response type is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(redirectURI)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "redirect uri is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(scopesStr)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "scope is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            var client = await _clientStore.GetClientAsync(clientID);
            if (null == client) {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            ValidateRedirectURIs(mr, client, redirectURI);
            if (!mr.IsSuccess) return mr;

            ValidateScopes(mr, client, scopesStr);
            if (!mr.IsSuccess) return mr;

            ValidateResponseType(mr, client, responseType);
            if (!mr.IsSuccess) return mr;

            mr.Result = client;
            return mr;
        }

        /// <summary>
        /// verify client id & redirect uri
        /// </summary>
        public async Task<MessageResult<IClient>> VerifyClientAsync(string clientID, string redirectURI) {
            var mr = new MessageResult<IClient>();
            if (string.IsNullOrWhiteSpace(clientID)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "client id is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }
            if (string.IsNullOrWhiteSpace(redirectURI)) {
                mr.MsgCode = OAuth2Consts.Err_invalid_request;
                mr.MsgCodeDescription = "redirect uri is missing";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            var client = await _clientStore.GetClientAsync(clientID);
            if (null == client) {
                mr.MsgCode = OAuth2Consts.Err_invalid_client;
                mr.MsgCodeDescription = "invalid client";
                _logger.LogWarning(mr.MsgCodeDescription);
                return mr;
            }

            ValidateRedirectURIs(mr, client, redirectURI);

            return mr;
        }

        protected virtual void ValidateRedirectURIs(MessageResult<IClient> mr, IClient client, string redirectURI) {
            if (client.RedirectUris == null || !client.RedirectUris.Any()) {
                mr.MsgCode = OAuth2Consts.Err_access_denied;
                mr.MsgCodeDescription = $"no redirect uri is allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            } else if (!client.RedirectUris.Contains(redirectURI)) {
                mr.MsgCode = OAuth2Consts.Err_access_denied;
                mr.MsgCodeDescription = $"'{redirectURI}' is not allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateScopes(MessageResult<IClient> mr, IClient client, string scopesStr) {
            if (client.Scopes == null) {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"no scope is allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
                return;
            }

            var scopeArray = scopesStr.Split(OAuth2Consts.Seperator_Scope);
            var notAllowedScopes = scopeArray.Except(client.Scopes);
            if (notAllowedScopes.Any()) {
                mr.MsgCode = OAuth2Consts.Err_invalid_scope;
                mr.MsgCodeDescription = $"scope '{string.Join(", ", notAllowedScopes)}' is not allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateGrants(MessageResult<IClient> mr, IClient client, string grantType) {
            if (client.Grants == null || !client.Grants.Contains(grantType)) {
                mr.MsgCode = OAuth2Consts.Err_unauthorized_client;
                mr.MsgCodeDescription = $"'{grantType}' grant is not allowed for '{client.ID}'";
                _logger.LogWarning(mr.MsgCodeDescription);
            }
        }

        protected virtual void ValidateResponseType(MessageResult<IClient> mr, IClient client, string responseType) {
            if (responseType == OAuth2Consts.ResponseType_Code) {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_AuthorizationCode);
            } else if (responseType == OAuth2Consts.ResponseType_Token) {
                ValidateGrants(mr, client, OAuth2Consts.GrantType_Implicit);
            }
        }
    }
}
