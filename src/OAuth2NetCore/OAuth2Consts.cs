namespace OAuth2NetCore {
    public static class OAuth2Consts {
        public const string Header_Authorization = "Authorization";
        public const string Header_CacheControl = "Cache-Control";
        public const string Header_CacheControl_Value = "no-store";
        public const string Header_Pragma = "Pragma";
        public const string Header_Pragma_Value = "no-cache";
        public const string ContentType_Json = "application/json;charset=UTF-8";
        public const string Claim_Role = "role";
        public const string Claim_Name = "name";
        public const string Claim_Audience = "aud";
        public const string Claim_Issuer = "iss";
        public const string Claim_AccessTokenExpire = "exp";
        public const string Claim_RefreshTokenExpire = "rexp";
        public const string Claim_Scope = "scope";
        public const string Claim_ClienID = "client_id";
        public const string Form_GrantType = "grant_type";
        public const string Form_ClientID = "client_id";
        public const string Form_ClientSecret = "client_secret";
        public const string Form_RedirectUri = "redirect_uri";
        public const string Form_ReturnUrl = "returnUrl";
        public const string Form_State = "state";
        public const string Form_Scope = "scope";
        public const string Form_Code = "code";
        public const string Form_EndSessionID = "es_id";
        public const string Form_Username = "username";
        public const string Form_Password = "password";
        public const string Form_ResponseType = "response_type";
        public const string Form_AccessToken = "access_token";
        public const string Form_RefreshToken = "refresh_token";
        public const string Form_TokenType = "token_type";
        public const string Form_ExpiresIn = "expires_in";
        public const string Form_CodeChallenge = "code_challenge";
        public const string Form_CodeChallengeMethod = "code_challenge_method";
        public const string Form_CodeVerifier = "code_verifier";
        public const string ResponseType_Token = "token";
        public const string ResponseType_Code = "code";
        public const string GrantType_Client = "client_credentials";
        public const string GrantType_AuthorizationCode = "authorization_code";
        public const string GrantType_Implicit = "implicit";
        public const string GrantType_ResourceOwner = "password";
        public const string GrantType_RefreshToken = "refresh_token";
        //public const string Format_Token1 = "{{\"" + Form_AccessToken + "\":\"{0}\",\"" + Form_ExpiresIn + "\":{1},\"" + Form_Scope + "\":\"{2}\",\"" + Form_TokenType + "\":\"Bearer\"}}";
        //public const string Format_Token2 = "{{\"" + Form_AccessToken + "\":\"{0}\",\"" + Form_RefreshToken + "\":\"{1}\",\"" + Form_ExpiresIn + "\":{2},\"" + Form_RefreshTokenExpiresIn + "\":{3},\"" + Form_Scope + "\":\"{4}\",\"" + Form_TokenType + "\":\"Bearer\"}}";
        public const string Format_Error = "{{\"error\":\"{0}\", \"error_description\":\"{1}\"}}";
        public const string Msg_Success = "";
        /// <summary>
        /// MsgCode returned by ITokenClaimBuilder when the subject is no longer allowed to obtain tokens
        /// (e.g. the user has been disabled or removed).
        /// </summary>
        public const string Msg_SubjectDenied = "subject_denied";
        public const string Err_invalid_request = "invalid_request";
        public const string Err_invalid_client = "invalid_client";
        public const string Err_invalid_grant = "invalid_grant";
        public const string Err_unauthorized_client = "unauthorized_client";
        public const string Err_unsupported_grant_type = "unsupported_grant_type";
        public const string Err_unsupported_response_type = "unsupported_response_type";
        public const string Err_invalid_scope = "invalid_scope";
        public const string Err_access_denied = "access_denied";
        public const string Err_description = "error_description";
        public const string Err_uri = "error_uri";
        public const string Pkce_Plain = "plain";
        public const string Pkce_S256 = "S256";
        //public const string Config_OAuth_PkceRequired = "OAuth:PkceRequired";
        public const string Token_Access = "access_token";
        public const string Token_Refresh = "refresh_token";
        public const string Token_ExpiresAt = "expires_at";
        public const string Token_Type_Bearer = "Bearer";
        public const string UtcTimesamp = "yyyy-MM-ddTHH:mm:ss.0000000+00:00";
        public const string Cookie_TokenDTO = "auth.token";
        public const char Seperator_Scope = ' ';
        public static readonly char[] Seperators_Auth = new char[] { ':' };

    }
}