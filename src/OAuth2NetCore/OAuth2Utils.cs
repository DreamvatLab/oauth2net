using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace OAuth2NetCore {
    public static class OAuth2Utils
    {
        public static string ToSHA256Base64URL(string str)
        {
            byte[] bytes;
            using (var sha256 = SHA256.Create())
            {
                bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(str));
            }

            return Base64UrlEncoder.Encode(bytes);
        }

        /// <summary>
        /// Append key/value pairs as a query string to <paramref name="uri"/>, preserving any
        /// existing query and properly URL-encoding both key and value. Null values are skipped.
        /// </summary>
        public static string AppendQuery(string uri, IEnumerable<KeyValuePair<string, string>> parameters)
        {
            if (string.IsNullOrEmpty(uri) || parameters == null) return uri;

            var sb = new StringBuilder(uri);
            var fragmentIdx = uri.IndexOf('#');
            var hasQuery = uri.IndexOf('?', 0, fragmentIdx < 0 ? uri.Length : fragmentIdx) >= 0;
            // If there is a fragment, we must insert before it; for OAuth redirects fragments are not expected.
            foreach (var kv in parameters)
            {
                if (kv.Value == null) continue;
                sb.Append(hasQuery ? '&' : '?');
                hasQuery = true;
                sb.Append(Uri.EscapeDataString(kv.Key));
                sb.Append('=');
                sb.Append(Uri.EscapeDataString(kv.Value));
            }
            return sb.ToString();
        }

        /// <summary>
        /// Append key/value pairs as a URL fragment ("#k=v&..."). Per RFC 6749 §4.2.2, implicit
        /// grant access tokens MUST be returned in the fragment, not the query string.
        /// </summary>
        public static string AppendFragment(string uri, IEnumerable<KeyValuePair<string, string>> parameters)
        {
            if (string.IsNullOrEmpty(uri) || parameters == null) return uri;

            var sb = new StringBuilder(uri);
            var hasFragment = uri.IndexOf('#') >= 0;
            foreach (var kv in parameters)
            {
                if (kv.Value == null) continue;
                sb.Append(hasFragment ? '&' : '#');
                hasFragment = true;
                sb.Append(Uri.EscapeDataString(kv.Key));
                sb.Append('=');
                sb.Append(Uri.EscapeDataString(kv.Value));
            }
            return sb.ToString();
        }
    }
}
