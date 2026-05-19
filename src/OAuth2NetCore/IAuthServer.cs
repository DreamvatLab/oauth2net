using Microsoft.AspNetCore.Http;

namespace OAuth2NetCore {
    public interface IAuthServer
    {
        RequestDelegate AuthorizeRequestHandler { get; }
        RequestDelegate TokenRequestHandler { get; }
        RequestDelegate EndSessionRequestHandler { get; }
        RequestDelegate ClearTokenRequestHandler { get; }
        RequestDelegate OpenIDConfigRequestHandler { get; }
        RequestDelegate OpenIDJwksRequestHandler { get; }

    }
}
