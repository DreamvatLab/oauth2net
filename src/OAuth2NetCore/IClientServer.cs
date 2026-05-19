using Microsoft.AspNetCore.Http;

namespace OAuth2NetCore {
    public interface IClientServer
    {
        RequestDelegate SignInRequestHandler { get; }
        RequestDelegate SignOutRequestHandler { get; }
        RequestDelegate SignOutCallbackRequestHandler { get; }
    }
}
