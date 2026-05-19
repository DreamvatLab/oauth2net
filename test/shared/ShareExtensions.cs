using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace shared {
    public static class ShareExtensions
    {
        public static IServiceCollection AddLazySingleton<TService, TImplementation>(this IServiceCollection services)
            where TService : class
            where TImplementation : class, TService
        {
            services.AddSingleton<TService, TImplementation>();
            services.AddTransient(sp => new Lazy<TService>(() => sp.GetService<TService>()));

            return services;
        }
        public static IServiceCollection AddLazySingleton<TService>(this IServiceCollection services, Func<IServiceProvider, TService> implementationFactory)
            where TService : class
        {
            services.AddSingleton<TService>(implementationFactory);
            services.AddTransient(sp => new Lazy<TService>(() => sp.GetService<TService>()));

            return services;
        }

        public static IServiceCollection AddLazyTransient<TService, TImplementation>(this IServiceCollection services)
            where TService : class
            where TImplementation : class, TService
        {
            services.AddTransient<TService, TImplementation>();
            services.AddTransient(sp => new Lazy<TService>(() => sp.GetService<TService>()));

            return services;
        }
        public static IServiceCollection AddLazyTransient<TService>(this IServiceCollection services, Func<IServiceProvider, TService> implementationFactory)
            where TService : class
        {
            services.AddTransient<TService>(implementationFactory);
            services.AddTransient(sp => new Lazy<TService>(() => sp.GetService<TService>()));

            return services;
        }

        public static IApplicationBuilder UseReverseProxy(this IApplicationBuilder app)
        {
            var options = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };
            options.KnownIPNetworks.Clear();
            options.KnownProxies.Clear();
            app.UseForwardedHeaders(options);

            return app;
        }
    }
}
