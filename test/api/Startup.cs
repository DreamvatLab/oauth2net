using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using shared;
using SimpleInjector;
using System.Security.Cryptography.X509Certificates;

namespace api {
    public class Startup
    {
        static readonly Container _container = ContainerFactory.CreateWithPropertyInjection<ImportPropertySelectionBehavior>();
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            services.AddOAuth2Resource(o =>
            {
                var cert = X509CertificateLoader.LoadCertificateFromFile(Configuration.GetValue<string>("CertPath"));
                o.IssuerSigningKey = new RsaSecurityKey(cert.GetRSAPublicKey());
                o.ValidAudience = Configuration.GetValue<string>("OAuth2:ValidAudience");
                o.ValidIssuer = Configuration.GetValue<string>("OAuth2:ValidIssuer");
            });

            services.AddSimpleInjector(_container, options =>
            {
                options.AddAspNetCore()
                    .AddControllerActivation();
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseReverseProxy();

            app.UseSimpleInjector(_container);

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            _container.Verify();
        }
    }
}
