using AegisAuthBase.Services;
using AegisAuthBase.Settings;
using Fido2NetLib;
using Microsoft.Extensions.DependencyInjection;

namespace AegisAuthBase.Extensions;

/// <summary>
/// WebAuthn 服务注册扩展
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 添加 WebAuthn 服务
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configureOptions">配置选项</param>
    /// <returns>服务集合</returns>
    public static IServiceCollection AddWebAuthnServices(
        this IServiceCollection services,
        Action<PasskeySettings>? configureOptions = null)
    {
        // 配置选项
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.Configure<PasskeySettings>(settings =>
            {
                settings.ServerName = "localhost";
                settings.ServerDomain = "localhost";
                settings.Origins = new HashSet<string> { "https://localhost", "http://localhost" };
            });
        }

        // 注册 Fido2
        services.AddScoped<IFido2>(sp =>
        {
            var settings = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<PasskeySettings>>().Value;
            return new Fido2(new Fido2Configuration
            {
                ServerDomain = settings.ServerDomain,
                ServerName = settings.ServerName,
                Origins = settings.Origins
            });
        });

        // 注册服务
        services.AddScoped<IPasskeyService, PasskeyService>();

        return services;
    }
}