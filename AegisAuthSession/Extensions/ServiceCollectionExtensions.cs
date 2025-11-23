using AegisAuth.Core.Services;
using AegisAuthSession.Managers;
using AegisAuthSession.Middleware;
using AegisAuthSession.Services;
using AegisAuthSession.Settings;
using AegisAuthSession.Workers;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AegisAuthSession.Extensions;

/// <summary>
/// AegisAuthSession 服务扩展方法
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// 添加 AegisAuthSession 服务（基础版本）
    /// 需要手动注册 ISessionStore、IUserRepository、ISecurityAuditLogRepository
    /// </summary>
    public static IServiceCollection AddAegisAuthSession(
        this IServiceCollection services,
        Action<SessionSetting>? configureSettings = null)
    {
        // 配置 SessionSetting
        var settings = new SessionSetting();
        configureSettings?.Invoke(settings);
        services.AddSingleton(settings);

        // 注册核心服务
        services.AddScoped<SessionAuthManager>();
        services.AddScoped<IHttpContextAccessorService, HttpContextAccessorService>();
        services.AddHttpContextAccessor();

        // 注册后台清理服务
        services.Configure<SessionCleanupWorkerOptions>(options =>
        {
            options.Enabled = true;
            options.CleanupIntervalMinutes = settings.CleanupIntervalMinutes;
        });
        services.AddHostedService<SessionCleanupWorker>();

        return services;
    }

    /// <summary>
    /// 添加 Redis Session 存储（生产环境推荐）
    /// 注意：需要先调用 services.AddStackExchangeRedisCache() 配置 Redis
    /// 或手动注册 IDistributedCache 实现
    /// </summary>
    /// <example>
    /// <code>
    /// // 先安装包：dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
    /// services.AddStackExchangeRedisCache(options =>
    /// {
    ///     options.Configuration = "localhost:6379";
    ///     options.InstanceName = "AegisAuth:";
    /// });
    /// services.AddRedisSessionStore();
    /// </code>
    /// </example>
    private static IServiceCollection AddRedisSessionStore(this IServiceCollection services)
    {
        // 注册 RedisSessionStore
        services.AddScoped<ISessionStore, RedisSessionStore>();
        return services;
    }



    /// <summary>
    /// 添加内存 Session 存储（仅用于开发/测试）
    /// 警告：不支持分布式部署，服务重启后数据丢失
    /// </summary>
    private static IServiceCollection AddMemorySessionStore(this IServiceCollection services)
    {
        services.AddScoped<ISessionStore, MemorySessionStore>();
        return services;
    }

    /// <summary>
    /// 添加数据库 Session 存储（使用 Entity Framework Core）
    /// 注意：需要先配置 DbContext
    /// </summary>
    private static IServiceCollection AddDatabaseSessionStore(this IServiceCollection services)
    {
        services.AddScoped<ISessionStore, DatabaseSessionStore>();
        return services;
    }

    /// <summary>
    /// 添加完整的 AegisAuthSession 服务（包含内存存储，仅用于开发/测试）
    /// 警告：不支持分布式部署，服务重启后数据丢失
    /// </summary>
    /// <example>
    /// <code>
    /// services.AddAegisAuthSessionWithMemory(settings =>
    /// {
    ///     settings.SessionExpirationMinutes = 30;
    ///     settings.MaxSessionsPerUser = 5;
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddAegisAuthSessionWithMemory(
        this IServiceCollection services,
        Action<SessionSetting>? configureSettings = null)
    {
        // 添加基础服务
        services.AddAegisAuthSession(configureSettings);

        // 添加内存存储
        services.AddMemorySessionStore();

        return services;
    }

    /// <summary>
    /// 添加完整的 AegisAuthSession 服务（包含 Redis 存储）
    /// 注意：需要先配置 Redis 缓存
    /// </summary>
    /// <example>
    /// <code>
    /// // 安装包：dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
    /// services.AddStackExchangeRedisCache(options =>
    /// {
    ///     options.Configuration = "localhost:6379";
    ///     options.InstanceName = "AegisAuth:";
    /// });
    /// services.AddAegisAuthSessionWithRedis();
    /// </code>
    /// </example>
    public static IServiceCollection AddAegisAuthSessionWithRedis(
        this IServiceCollection services,
        Action<SessionSetting>? configureSettings = null)
    {
        // 添加基础服务
        services.AddAegisAuthSession(configureSettings);

        // 添加 Redis 存储
        services.AddRedisSessionStore();

        return services;
    }

    /// <summary>
    /// 添加完整的 AegisAuthSession 服务（包含数据库存储）
    /// 注意：需要先配置 DbContext
    /// </summary>
    public static IServiceCollection AddAegisAuthSessionWithDatabase(
        this IServiceCollection services,
        Action<SessionSetting>? configureSettings = null)
    {
        // 添加基础服务
        services.AddAegisAuthSession(configureSettings);

        // 添加数据库存储
        services.AddDatabaseSessionStore();

        return services;
    }
}

/// <summary>
/// AegisAuthSession 应用扩展方法
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// 使用 Session 验证中间件
    /// </summary>
    public static IApplicationBuilder UseAegisAuthSession(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SessionValidationMiddleware>();
    }
}
