using AegisAuth.Core.Repositories;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace AegisAuthJwt.Workers;

/// <summary>
/// 过期令牌清理Worker配置
/// </summary>
public class TokenCleanupWorkerOptions
{
    /// <summary>
    /// 是否启用清理
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// 清理间隔（小时）
    /// </summary>
    public int CleanupIntervalHours { get; set; } = 24;
}

/// <summary>
/// 过期令牌清理Worker
/// </summary>
public class TokenCleanupWorker : BackgroundService
{
    private readonly ILogger<TokenCleanupWorker> m_Logger;
    private readonly IServiceProvider m_ServiceProvider;
    private readonly TokenCleanupWorkerOptions m_Options;
    private readonly PeriodicTimer m_Timer;

    public TokenCleanupWorker(
        ILogger<TokenCleanupWorker> logger,
        IServiceProvider serviceProvider,
        IOptions<TokenCleanupWorkerOptions> options)
    {
        m_Logger = logger;
        m_ServiceProvider = serviceProvider;
        m_Options = options.Value;
        m_Timer = new PeriodicTimer(TimeSpan.FromHours(m_Options.CleanupIntervalHours));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        m_Logger.LogInformation("过期令牌清理Worker启动，清理间隔: {interval}小时", m_Options.CleanupIntervalHours);

        // 首次清理
        await CleanupExpiredTokensAsync(stoppingToken);

        // 定时清理
        while (!stoppingToken.IsCancellationRequested && await m_Timer.WaitForNextTickAsync(stoppingToken))
        {
            await CleanupExpiredTokensAsync(stoppingToken);
        }
    }

    /// <summary>
    /// 清理过期的令牌
    /// </summary>
    private async Task CleanupExpiredTokensAsync(CancellationToken stoppingToken)
    {
        if (!m_Options.Enabled)
        {
            m_Logger.LogInformation("过期令牌清理已禁用");
            return;
        }

        if (stoppingToken.IsCancellationRequested)
            return;

        try
        {
            m_Logger.LogInformation("开始清理过期令牌");

            using var scope = m_ServiceProvider.CreateScope();
            var tokenBlacklistRepository = scope.ServiceProvider.GetRequiredService<ITokenBlacklistRepository>();

            // 执行清理操作
            var deletedCount = await tokenBlacklistRepository.CleanupExpiredTokensAsync();
            await tokenBlacklistRepository.CommitAsync();

            if (deletedCount > 0)
            {
                m_Logger.LogInformation("过期令牌清理完成，共清理 {count} 条过期记录", deletedCount);
            }
            else
            {
                m_Logger.LogInformation("过期令牌清理完成，没有需要清理的过期记录");
            }
        }
        catch (Exception ex)
        {
            m_Logger.LogError(ex, "清理过期令牌时发生错误");
        }
    }

    public override void Dispose()
    {
        m_Timer?.Dispose();
        base.Dispose();
    }
}
