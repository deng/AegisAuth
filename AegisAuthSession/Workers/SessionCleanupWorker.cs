using AegisAuthSession.Services;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace AegisAuthSession.Workers;

/// <summary>
/// 过期 Session 清理 Worker 配置
/// </summary>
public class SessionCleanupWorkerOptions
{
    /// <summary>
    /// 是否启用清理
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// 清理间隔（分钟）
    /// </summary>
    public int CleanupIntervalMinutes { get; set; } = 60;
}

/// <summary>
/// 过期 Session 清理 Worker
/// </summary>
public class SessionCleanupWorker : BackgroundService
{
    private readonly ILogger<SessionCleanupWorker> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly SessionCleanupWorkerOptions _options;
    private readonly PeriodicTimer _timer;

    public SessionCleanupWorker(
        ILogger<SessionCleanupWorker> logger,
        IServiceProvider serviceProvider,
        IOptions<SessionCleanupWorkerOptions> options)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _options = options.Value;
        _timer = new PeriodicTimer(TimeSpan.FromMinutes(_options.CleanupIntervalMinutes));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("过期 Session 清理 Worker 启动，清理间隔: {interval} 分钟", _options.CleanupIntervalMinutes);

        // 首次清理
        await CleanupExpiredSessionsAsync(stoppingToken);

        // 定时清理
        while (!stoppingToken.IsCancellationRequested && await _timer.WaitForNextTickAsync(stoppingToken))
        {
            await CleanupExpiredSessionsAsync(stoppingToken);
        }
    }

    /// <summary>
    /// 清理过期的 Session
    /// </summary>
    private async Task CleanupExpiredSessionsAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("过期 Session 清理已禁用");
            return;
        }

        if (stoppingToken.IsCancellationRequested)
            return;

        try
        {
            _logger.LogInformation("开始清理过期 Session");

            using var scope = _serviceProvider.CreateScope();
            var sessionStore = scope.ServiceProvider.GetRequiredService<ISessionStore>();

            // 执行清理操作
            var deletedCount = await sessionStore.DeleteExpiredSessionsAsync();

            if (deletedCount > 0)
            {
                _logger.LogInformation("过期 Session 清理完成，共清理 {count} 条过期记录", deletedCount);
            }
            else
            {
                _logger.LogInformation("过期 Session 清理完成，没有需要清理的过期记录");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "清理过期 Session 时发生错误");
        }
    }

    public override void Dispose()
    {
        _timer?.Dispose();
        base.Dispose();
    }
}
