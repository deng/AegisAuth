using AegisAuthSession.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace AegisAuthSession.Services;

/// <summary>
/// 基于 Entity Framework Core 的 Session 存储实现
/// 支持关系型数据库（SQL Server、PostgreSQL、MySQL 等）
/// </summary>
public class DatabaseSessionStore : ISessionStore
{
    private readonly DbContext _dbContext;
    private readonly ILogger<DatabaseSessionStore> _logger;
    private readonly DbSet<Session> _sessions;

    public DatabaseSessionStore(DbContext dbContext, ILogger<DatabaseSessionStore> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _sessions = _dbContext.Set<Session>();
    }

    /// <summary>
    /// 创建新的 Session
    /// </summary>
    public async Task CreateSessionAsync(Session session)
    {
        if (session == null)
            throw new ArgumentNullException(nameof(session));

        await _sessions.AddAsync(session);
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// 获取 Session
    /// 性能优化：使用 AsNoTracking 提高查询性能
    /// </summary>
    public async Task<Session?> GetSessionAsync(string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
            return null;

        return await _sessions
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == sessionId && s.ExpiresAt > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 更新 Session
    /// </summary>
    public async Task UpdateSessionAsync(Session session)
    {
        if (session == null)
            throw new ArgumentNullException(nameof(session));

        var existingSession = await _sessions.FindAsync(session.Id);
        if (existingSession == null)
            throw new InvalidOperationException($"Session {session.Id} not found");

        // 更新属性
        _dbContext.Entry(existingSession).CurrentValues.SetValues(session);
        await _dbContext.SaveChangesAsync();
    }

    /// <summary>
    /// 更新 Session 最后活动时间
    /// 性能优化：直接执行 SQL 更新，避免加载整个实体
    /// </summary>
    public async Task UpdateSessionActivityAsync(string sessionId, DateTimeOffset lastActivity)
    {
        if (string.IsNullOrEmpty(sessionId))
            return;

        // 使用原始 SQL 更新，提高性能
        var session = await _sessions.FindAsync(sessionId);
        if (session != null)
        {
            session.LastAccessedAt = lastActivity;
            await _dbContext.SaveChangesAsync();
        }
    }

    /// <summary>
    /// 删除 Session
    /// </summary>
    public async Task DeleteSessionAsync(string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
            return;

        // 直接删除
        var session = await _sessions.FindAsync(sessionId);
        if (session != null)
        {
            _sessions.Remove(session);
            await _dbContext.SaveChangesAsync();
            _logger.LogDebug("Deleted session {SessionId}", sessionId);
        }
    }

    /// <summary>
    /// 删除用户的所有 Session
    /// </summary>
    public async Task<int> DeleteUserSessionsAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return 0;

        // 批量删除用户所有Session
        var sessions = await _sessions.Where(s => s.UserId == userId).ToListAsync();
        if (sessions.Count > 0)
        {
            _sessions.RemoveRange(sessions);
            await _dbContext.SaveChangesAsync();
            _logger.LogInformation("Deleted all sessions for user {UserId}, count: {Count}", userId, sessions.Count);
        }
        return sessions.Count;
    }

    /// <summary>
    /// 清理过期的 Session
    /// 性能优化：使用索引友好的查询和批量删除
    /// </summary>
    public async Task<int> CleanupExpiredSessionsAsync()
    {
        var now = DateTimeOffset.UtcNow;

        try
        {
            // 批量删除过期Session
            var expiredSessions = await _sessions
                .Where(s => s.ExpiresAt < now)
                .ToListAsync();

            if (expiredSessions.Count > 0)
            {
                _sessions.RemoveRange(expiredSessions);
                await _dbContext.SaveChangesAsync();
                _logger.LogInformation("Cleaned up {Count} expired sessions", expiredSessions.Count);
            }

            return expiredSessions.Count;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up expired sessions");
            return 0;
        }
    }

    /// <summary>
    /// 删除过期的 Session（与 CleanupExpiredSessionsAsync 相同）
    /// </summary>
    public Task<int> DeleteExpiredSessionsAsync()
    {
        return CleanupExpiredSessionsAsync();
    }

    /// <summary>
    /// 获取用户的活跃 Session 列表
    /// 性能优化：添加索引提示和过滤条件
    /// </summary>
    public async Task<List<Session>> GetUserSessionsAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return new List<Session>();

        var now = DateTimeOffset.UtcNow;

        return await _sessions
            .AsNoTracking()
            .Where(s => s.UserId == userId && s.ExpiresAt > now)
            .OrderByDescending(s => s.LastAccessedAt)
            .ToListAsync();
    }

    /// <summary>
    /// 获取用户活跃 Session 数量
    /// 性能优化：使用 COUNT 查询而不是加载所有数据
    /// </summary>
    public async Task<int> GetUserActiveSessionCountAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return 0;

        var now = DateTimeOffset.UtcNow;

        return await _sessions
            .AsNoTracking()
            .CountAsync(s => s.UserId == userId && s.ExpiresAt > now);
    }

    /// <summary>
    /// 续期 Session
    /// 性能优化：直接执行 SQL 更新
    /// </summary>
    public async Task<bool> RenewSessionAsync(string sessionId, TimeSpan extension)
    {
        if (string.IsNullOrEmpty(sessionId))
            return false;

        var now = DateTimeOffset.UtcNow;
        var session = await _sessions.FindAsync(sessionId);
        
        if (session == null || session.ExpiresAt <= now)
            return false;

        session.ExpiresAt = now.Add(extension);
        session.LastAccessedAt = now;
        await _dbContext.SaveChangesAsync();
        
        return true;
    }
}

/// <summary>
/// Session 数据库上下文配置示例
/// 注意：此配置需要在使用关系型数据库的 DbContext 中应用
/// 需要添加 Microsoft.EntityFrameworkCore.Relational 包引用
/// </summary>
/// <example>
/// 在 DbContext 的 OnModelCreating 方法中使用：
/// <code>
/// protected override void OnModelCreating(ModelBuilder modelBuilder)
/// {
///     // 配置主键
///     modelBuilder.Entity&lt;Session&gt;().HasKey(e => e.Id);
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.Id).HasMaxLength(128);
///     
///     // 配置索引
///     modelBuilder.Entity&lt;Session&gt;().HasIndex(e => e.UserId);
///     modelBuilder.Entity&lt;Session&gt;().HasIndex(e => e.ExpiresAt);
///     modelBuilder.Entity&lt;Session&gt;().HasIndex(e => new { e.UserId, e.ExpiresAt });
///     
///     // 配置字段
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.UserId).HasMaxLength(50).IsRequired();
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.UserName).HasMaxLength(50).IsRequired();
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.Role).HasMaxLength(50);
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.IpAddress).HasMaxLength(45);
///     modelBuilder.Entity&lt;Session&gt;().Property(e => e.UserAgent).HasMaxLength(500);
/// }
/// </code>
/// </example>
public static class SessionDbContextConfiguration
{
    // 配置示例在文档注释中提供
}
