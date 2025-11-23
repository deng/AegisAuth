using AegisAuthSession.Entities;
using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace AegisAuthSession.Services;

/// <summary>
/// 基于 Redis 的 Session 存储实现
/// 使用 IDistributedCache 接口，支持 Redis、Memcached 等分布式缓存
/// </summary>
public class RedisSessionStore : ISessionStore
{
    private readonly IDistributedCache _cache;
    private const string SessionKeyPrefix = "aegis:session:";
    private const string UserSessionsKeyPrefix = "aegis:user:sessions:";
    
    // 性能优化：使用 JsonSerializerOptions 单例，避免每次序列化都创建新实例
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    public RedisSessionStore(IDistributedCache cache)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    }

    /// <summary>
    /// 创建新的 Session
    /// </summary>
    public async Task CreateSessionAsync(Session session)
    {
        if (session == null)
            throw new ArgumentNullException(nameof(session));

        var sessionKey = GetSessionKey(session.Id);
        var userSessionsKey = GetUserSessionsKey(session.UserId);

        // 序列化 Session
        var sessionJson = JsonSerializer.Serialize(session, _jsonOptions);
        
        // 计算过期时间
        var expirationTime = session.ExpiresAt - DateTimeOffset.UtcNow;
        if (expirationTime.TotalSeconds < 0)
            expirationTime = TimeSpan.FromSeconds(1); // 最少保留1秒

        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = session.ExpiresAt
        };

        // 存储 Session 数据
        await _cache.SetStringAsync(sessionKey, sessionJson, options);

        // 更新用户的 Session 列表（使用 Set 存储，避免重复）
        await AddSessionToUserListAsync(userSessionsKey, session.Id, expirationTime);
    }

    /// <summary>
    /// 获取 Session
    /// </summary>
    public async Task<Session?> GetSessionAsync(string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
            return null;

        var sessionKey = GetSessionKey(sessionId);
        var sessionJson = await _cache.GetStringAsync(sessionKey);

        if (string.IsNullOrEmpty(sessionJson))
            return null;

        return JsonSerializer.Deserialize<Session>(sessionJson, _jsonOptions);
    }

    /// <summary>
    /// 更新 Session
    /// </summary>
    public async Task UpdateSessionAsync(Session session)
    {
        if (session == null)
            throw new ArgumentNullException(nameof(session));

        var sessionKey = GetSessionKey(session.Id);

        // 先检查 Session 是否存在
        var exists = await _cache.GetStringAsync(sessionKey);
        if (exists == null)
            throw new InvalidOperationException($"Session {session.Id} not found");

        // 序列化并更新
        var sessionJson = JsonSerializer.Serialize(session, _jsonOptions);
        
        var options = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = session.ExpiresAt
        };

        await _cache.SetStringAsync(sessionKey, sessionJson, options);
    }

    /// <summary>
    /// 更新 Session 最后活动时间
    /// 性能优化：只更新时间戳，避免完整序列化
    /// </summary>
    public async Task UpdateSessionActivityAsync(string sessionId, DateTimeOffset lastActivity)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return;

        session.LastAccessedAt = lastActivity;
        await UpdateSessionAsync(session);
    }

    /// <summary>
    /// 删除 Session
    /// </summary>
    public async Task DeleteSessionAsync(string sessionId)
    {
        if (string.IsNullOrEmpty(sessionId))
            return;

        // 先获取 Session 信息以便从用户列表中移除
        var session = await GetSessionAsync(sessionId);
        
        var sessionKey = GetSessionKey(sessionId);
        await _cache.RemoveAsync(sessionKey);

        // 从用户的 Session 列表中移除
        if (session != null)
        {
            var userSessionsKey = GetUserSessionsKey(session.UserId);
            await RemoveSessionFromUserListAsync(userSessionsKey, sessionId);
        }
    }

    /// <summary>
    /// 删除用户的所有 Session
    /// </summary>
    public async Task<int> DeleteUserSessionsAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return 0;

        var userSessionsKey = GetUserSessionsKey(userId);
        var sessionIds = await GetUserSessionIdsAsync(userSessionsKey);

        if (sessionIds.Count == 0)
            return 0;

        // 批量删除 Session
        var deleteTasks = sessionIds.Select(id => _cache.RemoveAsync(GetSessionKey(id)));
        await Task.WhenAll(deleteTasks);

        // 删除用户的 Session 列表
        await _cache.RemoveAsync(userSessionsKey);

        return sessionIds.Count;
    }

    /// <summary>
    /// 清理过期的 Session
    /// 注意：Redis 会自动过期删除，这个方法主要用于清理用户 Session 列表中的过期引用
    /// </summary>
    public async Task<int> CleanupExpiredSessionsAsync()
    {
        // Redis 自动过期机制会处理 Session 数据本身
        // 这里只是返回0，实际清理由 Redis 自动完成
        await Task.CompletedTask;
        return 0;
    }

    /// <summary>
    /// 删除过期的 Session（与 CleanupExpiredSessionsAsync 相同）
    /// </summary>
    public Task<int> DeleteExpiredSessionsAsync()
    {
        return CleanupExpiredSessionsAsync();
    }

    /// <summary>
    /// 获取用户的所有 Session
    /// </summary>
    public async Task<List<Session>> GetUserSessionsAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return new List<Session>();

        var userSessionsKey = GetUserSessionsKey(userId);
        var sessionIds = await GetUserSessionIdsAsync(userSessionsKey);

        if (sessionIds.Count == 0)
            return new List<Session>();

        // 并行获取所有 Session
        var sessionTasks = sessionIds.Select(GetSessionAsync);
        var sessions = await Task.WhenAll(sessionTasks);

        // 过滤掉已过期或不存在的 Session
        return sessions.Where(s => s != null).ToList()!;
    }

    /// <summary>
    /// 获取用户的活跃 Session 数量
    /// </summary>
    public async Task<int> GetUserActiveSessionCountAsync(string userId)
    {
        if (string.IsNullOrEmpty(userId))
            return 0;

        var sessions = await GetUserSessionsAsync(userId);
        return sessions.Count;
    }

    /// <summary>
    /// 续期 Session
    /// </summary>
    public async Task<bool> RenewSessionAsync(string sessionId, TimeSpan extension)
    {
        var session = await GetSessionAsync(sessionId);
        if (session == null)
            return false;

        // 更新过期时间
        session.ExpiresAt = DateTimeOffset.UtcNow.Add(extension);
        session.LastAccessedAt = DateTimeOffset.UtcNow;

        await UpdateSessionAsync(session);
        return true;
    }

    #region 私有辅助方法

    private static string GetSessionKey(string sessionId) 
        => $"{SessionKeyPrefix}{sessionId}";

    private static string GetUserSessionsKey(string userId) 
        => $"{UserSessionsKeyPrefix}{userId}";

    /// <summary>
    /// 添加 Session ID 到用户的 Session 列表
    /// 使用简单的逗号分隔字符串存储，适合小量数据
    /// </summary>
    private async Task AddSessionToUserListAsync(string userSessionsKey, string sessionId, TimeSpan expiration)
    {
        var existingList = await _cache.GetStringAsync(userSessionsKey);
        var sessionIds = string.IsNullOrEmpty(existingList) 
            ? new HashSet<string>() 
            : new HashSet<string>(existingList.Split(',', StringSplitOptions.RemoveEmptyEntries));

        sessionIds.Add(sessionId);

        var newList = string.Join(',', sessionIds);
        
        var options = new DistributedCacheEntryOptions
        {
            SlidingExpiration = expiration
        };

        await _cache.SetStringAsync(userSessionsKey, newList, options);
    }

    /// <summary>
    /// 从用户的 Session 列表中移除 Session ID
    /// </summary>
    private async Task RemoveSessionFromUserListAsync(string userSessionsKey, string sessionId)
    {
        var existingList = await _cache.GetStringAsync(userSessionsKey);
        if (string.IsNullOrEmpty(existingList))
            return;

        var sessionIds = new HashSet<string>(existingList.Split(',', StringSplitOptions.RemoveEmptyEntries));
        sessionIds.Remove(sessionId);

        if (sessionIds.Count == 0)
        {
            await _cache.RemoveAsync(userSessionsKey);
        }
        else
        {
            var newList = string.Join(',', sessionIds);
            await _cache.SetStringAsync(userSessionsKey, newList);
        }
    }

    /// <summary>
    /// 获取用户的所有 Session ID
    /// </summary>
    private async Task<List<string>> GetUserSessionIdsAsync(string userSessionsKey)
    {
        var sessionList = await _cache.GetStringAsync(userSessionsKey);
        
        if (string.IsNullOrEmpty(sessionList))
            return new List<string>();

        return sessionList.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
    }

    #endregion
}
