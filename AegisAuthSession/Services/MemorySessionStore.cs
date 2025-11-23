using AegisAuthSession.Entities;

namespace AegisAuthSession.Services;

/// <summary>
/// 内存 Session 存储实现（仅用于开发和测试）
/// 警告：不支持分布式部署，服务重启后数据丢失
/// </summary>
public class MemorySessionStore : ISessionStore
{
    private readonly Dictionary<string, Session> _sessions = new();
    private readonly object _lock = new();

    public Task CreateSessionAsync(Session session)
    {
        lock (_lock)
        {
            _sessions[session.Id] = session;
        }
        return Task.CompletedTask;
    }

    public Task<Session?> GetSessionAsync(string sessionId)
    {
        lock (_lock)
        {
            return Task.FromResult(_sessions.TryGetValue(sessionId, out var session) ? session : null);
        }
    }

    public Task UpdateSessionAsync(Session session)
    {
        lock (_lock)
        {
            _sessions[session.Id] = session;
        }
        return Task.CompletedTask;
    }

    public Task UpdateSessionActivityAsync(string sessionId, DateTimeOffset lastActivity)
    {
        lock (_lock)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                session.LastAccessedAt = lastActivity;
            }
        }
        return Task.CompletedTask;
    }

    public Task DeleteSessionAsync(string sessionId)
    {
        lock (_lock)
        {
            _sessions.Remove(sessionId);
        }
        return Task.CompletedTask;
    }

    public Task<int> DeleteUserSessionsAsync(string userId)
    {
        lock (_lock)
        {
            var userSessions = _sessions.Where(s => s.Value.UserId == userId).ToList();
            foreach (var session in userSessions)
            {
                _sessions.Remove(session.Key);
            }
            return Task.FromResult(userSessions.Count);
        }
    }

    public Task<int> CleanupExpiredSessionsAsync()
    {
        lock (_lock)
        {
            var expiredSessions = _sessions.Where(s => s.Value.IsExpired).ToList();
            foreach (var session in expiredSessions)
            {
                _sessions.Remove(session.Key);
            }
            return Task.FromResult(expiredSessions.Count);
        }
    }

    public Task<List<Session>> GetUserSessionsAsync(string userId)
    {
        lock (_lock)
        {
            var userSessions = _sessions.Where(s => s.Value.UserId == userId).Select(s => s.Value).ToList();
            return Task.FromResult(userSessions);
        }
    }

    public Task<int> GetUserActiveSessionCountAsync(string userId)
    {
        lock (_lock)
        {
            var count = _sessions.Count(s => s.Value.UserId == userId && !s.Value.IsExpired);
            return Task.FromResult(count);
        }
    }

    public Task<bool> RenewSessionAsync(string sessionId, TimeSpan extension)
    {
        lock (_lock)
        {
            if (_sessions.TryGetValue(sessionId, out var session))
            {
                session.ExpiresAt = session.ExpiresAt.Add(extension);
                return Task.FromResult(true);
            }
            return Task.FromResult(false);
        }
    }

    public Task<int> DeleteExpiredSessionsAsync()
    {
        return CleanupExpiredSessionsAsync();
    }
}
