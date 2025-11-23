using AegisAuthSession.Entities;

namespace AegisAuthSession.Services;

/// <summary>
/// Session 存储接口
/// </summary>
public interface ISessionStore
{
    /// <summary>
    /// 创建新的 Session
    /// </summary>
    /// <param name="session">Session 信息</param>
    Task CreateSessionAsync(Session session);

    /// <summary>
    /// 获取 Session
    /// </summary>
    /// <param name="sessionId">Session ID</param>
    /// <returns>Session 信息</returns>
    Task<Session?> GetSessionAsync(string sessionId);

    /// <summary>
    /// 更新 Session
    /// </summary>
    /// <param name="session">Session 信息</param>
    Task UpdateSessionAsync(Session session);

    /// <summary>
    /// 更新 Session 最后活动时间
    /// </summary>
    /// <param name="sessionId">Session ID</param>
    /// <param name="lastActivity">最后活动时间</param>
    Task UpdateSessionActivityAsync(string sessionId, DateTimeOffset lastActivity);

    /// <summary>
    /// 删除 Session
    /// </summary>
    /// <param name="sessionId">Session ID</param>
    Task DeleteSessionAsync(string sessionId);

    /// <summary>
    /// 删除用户的全部 Session
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>删除的 Session 数量</returns>
    Task<int> DeleteUserSessionsAsync(string userId);

    /// <summary>
    /// 清理过期的 Session
    /// </summary>
    /// <returns>清理的 Session 数量</returns>
    Task<int> CleanupExpiredSessionsAsync();

    /// <summary>
    /// 获取用户的活跃 Session 列表
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>Session 列表</returns>
    Task<List<Session>> GetUserSessionsAsync(string userId);

    /// <summary>
    /// 获取用户活跃 Session 数量
    /// </summary>
    /// <param name="userId">用户ID</param>
    /// <returns>活跃 Session 数量</returns>
    Task<int> GetUserActiveSessionCountAsync(string userId);

    /// <summary>
    /// 续期 Session
    /// </summary>
    /// <param name="sessionId">Session ID</param>
    /// <param name="extension">续期时间</param>
    /// <returns>是否成功</returns>
    Task<bool> RenewSessionAsync(string sessionId, TimeSpan extension);

    /// <summary>
    /// 删除过期的 Session
    /// </summary>
    /// <returns>删除的 Session 数量</returns>
    Task<int> DeleteExpiredSessionsAsync();
}