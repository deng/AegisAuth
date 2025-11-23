using AegisAuthSession.Entities;

namespace AegisAuthSession.Repositories;

/// <summary>
/// Session 仓储接口
/// </summary>
public interface ISessionRepository
{
    /// <summary>
    /// 根据 Session ID 获取 Session
    /// </summary>
    Task<Session?> GetByIdAsync(string sessionId);

    /// <summary>
    /// 根据用户 ID 获取所有活跃 Session
    /// </summary>
    Task<List<Session>> GetActiveSessionsByUserIdAsync(string userId);

    /// <summary>
    /// 添加新 Session
    /// </summary>
    Task AddAsync(Session session);

    /// <summary>
    /// 更新 Session
    /// </summary>
    Task UpdateAsync(Session session);

    /// <summary>
    /// 删除 Session
    /// </summary>
    Task DeleteAsync(string sessionId);

    /// <summary>
    /// 删除用户的所有 Session
    /// </summary>
    Task DeleteAllSessionsByUserIdAsync(string userId);

    /// <summary>
    /// 删除过期的 Session
    /// </summary>
    Task<int> DeleteExpiredSessionsAsync();

    /// <summary>
    /// 获取所有活跃 Session 的 ID 列表
    /// </summary>
    Task<List<string>> GetActiveSessionIdsAsync();

    /// <summary>
    /// 提交更改
    /// </summary>
    Task CommitAsync();

    /// <summary>
    /// 检查 Session 是否存在
    /// </summary>
    Task<bool> ExistsAsync(string sessionId);
}