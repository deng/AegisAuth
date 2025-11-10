using AegisAuth.Entities;

namespace AegisAuth.Repositories;

/// <summary>
/// 安全审计日志仓储接口
/// </summary>
public interface ISecurityAuditLogRepository
{
    /// <summary>
    /// 添加安全审计日志
    /// </summary>
    /// <param name="log">日志实体</param>
    Task AddAsync(SecurityAuditLog log);

    /// <summary>
    /// 提交更改
    /// </summary>
    Task CommitAsync();
}