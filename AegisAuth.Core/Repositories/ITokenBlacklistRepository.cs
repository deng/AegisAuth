using AegisAuth.Core.Entities;

namespace AegisAuth.Core.Repositories;

/// <summary>
/// JWT令牌黑名单仓储接口
/// </summary>
public interface ITokenBlacklistRepository
{
    /// <summary>
    /// 添加令牌到黑名单
    /// </summary>
    /// <param name="tokenBlacklist">令牌黑名单实体</param>
    Task AddAsync(TokenBlacklist tokenBlacklist);

    /// <summary>
    /// 清理过期的黑名单令牌
    /// </summary>
    /// <returns>清理的记录数量</returns>
    Task<int> CleanupExpiredTokensAsync();

    /// <summary>
    /// 获取所有未过期的令牌哈希（用于内存黑名单初始化）
    /// </summary>
    Task<List<string>> GetValidTokenHashesAsync();

    /// <summary>
    /// 提交更改
    /// </summary>
    Task CommitAsync();
}