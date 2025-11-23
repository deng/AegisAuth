using AegisAuth.Core.Entities;

namespace AegisAuth.Core.Repositories;

/// <summary>
/// 用户仓储接口
/// </summary>
public interface IUserRepository
{
    /// <summary>
    /// 根据用户名查找用户
    /// </summary>
    /// <param name="userName">用户名</param>
    /// <returns>用户实体</returns>
    Task<User?> GetUserByUserNameAsync(string userName);

    /// <summary>
    /// 根据ID查找用户
    /// </summary>
    /// <param name="id">用户ID</param>
    /// <param name="getForUpdate">是否获取用于更新</param>
    /// <returns>用户实体</returns>
    Task<User?> GetByIdAsync(string id, bool getForUpdate);

    /// <summary>
    /// 更新用户
    /// </summary>
    /// <param name="user">用户实体</param>
    Task UpdateAsync(User user);

    /// <summary>
    /// 提交更改
    /// </summary>
    Task CommitAsync();
}