using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AegisAuthBase.Entities;

namespace AegisAuthBase.Repositories;

public interface IUserPasskeyRepository
{
    /// <summary>
    /// 根据凭证ID获取通行密钥
    /// </summary>
    Task<UserPasskey?> GetByCredentialIdAsync(string credentialId);

    /// <summary>
    /// 获取用户的所有通行密钥
    /// </summary>
    Task<IEnumerable<UserPasskey>> GetByUserIdAsync(string userId);

    /// <summary>
    /// 添加新的通行密钥
    /// </summary>
    Task AddAsync(UserPasskey passkey);

    /// <summary>
    /// 更新签名计数器和最后使用时间
    /// </summary>
    Task UpdateCounterAsync(string id, uint newCounter, DateTime lastUsedAt);
}
