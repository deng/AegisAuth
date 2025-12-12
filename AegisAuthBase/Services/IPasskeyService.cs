using AegisAuthBase.Entities;
using Fido2NetLib;

namespace AegisAuthBase.Services;

/// <summary>
/// 通行密钥服务接口
/// </summary>
public interface IPasskeyService
{
    /// <summary>
    /// 获取注册通行密钥的选项 (Challenge等)
    /// </summary>
    Task<CredentialCreateOptions> GetRegisterOptionsAsync(User user);

    /// <summary>
    /// 验证并保存新的通行密钥
    /// </summary>
    Task RegisterAsync(User user, AuthenticatorAttestationRawResponse attestation, CredentialCreateOptions originalOptions);

    /// <summary>
    /// 获取登录通行密钥的选项
    /// </summary>
    Task<AssertionOptions?> GetLoginOptionsAsync(User user);

    /// <summary>
    /// 验证登录断言
    /// </summary>
    Task<bool> LoginAsync(User user, AuthenticatorAssertionRawResponse assertion, AssertionOptions originalOptions);
}