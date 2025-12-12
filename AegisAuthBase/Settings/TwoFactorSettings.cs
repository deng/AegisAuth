using AegisAuthBase.Entities;

namespace AegisAuthBase.Settings;

/// <summary>
/// 双因素认证配置设置
/// </summary>
public class TwoFactorSettings
{
    /// <summary>
    /// 注册用户默认是否启用双因素认证
    /// </summary>
    public bool DefaultTwoFactorEnabled { get; set; } = false;

    /// <summary>
    /// 注册用户默认的双因素认证类型
    /// </summary>
    public TwoFactorTypeFlags DefaultTwoFactorType { get; set; } = TwoFactorTypeFlags.None;
}