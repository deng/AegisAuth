namespace AegisAuthBase.Entities;

/// <summary>
/// 安全事件结果枚举
/// </summary>
public enum SecurityEventResult : byte
{
    /// <summary>
    /// 成功
    /// </summary>
    Success = 1,

    /// <summary>
    /// 失败
    /// </summary>
    Failure = 2,

    /// <summary>
    /// 警告
    /// </summary>
    Warning = 3,

    /// <summary>
    /// 信息
    /// </summary>
    Information = 4
}
