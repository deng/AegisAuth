namespace AegisAuth.Core.Entities;

/// <summary>
/// 安全审计日志实体类
/// </summary>
public class SecurityAuditLog
{
    /// <summary>
    /// 日志ID
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// 用户名
    /// </summary>
    public required string UserName { get; set; }

    /// <summary>
    /// 事件类型
    /// </summary>
    public SecurityEventType EventType { get; set; }

    /// <summary>
    /// 事件描述
    /// </summary>
    public required string EventDescription { get; set; }

    /// <summary>
    /// IP地址
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// 用户代理
    /// </summary>
    public string? UserAgent { get; set; }

    /// <summary>
    /// 结果
    /// </summary>
    public SecurityEventResult Result { get; set; }

    /// <summary>
    /// 详细信息（JSON格式）
    /// </summary>
    public string? Details { get; set; }

    /// <summary>
    /// 创建时间
    /// </summary>
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}