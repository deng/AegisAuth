namespace AegisAuthBase.Settings;

/// <summary>
/// 通行密钥配置设置
/// </summary>
public class PasskeySettings
{
    /// <summary>
    /// 服务器域名
    /// </summary>
    public string ServerDomain { get; set; } = "localhost";

    /// <summary>
    /// 服务器名称
    /// </summary>
    public string ServerName { get; set; } = "localhost";

    /// <summary>
    /// 允许的源
    /// </summary>
    public HashSet<string> Origins { get; set; } = new() { "https://localhost", "http://localhost" };
}