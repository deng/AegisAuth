using System.Security.Cryptography;
using System.Text;

namespace AegisAuthBase.Services;

/// <summary>
/// 密码安全服务 - 生产环境级别的密码处理
/// </summary>
public class PasswordSecurityService
{
    private const int SaltSize = 32; // 盐值长度
    private const int HashSize = 32; // 哈希长度
    private const int Iterations = 100000; // PBKDF2 迭代次数

    /// <summary>
    /// 创建密码哈希和盐值
    /// </summary>
    /// <param name="password">明文密码</param>
    /// <returns>包含哈希和盐值的元组</returns>
    public (string hash, string salt) CreatePasswordHash(string password)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("密码不能为空", nameof(password));

        // 生成随机盐值
        var salt = GenerateSalt();

        // 使用 PBKDF2 生成哈希
        var hash = GenerateHash(password, salt);

        return (Convert.ToBase64String(hash), Convert.ToBase64String(salt));
    }

    /// <summary>
    /// 验证密码
    /// </summary>
    /// <param name="password">明文密码</param>
    /// <param name="storedHash">存储的哈希值</param>
    /// <param name="storedSalt">存储的盐值</param>
    /// <returns>密码是否正确</returns>
    public bool VerifyPassword(string password, string storedHash, string storedSalt)
    {
        if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(storedSalt))
            return false;

        try
        {
            var salt = Convert.FromBase64String(storedSalt);
            var expectedHash = Convert.FromBase64String(storedHash);

            var actualHash = GenerateHash(password, salt);

            // 使用固定时间比较防止时序攻击
            return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
        }
        catch
        {
            // 如果解码失败或出现其他异常，认为验证失败
            return false;
        }
    }

    /// <summary>
    /// 检查密码强度
    /// </summary>
    /// <param name="password">密码</param>
    /// <returns>密码强度信息</returns>
    public (bool isValid, string message) ValidatePasswordStrength(string password)
    {
        if (string.IsNullOrEmpty(password))
            return (false, "密码不能为空");

        if (password.Length < 8)
            return (false, "密码长度至少为8个字符");

        if (password.Length > 128)
            return (false, "密码长度不能超过128个字符");

        // 检查是否包含至少一个小写字母
        if (!password.Any(char.IsLower))
            return (false, "密码必须包含至少一个小写字母");

        // 检查是否包含至少一个大写字母
        if (!password.Any(char.IsUpper))
            return (false, "密码必须包含至少一个大写字母");

        // 检查是否包含至少一个数字
        if (!password.Any(char.IsDigit))
            return (false, "密码必须包含至少一个数字");

        // 检查是否包含至少一个特殊字符
        var specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (!password.Any(c => specialChars.Contains(c)))
            return (false, "密码必须包含至少一个特殊字符");

        // 检查是否包含连续相同字符
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] && password[i] == password[i + 2])
                return (false, "密码不能包含3个或更多连续相同字符");
        }

        return (true, "密码强度符合要求");
    }

    /// <summary>
    /// 生成随机盐值
    /// </summary>
    private byte[] GenerateSalt()
    {
        var salt = new byte[SaltSize];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    /// <summary>
    /// 使用 PBKDF2 生成密码哈希
    /// </summary>
    private byte[] GenerateHash(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256);
        return pbkdf2.GetBytes(HashSize);
    }
}