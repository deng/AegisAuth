using AegisAuthJwt.Controllers;
using AegisAuthBase.Entities;
using AegisAuthJwt.Managers;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using AegisAuthBase.Settings;
using AegisAuthJwt.Workers;
using AegisAuthJwtTest.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddHttpContextAccessor();

// Configure AegisAuth services
builder.Services.AddScoped<IUserRepository, InMemoryUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, InMemorySecurityAuditLogRepository>();
builder.Services.AddScoped<ITokenBlacklistRepository, InMemoryTokenBlacklistRepository>();

builder.Services.AddScoped<AuthManager>();
builder.Services.AddScoped<IHttpContextAccessorService, HttpContextAccessorService>();

// Configure settings
var authSetting = new AuthSetting
{
    JwtTokenKey = "your-256-bit-secret-key-here-make-it-long-enough",
    JwtTokenIssuer = "https://localhost:5001",
    JwtTokenAudience = "https://localhost:5001",
    AccessTokenExpirationMinutes = 60,
    RefreshTokenExpirationDays = 7
};
builder.Services.AddSingleton(authSetting);

// Configure TwoFactor settings
var twoFactorSettings = new TwoFactorSettings
{
    DefaultTwoFactorEnabled = true,
    DefaultTwoFactorType = TwoFactorTypeFlags.Passkey,
};
builder.Services.AddSingleton(twoFactorSettings);

// Add JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var authSetting = new AuthSetting
    {
        JwtTokenKey = "your-256-bit-secret-key-here-make-it-long-enough",
        JwtTokenIssuer = "https://localhost:5001",
        JwtTokenAudience = "https://localhost:5001"
    };

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = authSetting.JwtTokenIssuer,
        ValidateAudience = true,
        ValidAudience = authSetting.JwtTokenAudience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authSetting.JwtTokenKey)),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };

    // Add token blacklist validation
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var tokenHash = AuthManager.ComputeTokenHash(token);

            if (AuthManager.IsTokenBlacklisted(tokenHash))
            {
                context.Fail("Token has been revoked");
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Initialize token blacklist from database
using (var scope = app.Services.CreateScope())
{
    var authManager = scope.ServiceProvider.GetRequiredService<AuthManager>();
    await authManager.InitializeMemoryBlacklistAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
