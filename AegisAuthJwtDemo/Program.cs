using AegisAuthJwt.Managers;
using AegisAuthBase.Entities;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using AegisAuthBase.Settings;
using AegisAuthBase.Extensions;
using AegisAuthJwtDemo.Repositories;
using AegisAuthJwtDemo.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddHttpContextAccessor();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add CORS for frontend
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// Configure database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite("Data Source=jwt-demo.db"));

// Configure AegisAuth services
builder.Services.AddScoped<IUserRepository, DbUserRepository>();
builder.Services.AddScoped<ISecurityAuditLogRepository, DbSecurityAuditLogRepository>();
builder.Services.AddScoped<ITokenBlacklistRepository, DbTokenBlacklistRepository>();
builder.Services.AddScoped<IUserPasskeyRepository, DbUserPasskeyRepository>();

builder.Services.AddScoped<AuthManager>();
builder.Services.AddScoped<ITwoFactorService, AuthManager>();
builder.Services.AddScoped<IPasskeyAuthService, AuthManager>();
builder.Services.AddScoped<IHttpContextAccessorService, HttpContextAccessorService>();
builder.Services.AddSingleton<ICredentialStore, InMemoryCredentialStore>();
builder.Services.AddSingleton<ITwoFactorStore, InMemoryTwoFactorStore>();

// Configure settings
var authSetting = new AuthSetting
{
    JwtTokenKey = "your-256-bit-secret-key-here-make-it-long-enough-for-demo-purposes-123456789",
    JwtTokenIssuer = "https://arundinaceous-wider-jadiel.ngrok-free.dev",
    JwtTokenAudience = "https://arundinaceous-wider-jadiel.ngrok-free.dev",
    AccessTokenExpirationMinutes = 60,
    RefreshTokenExpirationDays = 7
};
builder.Services.AddSingleton(authSetting);

// Configure Passkey settings
var passkeySettings = new PasskeySettings
{
    ServerDomain = "localhost",
    //ServerDomain = "arundinaceous-wider-jadiel.ngrok-free.dev",
    ServerName = "JWT WebAuthn Demo",
    Origins = new HashSet<string> { "https://arundinaceous-wider-jadiel.ngrok-free.dev" }
    //Origins = new HashSet<string> { "https://arundinaceous-wider-jadiel.ngrok-free.dev" }
};
builder.Services.AddSingleton(passkeySettings);

// Configure TwoFactor settings
var twoFactorSettings = new TwoFactorSettings
{
    DefaultTwoFactorEnabled = true,
    DefaultTwoFactorType = TwoFactorTypeFlags.Passkey,
};
builder.Services.AddSingleton(twoFactorSettings);

// Add WebAuthn services
builder.Services.AddWebAuthnServices(options =>
{
    options.ServerDomain = passkeySettings.ServerDomain;
    options.ServerName = passkeySettings.ServerName;
    options.Origins = passkeySettings.Origins;
});

// Add JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
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

var app = builder.Build();

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await dbContext.Database.EnsureCreatedAsync();

    // Initialize token blacklist from database
    var authManager = scope.ServiceProvider.GetRequiredService<AuthManager>();
    await authManager.InitializeMemoryBlacklistAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");

// Configure static files to serve apple-app-site-association without extension
var fileExtensionContentTypeProvider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
fileExtensionContentTypeProvider.Mappings[""] = "application/json";
app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = fileExtensionContentTypeProvider,
    ServeUnknownFileTypes = true,
    DefaultContentType = "application/json"
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Database context for demo
public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }
    public DbSet<UserCredential> UserCredentials { get; set; }
    public DbSet<UserPasskey> UserPasskeys { get; set; }
    public DbSet<SecurityAuditLog> SecurityAuditLogs { get; set; }
    public DbSet<TokenBlacklist> TokenBlacklists { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Configure UserCredential composite primary key
        modelBuilder.Entity<UserCredential>()
            .HasKey(uc => new { uc.UserId, uc.CredentialId });
    }
}
