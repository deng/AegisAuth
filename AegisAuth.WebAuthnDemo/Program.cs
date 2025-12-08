using AegisAuth.WebAuthnDemo.Repositories;
using AegisAuthBase.Repositories;
using AegisAuthBase.Services;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Builder;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
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

// Add AegisAuth services (mock implementations for demo)
builder.Services.AddSingleton<IUserRepository, MockUserRepository>();
builder.Services.AddSingleton<IUserPasskeyRepository, MockUserPasskeyRepository>();
builder.Services.AddSingleton<ITwoFactorStore, MockTwoFactorStore>();

// Configure Fido2
builder.Services.AddSingleton<IFido2>(new Fido2(new Fido2Configuration
{
    ServerDomain = "localhost",
    ServerName = "WebAuthn Demo",
    Origins = new HashSet<string> { "https://localhost:7122", "http://localhost:5202" }
}));

// Add PasskeyService
builder.Services.AddScoped<IPasskeyService, PasskeyService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseStaticFiles(); // Add static files middleware

app.UseAuthorization();

app.MapControllers();

app.Run();
