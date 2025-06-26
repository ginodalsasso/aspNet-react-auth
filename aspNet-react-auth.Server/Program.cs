using aspNet_react_auth.Server.Data;
using aspNet_react_auth.Server.Extensions;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Configure Serilog for logging
builder.Host.SerilogConfiguration();

// Add services to the container.
builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile("appsettings.Secrets.json", optional: true, reloadOnChange: true);

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// authorize Client and Server communication
var clientAddress = "aspnet-react-chat.client";
builder.Services.AddCors(option =>
{
    option.AddPolicy(clientAddress, builder =>
    {
        builder.WithOrigins("https://localhost:24233") // client address
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var rsa = RSA.Create();
var privateKeyPath = Path.Combine(builder.Environment.ContentRootPath, "Keys", "private_key.pem");

if (File.Exists(privateKeyPath))
{
    var privateKeyPem = File.ReadAllText(privateKeyPath);
    rsa.ImportFromPem(privateKeyPem);
}
else
{
    throw new FileNotFoundException($"Key is not found : {privateKeyPath}");
}
// Add Identity services 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["AppSettings:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["AppSettings:Audience"],
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new RsaSecurityKey(rsa),
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 }
        };
    });

// Configure CSRF Protection
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "__Host-X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = false;
});

// Add singleton RSA key for signing JWT tokens
builder.Services.AddSingleton(rsa);

// Register the AuthService
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();

app.UseCors(clientAddress);

app.UseAuthentication();

app.UseAuthorization();

app.UseAntiforgery();


app.MapControllers();

app.Run();
