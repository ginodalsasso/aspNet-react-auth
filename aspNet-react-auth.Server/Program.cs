using aspNet_react_auth.Server.Data;
using aspNet_react_auth.Server.Entities;
using aspNet_react_auth.Server.Extensions;
using aspNet_react_auth.Server.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// ------------------------
// Logging (Serilog)
// ------------------------
builder.Host.SerilogConfiguration();

// ------------------------
// Load configuration files
// ------------------------
builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile("appsettings.Secrets.json", optional: true, reloadOnChange: true);

// ------------------------
// Register Controllers
// ------------------------
builder.Services.AddControllers();
builder.Services.AddControllersWithViews();

// ------------------------
// OpenAPI
// ------------------------
builder.Services.AddOpenApi();

// ------------------------
// CORS for React Client
// ------------------------
var clientAddress = "aspnet-react-chat.client";
builder.Services.AddCors(option =>
{
    option.AddPolicy(clientAddress, builder =>
    {
        builder.WithOrigins("https://localhost:24233")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

// ------------------------
// EF Core + SQL Server
// ------------------------
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// ------------------------
// Identity (User + Roles)
// ------------------------
builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// ------------------------
// Identity options
// ------------------------
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
});

// ------------------------
// Load RSA key for signing JWT
// ------------------------
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

// ------------------------
// JWT Bearer Authentication
// ------------------------
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
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

// ------------------------
// CSRF Protection
// ------------------------
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN";
    options.Cookie.Name = "__Host-X-XSRF-TOKEN";
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = false;
});

// ------------------------
// App services (DI)
// ------------------------
// builder.Services.AddMemoryCache(); // For manual CSRF
// builder.Services.AddScoped<ICsrfService, CsrfService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton(rsa);

var app = builder.Build();

// ------------------------
// Dev endpoints
// ------------------------
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// ------------------------
// Middleware pipeline
// ------------------------
app.UseHttpsRedirection();

app.UseCors(clientAddress);

app.UseAuthentication();
app.UseAuthorization();

app.UseCookiePolicy();
app.UseAntiforgery();

app.MapControllers();

app.Run();
