using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// Certificate setup - safe implementation
var certPassword = builder.Configuration["Certificate:Password"] ?? "YourSecurePassword";
var certPath = builder.Configuration["Certificate:Path"];

if (string.IsNullOrEmpty(certPath))
{
    // Use default location in user profile
    var certDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".aspnet",
        "https");
    
    Directory.CreateDirectory(certDir);
    certPath = Path.Combine(certDir, "authserver.pfx");
}
else
{
    // If a custom path is provided, ensure its directory exists
    string certDir = Path.GetDirectoryName(certPath);
    if (!string.IsNullOrEmpty(certDir))
    {
        Directory.CreateDirectory(certDir);
    }
    else
    {
        // If no directory component, place it in current directory
        certPath = Path.Combine(Directory.GetCurrentDirectory(), certPath);
    }
}

Console.WriteLine($"Using certificate path: {certPath}");

if (!File.Exists(certPath))
{
    Console.WriteLine($"Certificate not found. Generating a new self-signed certificate...");
    GenerateSelfSignedCertificate(certPath, certPassword);
}

// Configure Kestrel to listen on both HTTP and HTTPS
builder.WebHost.ConfigureKestrel(options =>
{
    options.Listen(IPAddress.Any, 5555);
    
    options.Listen(IPAddress.Any, 5556, listenOptions =>
    {
        try
        {
            listenOptions.UseHttps(certPath, certPassword);
            Console.WriteLine($"HTTPS enabled with certificate from: {certPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to configure HTTPS: {ex.Message}");
            Console.WriteLine("HTTPS will not be available.");
        }
    });
});

// Get and validate JWT configuration
var jwtSecret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    throw new InvalidOperationException("JWT secret is not configured in appsettings.json");
}

var key = Encoding.ASCII.GetBytes(jwtSecret);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = !string.IsNullOrEmpty(builder.Configuration["Jwt:Issuer"]),
        ValidateAudience = !string.IsNullOrEmpty(builder.Configuration["Jwt:Audience"]),
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddControllers();
builder.Services.AddSingleton<Database>();

// Add CORS support
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
});

// Add HTTP logging
builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = HttpLoggingFields.All;
    logging.RequestHeaders.Add("Authorization");
    logging.ResponseHeaders.Add("WWW-Authenticate");
    logging.MediaTypeOptions.AddText("application/json");
});

var app = builder.Build();

// Log requests middleware
app.Use(async (context, next) =>
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"[{DateTime.Now}] Request: {context.Request.Method} {context.Request.Path}{context.Request.QueryString}");
    
    if (context.Request.Method == "POST" || context.Request.Method == "PUT")
    {
        context.Request.EnableBuffering();
        
        using (var reader = new System.IO.StreamReader(
            context.Request.Body,
            encoding: System.Text.Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            leaveOpen: true))
        {
            var body = await reader.ReadToEndAsync();
            Console.WriteLine($"Request Body: {body}");
            
            context.Request.Body.Position = 0;
        }
    }
    
    Console.ResetColor();
    await next();
});

app.UseCors();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Log startup information
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("Auth Server started successfully!");
Console.WriteLine("Server is running at:");
Console.WriteLine("- HTTP:  http://localhost:5555");
Console.WriteLine("- HTTPS: https://localhost:5556");
Console.WriteLine($"Database location: {AppDomain.CurrentDomain.BaseDirectory}users.db");
Console.ResetColor();

app.Run();

void GenerateSelfSignedCertificate(string certPath, string password)
{
    try
    {
        string subject = "CN=localhost";
        
        using (RSA rsa = RSA.Create(2048))
        {
            var request = new CertificateRequest(
                subject, 
                rsa, 
                HashAlgorithmName.SHA256, 
                RSASignaturePadding.Pkcs1);

            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
                
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                    false));
                    
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                    false));

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(IPAddress.Parse("127.0.0.1"));
            sanBuilder.AddIpAddress(IPAddress.Parse("::1"));
            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddYears(1));

            File.WriteAllBytes(
                certPath,
                certificate.Export(X509ContentType.Pfx, password));
                
            Console.WriteLine($"Self-signed certificate created successfully at {certPath}");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Failed to generate certificate: {ex.Message}");
        throw;
    }
}