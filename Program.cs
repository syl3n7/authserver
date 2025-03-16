using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Net;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Get certificate password from configuration or environment variable
// In production, use environment variables or secrets manager
var certPassword = builder.Configuration["Certificate:Password"] ?? "YourSecurePassword";
var certPath = builder.Configuration["Certificate:Path"] ?? 
               Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), 
                           ".aspnet", "https", "authserver.pfx");

// Configure Kestrel to listen on ports with HTTPS
builder.WebHost.ConfigureKestrel(options =>
{
    // HTTP on port 5555 (optional, you might want to remove in production)
    options.Listen(IPAddress.Any, 5555);
    
    // HTTPS on port 5556
    options.Listen(IPAddress.Any, 5556, listenOptions =>
    {
        // Load certificate
        if (File.Exists(certPath))
        {
            listenOptions.UseHttps(certPath, certPassword);
            Console.WriteLine($"HTTPS enabled with certificate from: {certPath}");
        }
        else
        {
            Console.WriteLine($"Certificate not found at {certPath}. HTTPS will not be available.");
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
    // Set to true as requested
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

// Add services to the container
builder.Services.AddControllers();
builder.Services.AddSingleton<Database>();

// Add CORS support
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        policy =>
        {
            // Keep allowing any origin for university project as requested
            // In production, you should replace with specific origins:
            // policy.WithOrigins("https://yourgame.com", "https://www.yourdomain.com")
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

// Configure the HTTP request pipeline

// Add this custom middleware to log requests
app.Use(async (context, next) =>
{
    // Log the request details
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"[{DateTime.Now}] Request: {context.Request.Method} {context.Request.Path}{context.Request.QueryString}");
    
    // Capture the request body for POST/PUT requests
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
            
            // Reset the request body position for the next middleware
            context.Request.Body.Position = 0;
        }
    }
    
    Console.ResetColor();
    
    // Call the next middleware
    await next();
});

app.UseCors(); // Enable CORS

// Enable HTTPS redirection
app.UseHttpsRedirection();

app.UseAuthentication(); // Add JWT authentication middleware - must be before authorization
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