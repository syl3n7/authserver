using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly Database _database;
    private readonly IConfiguration _configuration;
    private readonly int _tokenExpirationMinutes;

    // Use dependency injection for both database and configuration
    public AuthController(Database database, IConfiguration configuration)
    {
        _database = database;
        _configuration = configuration;
        _tokenExpirationMinutes = _configuration.GetValue<int>("Jwt:ExpiryInMinutes", 60);
    }

    /// <summary>
    /// Registers a new user in the system
    /// </summary>
    /// <param name="user">User model containing username and password</param>
    /// <returns>IActionResult with registration status</returns>
    /// <remarks>
    /// Password must be at least 8 characters long.
    /// Username must be unique.
    /// </remarks>
    [HttpPost("register")]
    public IActionResult Register([FromBody] UserModel user)
    {
        Console.WriteLine($"Registering user: {user.Username}");
        
        if (string.IsNullOrWhiteSpace(user.Username) || string.IsNullOrWhiteSpace(user.Password))
        {
            return BadRequest(new { success = false, message = "Username and password are required" });
        }
        
        if (user.Password.Length < 8)
        {
            return BadRequest(new { success = false, message = "Password must be at least 8 characters long" });
        }
        
        bool success = _database.RegisterUser(user.Username, user.Password);
        
        if (success)
        {
            return Ok(new { success = true, message = "User registered successfully" });
        }
        else
        {
            return BadRequest(new { success = false, message = "Username already exists or registration failed" });
        }
    }

    /// <summary>
    /// Authenticates a user and issues a JWT token
    /// </summary>
    /// <param name="user">User model containing username and password</param>
    /// <returns>IActionResult with login status and JWT token if successful</returns>
    /// <remarks>
    /// Failed login attempts are tracked to prevent brute force attacks.
    /// Accounts will be locked after 5 failed attempts for 15 minutes.
    /// </remarks>
    [HttpPost("login")]
    public IActionResult Login([FromBody] UserModel user)
    {
        Console.WriteLine($"Login attempt for user: {user.Username}");
        
        string errorMessage;
        if (_database.ValidateUser(user.Username, user.Password, out errorMessage))
        {
            _database.SetUserLoggedIn(user.Username, true);
            
            // Generate JWT token
            var token = GenerateJwtToken(user.Username);
            
            Console.WriteLine($"User logged in: {user.Username}");
            return Ok(new { 
                success = true, 
                message = "Login successful",
                token = token,
                username = user.Username
            });
        }

        Console.WriteLine($"Failed login attempt for user: {user.Username} - {errorMessage}");
        return Unauthorized(new { success = false, message = errorMessage });
    }

    /// <summary>
    /// Logs out a user by updating their login status
    /// </summary>
    /// <param name="user">User model containing username</param>
    /// <returns>IActionResult with logout status</returns>
    [HttpPost("logout")]
    public IActionResult Logout([FromBody] UserModel user)
    {
        Console.WriteLine($"Logging out user: {user.Username}");
        
        if (string.IsNullOrWhiteSpace(user.Username))
        {
            return BadRequest(new { success = false, message = "Username is required" });
        }
        
        bool success = _database.SetUserLoggedIn(user.Username, false);
        
        if (success)
        {
            return Ok(new { success = true, message = "User logged out successfully" });
        }
        else
        {
            return BadRequest(new { success = false, message = "User not found or logout failed" });
        }
    }
    
    /// <summary>
    /// Generates a JWT token for the authenticated user using the secret from configuration
    /// </summary>
    private string GenerateJwtToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        
        // Get the JWT secret from configuration
        var jwtSecret = _configuration["Jwt:Secret"];
        
        if (string.IsNullOrEmpty(jwtSecret))
        {
            throw new InvalidOperationException("JWT secret is not configured in appsettings.json");
        }
        
        var key = Encoding.ASCII.GetBytes(jwtSecret);
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, username)
            }),
            Expires = DateTime.UtcNow.AddMinutes(_tokenExpirationMinutes),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature
            ),
            // Optional: Adding issuer and audience if configured
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}

public class UserModel
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}