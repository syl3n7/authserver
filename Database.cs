using System;
using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.IO;

/// <summary>
/// Handles database operations for user authentication and session management
/// </summary>
public class Database
{
    private readonly string ConnectionString;
    private const int PBKDF2_ITERATIONS = 10000; // Recommended minimum for PBKDF2
    private const int SALT_SIZE_BYTES = 32;
    private readonly ILogger _logger;
    
    // Brute force protection settings
    private const int MAX_LOGIN_ATTEMPTS = 5;
    private const int LOCKOUT_MINUTES = 15;
    
    public Database(ILogger? logger = null)
    {
        _logger = logger;
        
        try
        {
            // Get the output directory path for the SQLite database file
            string outputDir = AppDomain.CurrentDomain.BaseDirectory;
            string dbPath = Path.Combine(outputDir, "users.db");
            
            // Create connection string with the path
            ConnectionString = $"Data Source={dbPath}";
            
            // Ensure the directory exists
            Directory.CreateDirectory(Path.GetDirectoryName(dbPath));
            
            InitializeDatabase();
            LogInfo("Database initialized successfully");
        }
        catch (Exception ex)
        {
            LogError($"Error initializing database: {ex.Message}");
            throw new DatabaseInitializationException("Failed to initialize database", ex);
        }
    }
    
    private void InitializeDatabase()
    {
        using (var connection = new SqliteConnection(ConnectionString))
        {
            connection.Open();
            
            // Enhanced table with failed login tracking
            string createTableQuery = @"CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT UNIQUE NOT NULL,
                PasswordHash TEXT NOT NULL,
                Salt TEXT NOT NULL,
                IsLoggedIn INTEGER DEFAULT 0,
                LastLoginTime TEXT,
                RegistrationTime TEXT NOT NULL,
                FailedLoginAttempts INTEGER DEFAULT 0,
                LastFailedLoginTime TEXT
            );";
            
            using (var command = new SqliteCommand(createTableQuery, connection))
            {
                command.ExecuteNonQuery();
            }
        }
    }
    
    /// <summary>
    /// Registers a new user with the provided username and password
    /// </summary>
    /// <param name="username">Username for the new user</param>
    /// <param name="password">Password for the new user</param>
    /// <returns>True if registration was successful, otherwise false</returns>
    public bool RegisterUser(string username, string password)
    {
        // Validate inputs
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            LogError("Registration failed: Username or password cannot be empty");
            return false;
        }
        
        // Implement minimum password requirements
        if (password.Length < 8)
        {
            LogError("Registration failed: Password must be at least 8 characters long");
            return false;
        }
        
        try
        {
            using (var connection = new SqliteConnection(ConnectionString))
            {
                connection.Open();
                string salt = GenerateSalt();
                string hashedPassword = HashPassword(password, salt);
                string insertQuery = @"INSERT INTO Users 
                                      (Username, PasswordHash, Salt, RegistrationTime) 
                                      VALUES(@Username, @PasswordHash, @Salt, @RegistrationTime)";
                
                using (var command = new SqliteCommand(insertQuery, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@PasswordHash", hashedPassword);
                    command.Parameters.AddWithValue("@Salt", salt);
                    command.Parameters.AddWithValue("@RegistrationTime", DateTime.UtcNow.ToString("o"));
                    
                    command.ExecuteNonQuery();
                    LogInfo($"User '{username}' registered successfully");
                    return true;
                }
            }
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // UNIQUE constraint failed
        {
            LogError($"Registration failed: User '{username}' already exists");
            return false;
        }
        catch (Exception ex)
        {
            LogError($"Registration error: {ex.Message}");
            return false;
        }
    }
    
    /// <summary>
    /// Validates user credentials and implements brute force protection
    /// </summary>
    /// <param name="username">Username to validate</param>
    /// <param name="password">Password to validate</param>
    /// <param name="errorMessage">Out parameter with detailed error message</param>
    /// <returns>True if credentials are valid, otherwise false</returns>
    public bool ValidateUser(string username, string password, out string errorMessage)
    {
        errorMessage = string.Empty;
        
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            errorMessage = "Username and password are required";
            return false;
        }
        
        try
        {
            using (var connection = new SqliteConnection(ConnectionString))
            {
                connection.Open();
                
                // First check if account is locked out
                if (IsAccountLocked(username, connection))
                {
                    errorMessage = "Account is temporarily locked due to too many failed login attempts";
                    LogInfo($"Authentication failed: Account '{username}' is locked out");
                    return false;
                }
                
                string query = "SELECT PasswordHash, Salt, FailedLoginAttempts FROM Users WHERE Username = @Username";
                
                using (var command = new SqliteCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string storedHash = reader.GetString(0); // PasswordHash
                            string storedSalt = reader.GetString(1); // Salt
                            int failedAttempts = reader.GetInt32(2); // FailedLoginAttempts
                            
                            string computedHash = HashPassword(password, storedSalt);
                            
                            bool isValid = storedHash == computedHash;
                            
                            if (isValid)
                            {
                                // Reset failed login attempts on successful login
                                ResetFailedLoginAttempts(username, connection);
                                LogInfo($"Authentication successful for '{username}'");
                                return true;
                            }
                            else
                            {
                                // Increment failed login attempts
                                IncrementFailedLoginAttempts(username, connection);
                                errorMessage = "Invalid password";
                                LogInfo($"Authentication failed for '{username}': Invalid password");
                                return false;
                            }
                        }
                    }
                }
                
                errorMessage = "User not found";
                LogInfo($"Authentication failed: User '{username}' not found");
                return false;
            }
        }
        catch (Exception ex)
        {
            errorMessage = "An internal error occurred";
            LogError($"Validation error for user '{username}': {ex.Message}");
            return false;
        }
    }
    
    // Overload to maintain compatibility with existing code
    public bool ValidateUser(string username, string password)
    {
        string errorMessage;
        return ValidateUser(username, password, out errorMessage);
    }
    
    /// <summary>
    /// Checks if an account is currently locked out due to too many failed attempts
    /// </summary>
    private bool IsAccountLocked(string username, SqliteConnection connection)
    {
        string query = @"SELECT FailedLoginAttempts, LastFailedLoginTime 
                        FROM Users 
                        WHERE Username = @Username";
                        
        using (var command = new SqliteCommand(query, connection))
        {
            command.Parameters.AddWithValue("@Username", username);
            
            using (var reader = command.ExecuteReader())
            {
                if (reader.Read())
                {
                    int failedAttempts = reader.GetInt32(0);
                    
                    // If user has reached max attempts
                    if (failedAttempts >= MAX_LOGIN_ATTEMPTS)
                    {
                        // Check if lockout period has expired
                        if (!reader.IsDBNull(1))
                        {
                            DateTime lastFailedTime = DateTime.Parse(reader.GetString(1));
                            DateTime lockoutEnd = lastFailedTime.AddMinutes(LOCKOUT_MINUTES);
                            
                            // If lockout period has expired, reset the counter and allow login
                            if (DateTime.UtcNow > lockoutEnd)
                            {
                                ResetFailedLoginAttempts(username, connection);
                                return false;
                            }
                            return true; // Account is still locked
                        }
                    }
                }
            }
        }
        
        return false; // Account is not locked
    }
    
    /// <summary>
    /// Increments the failed login attempts counter
    /// </summary>
    private void IncrementFailedLoginAttempts(string username, SqliteConnection connection)
    {
        string query = @"UPDATE Users 
                        SET FailedLoginAttempts = FailedLoginAttempts + 1, 
                            LastFailedLoginTime = @LastFailedTime
                        WHERE Username = @Username";
                        
        using (var command = new SqliteCommand(query, connection))
        {
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@LastFailedTime", DateTime.UtcNow.ToString("o"));
            command.ExecuteNonQuery();
        }
    }
    
    /// <summary>
    /// Resets the failed login attempts counter after successful login
    /// </summary>
    private void ResetFailedLoginAttempts(string username, SqliteConnection connection)
    {
        string query = @"UPDATE Users 
                        SET FailedLoginAttempts = 0,
                            LastFailedLoginTime = NULL
                        WHERE Username = @Username";
                        
        using (var command = new SqliteCommand(query, connection))
        {
            command.Parameters.AddWithValue("@Username", username);
            command.ExecuteNonQuery();
        }
    }
    
    /// <summary>
    /// Updates the login status of a user
    /// </summary>
    /// <param name="username">Username to update</param>
    /// <param name="isLoggedIn">Whether the user is logged in</param>
    /// <returns>True if update was successful, otherwise false</returns>
    public bool SetUserLoggedIn(string username, bool isLoggedIn)
    {
        try
        {
            using (var connection = new SqliteConnection(ConnectionString))
            {
                connection.Open();
                string query = @"UPDATE Users 
                                SET IsLoggedIn = @IsLoggedIn, 
                                    LastLoginTime = CASE WHEN @IsLoggedIn = 1 THEN @LoginTime ELSE LastLoginTime END
                                WHERE Username = @Username";
                
                using (var command = new SqliteCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@IsLoggedIn", isLoggedIn ? 1 : 0);
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@LoginTime", DateTime.UtcNow.ToString("o"));
                    
                    int rowsAffected = command.ExecuteNonQuery();
                    bool success = rowsAffected > 0;
                    
                    if (success)
                    {
                        LogInfo($"User '{username}' login status set to: {(isLoggedIn ? "Online" : "Offline")}");
                    }
                    else
                    {
                        LogError($"Failed to update login status: User '{username}' not found");
                    }
                    
                    return success;
                }
            }
        }
        catch (Exception ex)
        {
            LogError($"Error updating login status for '{username}': {ex.Message}");
            return false;
        }
    }
    
    /// <summary>
    /// Gets a list of users who are currently logged in
    /// </summary>
    /// <returns>List of usernames who are currently online</returns>
    public List<string> GetOnlinePlayers()
    {
        List<string> players = new List<string>();
        
        try
        {
            using (var connection = new SqliteConnection(ConnectionString))
            {
                connection.Open();
                string query = "SELECT Username FROM Users WHERE IsLoggedIn = 1";
                
                using (var command = new SqliteCommand(query, connection))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            players.Add(reader.GetString(0)); // Username
                        }
                    }
                }
            }
            
            LogInfo($"Retrieved {players.Count} online player(s)");
            return players;
        }
        catch (Exception ex)
        {
            LogError($"Error retrieving online players: {ex.Message}");
            return players;
        }
    }
    
    /// <summary>
    /// Hashes a password using PBKDF2 with the provided salt
    /// </summary>
    /// <param name="password">Password to hash</param>
    /// <param name="salt">Salt for the hashing operation</param>
    /// <returns>Base64-encoded hash of the password</returns>
    private string HashPassword(string password, string salt)
    {
        byte[] saltBytes = Convert.FromBase64String(salt);
        
        using (var pbkdf2 = new Rfc2898DeriveBytes(
            password,
            saltBytes,
            PBKDF2_ITERATIONS,
            HashAlgorithmName.SHA256))
        {
            byte[] hash = pbkdf2.GetBytes(32); // 256 bits
            return Convert.ToBase64String(hash);
        }
    }
    
    /// <summary>
    /// Generates a cryptographically secure random salt
    /// </summary>
    /// <returns>Base64-encoded salt value</returns>
    private string GenerateSalt()
    {
        byte[] saltBytes = new byte[SALT_SIZE_BYTES];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }
        return Convert.ToBase64String(saltBytes);
    }
    
    private void LogInfo(string message)
    {
        _logger?.LogInfo($"[Database] {message}");
        Console.WriteLine($"[Database] {message}");
    }
    
    private void LogError(string message)
    {
        _logger?.LogError($"[Database] {message}");
        Console.WriteLine($"[Database] ERROR: {message}");
    }
}

/// <summary>
/// Simple logger interface for dependency injection
/// </summary>
public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}

/// <summary>
/// Thrown when the database fails to initialize
/// </summary>
public class DatabaseInitializationException : Exception
{
    public DatabaseInitializationException(string message) : base(message) { }
    public DatabaseInitializationException(string message, Exception innerException) : base(message, innerException) { }
}