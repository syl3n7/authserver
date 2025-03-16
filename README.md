# Authentication Server

Secure authentication server built with ASP.NET Core and SQLite for user management and authentication.

## Features

- ✅ Secure user registration with password hashing (PBKDF2 + salt)
- ✅ Secure login with JWT token generation
- ✅ Brute force protection (account lockout after 5 failed attempts)
- ✅ SQL Injection protection (parameterized queries)
- ✅ HTTPS/TLS support
- ✅ Comprehensive logging of authentication events
- ✅ Unity integration support via REST API

## System Architecture

The system consists of the following main components:

1. **Database Class**: Handles SQLite operations for user management
2. **AuthController**: REST endpoints for registration, login, and logout
3. **GameController**: Protected endpoints requiring authentication
4. **JWT Authentication**: Token-based authentication middleware

## API Documentation

### Authentication Endpoints

#### Register User
```
POST /api/auth/register
```
Request body:
```json
{
  "username": "user123",
  "password": "password123"
}
```
Response (success):
```json
{
  "success": true,
  "message": "User registered successfully"
}
```

#### User Login
```
POST /api/auth/login
```
Request body:
```json
{
  "username": "user123",
  "password": "password123"
}
```
Response (success):
```json
{
  "success": true,
  "message": "Login successful",
  "token": "JWT_TOKEN",
  "username": "user123"
}
```

#### User Logout
```
POST /api/auth/logout
```
Request body:
```json
{
  "username": "user123"
}
```
Response (success):
```json
{
  "success": true,
  "message": "User logged out successfully"
}
```

### Game Endpoints (Protected)

All game endpoints require an Authorization header with a valid JWT token:
```
Authorization: Bearer JWT_TOKEN
```

#### Get Online Players
```
GET /api/game/online-players
```
Response:
```json
{
  "success": true,
  "players": ["user1", "user2"],
  "count": 2
}
```

#### Get Current Player Info
```
GET /api/game/player-info
```
Response:
```json
{
  "success": true,
  "username": "user123",
  "isLoggedIn": true
}
```

## Security Measures

1. **Password Security**
   - PBKDF2 hashing algorithm with 10,000 iterations
   - 32-byte random salt per user
   - Password complexity requirements (minimum 8 characters)

2. **Brute Force Protection**
   - Account lockout after 5 failed login attempts
   - 15-minute lockout period
   - Failed login attempt tracking

3. **SQL Injection Protection**
   - Parameterized queries for all database operations

4. **API Security**
   - JWT token validation
   - Token expiration (60 minutes)
   - CORS protection (configurable)

## Setup and Installation

### Prerequisites
- .NET 6.0 SDK or higher
- Visual Studio 2022 or VS Code with C# extension

### Setup Steps

1. Clone the repository:
```
git clone [repository-url]
cd authserver
```

2. Restore packages:
```
dotnet restore
```

3. Run the server:
```
dotnet run
```

The server will start at http://localhost:5555

### Production Deployment

For production deployment:

1. Enable HTTPS redirection by uncommenting the line in Program.cs
2. Use a strong JWT secret key stored in environment variables
3. Enable issuer and audience validation in token validation parameters
4. Set appropriate CORS policies based on your deployment environment

## Unity Client Integration

To integrate with a Unity client:

1. Add a reference to UnityWebRequest
2. Make HTTP requests to the API endpoints
3. Store the JWT token securely for subsequent requests
4. Add the token to the Authorization header for protected endpoints