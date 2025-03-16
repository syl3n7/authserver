# Authentication Server API Documentation

This document provides detailed information about the available API endpoints and how to use them.

## Authentication API

Base URL: `/api/auth`

### Register User

Creates a new user account.

- **URL:** `/api/auth/register`
- **Method:** `POST`
- **Auth required:** No

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Success Response:**
- **Code:** 200 OK
- **Content:**
```json
{
  "success": true,
  "message": "User registered successfully"
}
```

**Error Responses:**
- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "Username and password are required"
}
```

OR

- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "Password must be at least 8 characters long"
}
```

OR

- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "Username already exists or registration failed"
}
```

### User Login

Authenticates a user and returns a JWT token.

- **URL:** `/api/auth/login`
- **Method:** `POST`
- **Auth required:** No

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Success Response:**
- **Code:** 200 OK
- **Content:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "JWT_TOKEN_STRING",
  "username": "string"
}
```

**Error Responses:**
- **Code:** 401 Unauthorized
- **Content:**
```json
{
  "success": false,
  "message": "Invalid password"
}
```

OR

- **Code:** 401 Unauthorized
- **Content:**
```json
{
  "success": false,
  "message": "User not found"
}
```

OR

- **Code:** 401 Unauthorized
- **Content:**
```json
{
  "success": false,
  "message": "Account is temporarily locked due to too many failed login attempts"
}
```

### User Logout

Logs out a user.

- **URL:** `/api/auth/logout`
- **Method:** `POST`
- **Auth required:** No (but typically should include the token)

**Request Body:**
```json
{
  "username": "string"
}
```

**Success Response:**
- **Code:** 200 OK
- **Content:**
```json
{
  "success": true,
  "message": "User logged out successfully"
}
```

**Error Responses:**
- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "Username is required"
}
```

OR

- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "User not found or logout failed"
}
```

## Game API

Base URL: `/api/game`

**Authentication:** All game API endpoints require JWT authentication using the Authorization header:
```
Authorization: Bearer JWT_TOKEN
```

### Get Online Players

Returns a list of currently online players.

- **URL:** `/api/game/online-players`
- **Method:** `GET`
- **Auth required:** Yes

**Success Response:**
- **Code:** 200 OK
- **Content:**
```json
{
  "success": true,
  "players": ["string", "string"],
  "count": 2
}
```

### Get Player Info

Returns information about the authenticated user.

- **URL:** `/api/game/player-info`
- **Method:** `GET`
- **Auth required:** Yes

**Success Response:**
- **Code:** 200 OK
- **Content:**
```json
{
  "success": true,
  "username": "string",
  "isLoggedIn": true
}
```

**Error Responses:**
- **Code:** 400 Bad Request
- **Content:**
```json
{
  "success": false,
  "message": "User not authenticated properly"
}
```

## Using JWT Tokens

JWT tokens should be included in the Authorization header of requests to protected endpoints:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Tokens expire after 60 minutes, after which a new login is required.