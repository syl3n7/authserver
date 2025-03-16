using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;
using System;

[Route("api/game")]
[ApiController]
[Authorize] // Requires valid JWT token
public class GameController : ControllerBase
{
    private readonly Database _database;
    
    public GameController(Database database)
    {
        _database = database;
    }
    
    [HttpGet("online-players")]
    public IActionResult GetOnlinePlayers()
    {
        Console.WriteLine("Fetching online players...");
        List<string> players = _database.GetOnlinePlayers();
        Console.WriteLine($"Found {players.Count} online players");
        return Ok(new { 
            success = true,
            players = players,
            count = players.Count
        });
    }
    
    // Get current player information (example of using the authenticated user's identity)
    [HttpGet("player-info")]
    public IActionResult GetPlayerInfo()
    {
        // Extract username from the authenticated user's claims
        string username = User.Identity.Name;
        
        if (string.IsNullOrEmpty(username))
        {
            return BadRequest(new { success = false, message = "User not authenticated properly" });
        }
        
        return Ok(new {
            success = true,
            username = username,
            isLoggedIn = true
        });
    }
}