using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace WebApIJWT_Ex2.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private readonly JwtAuthenticationManager _jwtAuthenticationManager;
        private static readonly string[] Summaries = new[]
        {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };
        public WeatherForecastController(JwtAuthenticationManager jwtAuthenticationManager)
        {
            this._jwtAuthenticationManager = jwtAuthenticationManager;
        }

        private readonly ILogger<WeatherForecastController> _logger;

        [Authorize]
        [HttpGet("Get")]
        public IEnumerable<WeatherForecast> GetWeatherForecast2()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }

        [AllowAnonymous]
        [HttpPost("Authorize")]
        public IActionResult AuthUser([FromBody] UserDto user)
        {
            UserDto my = setUser();
            if (my.username != user.username || my.password != user.password)
            {
                return Ok("±b±K¿ù»~");
            }
            var token = this._jwtAuthenticationManager.Authenticate(user.username, user.password);
            if (token == null)
            { 
                return Unauthorized();
            }
            return Ok(token);
        }

        private UserDto setUser()
        {
            UserDto user = new UserDto();
            user.username = "test1";
            user.password = "pwd1";
            return user;
        }

    }
}