using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

namespace WebApIJWT_Ex2.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        //jwt 相關參數 參考
        //https://blog.poychang.net/authenticating-jwt-tokens-in-asp-net-core-webapi/ 
        //相關url 參考 
        //https://www.youtube.com/watch?v=v7q3pEK1EA0
        //相關 重設參考
        // https://github.com/patrickgod/JwtWebApiTutorial/blob/master/JwtWebApiTutorial/Controllers/AuthController.cs
        //可以用來驗證 jwt
        // https://jwt.io/
        public static User user = new User();

        private readonly JwtAuthenticationManager _jwtAuthenticationManager;
        private static readonly string[] Summaries = new[]
{
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };
        public AuthController(JwtAuthenticationManager jwtAuthenticationManager)
        {
            this._jwtAuthenticationManager = jwtAuthenticationManager;

            user.Username = "test1";//假設資料庫帳號
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            CreatePasswordHash(request.password, out byte[] pwdHash, out byte[] pwdSalt);
            user.Username = request.username;
            user.PasswordHash = pwdHash;
            user.PasswordSalt = pwdSalt;
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if (user.Username != request.username)
            {
                return BadRequest("User not found");
            }
            if (!VerifyPasswordHash(request.password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Wrong password");
            }
            string token =  this._jwtAuthenticationManager.Authenticate(user);

            return Ok(token);
        }

        [Authorize]
        [HttpGet("Get")]
        public IEnumerable<WeatherForecast> GetWeatherForecast2()
        {
            //取得 Claims 的已認證成功帳號
            var userName =  HttpContext.AuthenticateAsync().Result.Principal.Claims.First(x=>x.Type.Equals(ClaimTypes.NameIdentifier))?.Value;

            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateTime.Now.AddDays(index),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }


        //建立 hash
        private void CreatePasswordHash(string pwd, out byte[] pwdHash, out byte[] pwdSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                pwdSalt = hmac.Key;
                pwdHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(pwd));
            }
        }
        //驗證密碼 hash
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(user.PasswordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computeHash.SequenceEqual(passwordHash);

            }
        }


           

    }
}
