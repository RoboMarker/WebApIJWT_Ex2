using Microsoft.IdentityModel.Tokens;
using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApIJWT_Ex2
{
    //jwt範例
    public class JwtAuthenticationManager
    {
        private readonly IConfiguration Configuration;
        public JwtAuthenticationManager(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }
        public string Authenticate(User user)
        {
            var issuer = Configuration.GetValue<string>("JwtSettings:Issuer");//表示 Issuer，發送 Token 的發行者
            var signKey = Configuration.GetValue<string>("JwtSettings:SignKey");
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(signKey);//加密

            var claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Username));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim("roles", "Admin"));
            claims.Add(new Claim("roles", "Users"));

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Subject =new ClaimsIdentity(claims),
                Expires=DateTime.UtcNow.AddHours(1),//逾期時間
                //使用雜湊運算打亂結果
                SigningCredentials=new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            //傳回token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);


            //法2
            #region
            //var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));
            //var alogrithm = SecurityAlgorithms.HmacSha256;
            //
            //var signingCredentials = new SigningCredentials(secretKey, alogrithm);
            //var jwtSecurityToken = new JwtSecurityToken(
            //    issuer: issuer,
            //    notBefore: DateTime.Now,
            //    expires: DateTime.Now.AddMinutes(30),
            //    signingCredentials: signingCredentials);
            //return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            #endregion
        }


        public string Authenticate(string username,string password)
        {
            var issuer = Configuration.GetValue<string>("JwtSettings:Issuer");//表示 Issuer，發送 Token 的發行者
            var signKey = Configuration.GetValue<string>("JwtSettings:SignKey");
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(signKey);//加密

            //定義 claim
            var claims = new List<Claim>();
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, username));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim("roles", "Admin"));
            claims.Add(new Claim("roles", "Users"));

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = issuer,//必要
                Subject = new ClaimsIdentity(claims),//必要
                Expires = DateTime.UtcNow.AddHours(1),//逾期時間
                //使用雜湊運算打亂結果
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature)
            };
            //傳回token
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);


            //法2
            #region
            //var secretKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));
            //var alogrithm = SecurityAlgorithms.HmacSha256;
            //
            //var signingCredentials = new SigningCredentials(secretKey, alogrithm);
            //var jwtSecurityToken = new JwtSecurityToken(
            //    issuer: issuer,
            //    notBefore: DateTime.Now,
            //    expires: DateTime.Now.AddMinutes(30),
            //    signingCredentials: signingCredentials);
            //return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            #endregion
        }

    }
}
