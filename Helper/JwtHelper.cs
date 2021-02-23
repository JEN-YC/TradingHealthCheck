using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace TradingHealthCheck.Helper
{
    public static class JwtHelper
    {
        // 需將相同金鑰存放於後端伺服器以及富邦PC,APP端軟體內
        private const string Secret = "SnVzdCBmb3Igand0IGF1dGhlbnRpY2F0ZSBkZW1v";

        public static string GenerateToken(string userId, int expireMinutes = 300)
        {
            var symmetricKey = Convert.FromBase64String(Secret);
            var tokenHandler = new JwtSecurityTokenHandler();

            var now = DateTime.UtcNow;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("UserID", userId) // 將客戶身分證存放至Payload
                }),

                Expires = now.AddMinutes(Convert.ToInt32(expireMinutes)),　// 設定Token到期時間

                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(symmetricKey),
                    SecurityAlgorithms.HmacSha256Signature)　// 使用HS256演算法進行簽章
            };

            var stoken = tokenHandler.CreateToken(tokenDescriptor);
            var token = tokenHandler.WriteToken(stoken);

            return token;
        }

        public static bool ValidateToken(string token, out ClaimsPrincipal principal)
        {
            principal = null;
            if (string.IsNullOrWhiteSpace(token))
            {
                return false;
            }

            var handler = new JwtSecurityTokenHandler();

            try
            {
                var jwt = handler.ReadJwtToken(token); //　讀取JWT Token

                if (jwt == null)
                {
                    return false;
                }

                var secretBytes = Convert.FromBase64String(Secret); //　需使用相同金鑰進行驗證

                var validationParameters = new TokenValidationParameters
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(secretBytes),
                    ClockSkew = TimeSpan.Zero
                };

                SecurityToken securityToken;
                principal = handler.ValidateToken(token, validationParameters, out securityToken);

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
