using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using WebApplication1.Models;

namespace WebApplication1.JwtHelpers
{
    public static class JwtHelpers
    {
        //GetClaims() Method is used to create return claims list from user token details.
        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, Guid id)
        {
            IEnumerable<Claim> claims = new Claim[]
            {
                new Claim("Id", userAccounts.Id.ToString()),
                new Claim(ClaimTypes.Name,userAccounts.UserName),
                new Claim(ClaimTypes.Email,userAccounts.EmailId),
                new Claim(ClaimTypes.NameIdentifier, id.ToString()),
                new Claim(ClaimTypes.Expiration,DateTime.UtcNow.AddDays(1).ToString("MMM ddd dd yyyy HH:mm:ss tt"))
            };
            return claims;
        }

        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, out Guid Id)
        {
            Id = Guid.NewGuid();
            return GetClaims(userAccounts, Id);

        }

        public static UserTokens GenToKenKey(UserTokens model, JwtSettings jwtSettings)
        {
            try
            {
                var UserToken = new UserTokens();
                if (model == null) throw new ArgumentException(nameof(model));
                //Get secret Key
                var key = System.Text.Encoding.ASCII.GetBytes(jwtSettings.IssuerSigningKey);
                Guid Id = Guid.Empty;
                DateTime expireTime = DateTime.UtcNow.AddDays(1);
                UserToken.Validaty = expireTime.TimeOfDay;
                var JWToken = new JwtSecurityToken(issuer: jwtSettings.ValidIssuer, audience: jwtSettings.ValidAudience, claims: GetClaims(model, out Id), notBefore: new DateTimeOffset(DateTime.Now).DateTime, expires: new DateTimeOffset(expireTime).DateTime, signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256));
                UserToken.Token = new JwtSecurityTokenHandler().WriteToken(JWToken);
                UserToken.UserName = model.UserName;
                UserToken.Id = model.Id;
                UserToken.GuidId = Id;
                return UserToken;
            }
            catch (Exception)
            {
                throw;
            }

        }

    }
}
