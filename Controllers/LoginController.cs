using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using LogInApp.Models;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;




namespace LogInApp.Controllers;

[Route("api/[controller]")]
[ApiController]
public class LoginController : Controller
{

    private IConfiguration _config;  // get variables from appSetting.json
    public LoginController(IConfiguration configuration)
    {
        _config = configuration;
        Console.WriteLine("*********************************");
    }
    private User AuthenticateUser(User user)
    {
        User _user = null;
        if (_user.username == "admin" && user.password == "1234")
        {
            _user = new User();
        }
        return _user;
    }

    // generate token

    private string GenerateJWT(User user)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtAuth:Key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(_config["JwtAuth:Issuer"],
          _config["JwtAuth:Issuer"],
          expires: DateTime.Now.AddMinutes(120),
          signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Login(User user)
    {

        IActionResult response = Unauthorized();

        var _user = AuthenticateUser(user);

        if (_user != null)
        {
            var tokenString = GenerateJWT(_user);
            return Ok(new { token = tokenString });

        }
        else
        {
            return response;
        }


    }


}