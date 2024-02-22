using ASPDotNetCRUDApp.Configurations;
using ASPDotNetCRUDApp.Data;
using ASPDotNetCRUDApp.DTOs;
using ASPDotNetCRUDApp.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASPDotNetCRUDApp.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
		//IdentityUser is the default user
		private readonly UserManager<IdentityUser> _userManager;
		//private readonly JwtConfig _jwtConfig;
		private readonly IConfiguration _configuration;
		private readonly TokenValidationParameters _tokenValidationParameters;

		private readonly AppDbContext _appDbContext;

		public AuthenticationController(UserManager<IdentityUser> userManager, IConfiguration configuration, AppDbContext appDbContext, TokenValidationParameters tokenValidationParameters)
		{
			_configuration = configuration;
			_userManager = userManager;
			_appDbContext = appDbContext;
			_tokenValidationParameters = tokenValidationParameters;

		}

		[HttpPost]
		[Route("Register")]

		public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDTO requestDTO)
		{
			//validate the incoming request
			if (ModelState.IsValid)
			{
				//We need to check if the email already exists

				var user_exist = await _userManager.FindByEmailAsync(requestDTO.Email);
				if (user_exist != null)
				{
					return BadRequest(new AuthResult()
					{
						Result = false,
						Errors = new List<string>()
						{
							"Email already exists"
						}

					});
				}
				// create a user
				var new_user = new IdentityUser()
				{
					Email = requestDTO.Email,
					UserName = requestDTO.Email
				};

				var is_created = await _userManager.CreateAsync(new_user, requestDTO.Password);

				if (is_created.Succeeded)
				{
					var tokenResult = await GenerateJwtToken(new_user);
					return Ok(tokenResult);
				}
				return BadRequest(new AuthResult()
				{
					Result = false,
					Errors = new List<string>()
					{
						string.Join(",",is_created.Errors.Select(err => err.Description))
					}
				});
			}
			return BadRequest("Server Error");
		}


		[HttpPost]
		[Route("Login")]
		public async Task<IActionResult> Login([FromBody] UserLoginRequestDTO loginRequest)
		{
			if (ModelState.IsValid)
			{
				//check whether the user exists

				var existing_user = await _userManager.FindByEmailAsync(loginRequest.Email);
				if (existing_user == null)
				{
					return BadRequest(new AuthResult()
					{
						Errors = new List<string>()
						{
							"Invalid Payload"
						},
						Result = false
					});
				}

				var isCorrect = await _userManager.CheckPasswordAsync(existing_user, loginRequest.Password);
				if (!isCorrect)
				{
					return BadRequest(new AuthResult()
					{
						Errors = new List<string>()
						{
							"Invalid Credentials"
						},
						Result = false
					});
				}

				var tokenResponse = await GenerateJwtToken(existing_user);
				return Ok(tokenResponse);

			}
			return BadRequest(new AuthResult()
			{
				Errors = new List<string>()
				{
					"Invalid Payload"
				},
				Result = false
			});
		}

		[HttpPost]
		[Route("RefreshToken")]

		public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
		{
			if (ModelState.IsValid)
			{
				var result = await VerifyAndGenerateToken(tokenRequest);
				if (result == null)
				{
					return BadRequest(new AuthResult()
					{
						Errors = new List<string>() { "Invalid Tokens" },
						Result = false
					});
				}
				return Ok(result);

			}

			return BadRequest(new AuthResult()
			{
				Errors = new List<string>() { "Invalid Parameters" },
				Result = false
			});
		}
		[ApiExplorerSettings(IgnoreApi = true)]

		private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();

			var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);

			//Token Descriptor

			var tokenDescriptor = new SecurityTokenDescriptor()
			{
				Subject = new ClaimsIdentity(new[]
				{
					new Claim("Id",user.Id),
					new Claim(JwtRegisteredClaimNames.Sub,user.Email),
					new Claim(JwtRegisteredClaimNames.Email,user.Email),
					new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
					new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
				}),
                //Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection("JwtConfig:ExpiryTimeFrame").Value)),
                Expires = DateTime.UtcNow.AddSeconds(40),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
			};

			var token = jwtTokenHandler.CreateToken(tokenDescriptor);
			var jwtToken = jwtTokenHandler.WriteToken(token);

			var refreshToken = new RefreshToken()
			{
				JwtId = token.Id,
				Token = RandomStringeGenerator(23),//Generate Refresh Token
				ExpiryDate= DateTime.UtcNow.AddMonths(6),
				IsRevoked = false,
				IsUsed = false,
				UserId = user.Id,
				AddedDate = DateTime.UtcNow,
			};

			await _appDbContext.RefreshTokens.AddAsync(refreshToken);
			await _appDbContext.SaveChangesAsync();

			var tokenResponse = new AuthResult()
			{
				Token = jwtToken,
				RefreshToken = refreshToken.Token,
				Result = true
			};

			return tokenResponse;
		}



		[ApiExplorerSettings(IgnoreApi = true)]
		public async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
		{
			var jwtTokenHandler = new JwtSecurityTokenHandler();
			AuthResult response = new AuthResult();
			try
			{
				_tokenValidationParameters.ValidateLifetime = false;//for testing,it's made false, in actual case it should be true
				var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token,_tokenValidationParameters,out var validatedToken);
				if(validatedToken is JwtSecurityToken jwtSecurityToken)
				{
					var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase);
					if (result == false)
						return new AuthResult() { Result=false,Errors=new List<string>() { "Invalid Creds"} };

					var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
					var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);
					if (expiryDate > DateTime.Now)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Expired Token" }
						};
					}

					var storedToken = await _appDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

					if (storedToken == null)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Invalid Token" }
						};
					}

					if (storedToken.IsUsed==true)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Invalid Token" }
						};
					}

					if (storedToken.IsRevoked == true)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Invalid Token" }
						};
					}

					var jti = tokenInVerification.Claims.FirstOrDefault(x=>x.Type== JwtRegisteredClaimNames.Jti).Value;
					if (storedToken.JwtId != jti)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Invalid Token" }
						};
					}

					if (storedToken.ExpiryDate < DateTime.UtcNow)
					{
						return new AuthResult()
						{
							Result = false,
							Errors = new List<string>() { "Expired Token" }
						};
					}

					storedToken.IsUsed = true;
					_appDbContext.RefreshTokens.Update(storedToken);
					await _appDbContext.SaveChangesAsync();

					var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
					response= await GenerateJwtToken(dbUser);
				}
				return response;
			}
			catch (Exception)
			{

				return new AuthResult()
				{
					Result = false,
					Errors = new List<string>() { "Server Error" }
				};
			}
		}

		[ApiExplorerSettings(IgnoreApi = true)]
		private DateTime UnixTimeStampToDateTime(long utcExpiryDate)
		{
            var dateTimeValue = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeValue = dateTimeValue.AddSeconds(utcExpiryDate).ToUniversalTime();
            return dateTimeValue;

        }

		[ApiExplorerSettings(IgnoreApi = true)]
		private string RandomStringeGenerator(int length)
		{
			var random = new Random();
			var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_";
			return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
		}
	}
}
