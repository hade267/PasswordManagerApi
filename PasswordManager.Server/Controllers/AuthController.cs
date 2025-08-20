using Microsoft.AspNetCore.Mvc;
using PasswordManagerApi.Models;
using PasswordManagerApi.Data;
using BCrypt.Net;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using OtpNet;
using Microsoft.AspNetCore.RateLimiting;
using Serilog;

namespace PasswordManagerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableRateLimiting("fixed")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ApplicationDbContext context, IConfiguration config, ILogger<AuthController> logger)
        {
            _context = context;
            _config = config;
            _logger = logger;
        }

        // POST: api/auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            _logger.LogInformation("Register attempt for username: {Username}", dto.Username);

            if (_context.Users.Any(u => u.Username == dto.Username))
                return BadRequest("Username already exists.");

            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(dto.MasterPassword);

            // Tạo MFA secret nhưng không enable
            var secret = KeyGeneration.GenerateRandomKey(20);
            var mfaSecret = Base32Encoding.ToString(secret);

            var user = new User
            {
                Username = dto.Username,
                MasterPasswordHash = hashedPassword,
                EncryptedVault = "",
                MFASecret = mfaSecret,
                IsMfaEnabled = false  // Mặc định tắt
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return Ok(new { Message = "User registered. MFA is disabled by default. Use /enable-mfa to enable." });
        }

        // POST: api/auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            _logger.LogInformation("Login attempt for username: {Username}", dto.Username);

            var user = _context.Users.FirstOrDefault(u => u.Username == dto.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.MasterPassword, user.MasterPasswordHash))
                return Unauthorized("Invalid credentials.");

            // Verify MFA chỉ nếu enabled
            if (user.IsMfaEnabled)
            {
                if (string.IsNullOrEmpty(dto.MfaCode))
                    return BadRequest("MFA code required.");

                var totp = new Totp(Base32Encoding.ToBytes(user.MFASecret));
                if (!totp.VerifyTotp(dto.MfaCode, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay))
                    return Unauthorized("Invalid MFA code.");
            }

            // Tạo JWT token
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        // GET: api/auth/user-info (Lấy status MFA và secret cho QR)
        [Authorize]
        [HttpGet("user-info")]
        public IActionResult GetUserInfo()
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = _context.Users.Find(userId);
            if (user == null) return NotFound();

            return Ok(new
            {
                IsMfaEnabled = user.IsMfaEnabled,
                MFASecret = user.MFASecret  // Trả secret để client generate QR
            });
        }

        // POST: api/auth/enable-mfa (Enable MFA, require verify code)
        [Authorize]
        [HttpPost("enable-mfa")]
        public async Task<IActionResult> EnableMfa([FromBody] MfaDto dto)
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = _context.Users.Find(userId);
            if (user == null) return NotFound();

            if (user.IsMfaEnabled) return BadRequest("MFA already enabled.");

            // Verify code để confirm setup
            var totp = new Totp(Base32Encoding.ToBytes(user.MFASecret));
            if (!totp.VerifyTotp(dto.MfaCode, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay))
                return BadRequest("Invalid MFA code for verification.");

            user.IsMfaEnabled = true;
            await _context.SaveChangesAsync();
            return Ok("MFA enabled.");
        }

        // POST: api/auth/disable-mfa (Disable MFA)
        [Authorize]
        [HttpPost("disable-mfa")]
        public async Task<IActionResult> DisableMfa()
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = _context.Users.Find(userId);
            if (user == null) return NotFound();

            if (!user.IsMfaEnabled) return BadRequest("MFA already disabled.");

            user.IsMfaEnabled = false;
            await _context.SaveChangesAsync();
            return Ok("MFA disabled.");
        }

        // GET: api/auth/vault
        [Authorize]
        [HttpGet("vault")]
        public IActionResult GetVault()
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = _context.Users.Find(userId);
            return Ok(user?.EncryptedVault ?? "");
        }

        // POST: api/auth/vault
        [Authorize]
        [HttpPost("vault")]
        public async Task<IActionResult> UpdateVault([FromBody] string encryptedVault)
        {
            var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier));
            var user = _context.Users.Find(userId);
            if (user == null) return NotFound();

            user.EncryptedVault = encryptedVault;
            await _context.SaveChangesAsync();
            return Ok("Vault updated.");
        }

    }

    public class RegisterDto
    {
        public string Username { get; set; } = string.Empty;
        public string MasterPassword { get; set; } = string.Empty;
    }

    public class LoginDto
    {
        public string Username { get; set; } = string.Empty;
        public string MasterPassword { get; set; } = string.Empty;
        public string MfaCode { get; set; } = string.Empty;  // Optional nếu MFA tắt
    }

    public class MfaDto
    {
        public string MfaCode { get; set; } = string.Empty;
    }
}