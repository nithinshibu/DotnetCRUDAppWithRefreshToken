using System.ComponentModel.DataAnnotations;

namespace ASPDotNetCRUDApp.DTOs
{
	public class TokenRequest
	{
        [Required]
        public string Token { get; set; }
        [Required]  
        public string RefreshToken { get; set; }
    }
}
