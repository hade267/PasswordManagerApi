using System.ComponentModel.DataAnnotations;

namespace PasswordManagerApi.Models
{
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Username { get; set; } = string.Empty;

        [Required]
        public string MasterPasswordHash { get; set; } = string.Empty;

        public string EncryptedVault { get; set; } = string.Empty;

        public string MFASecret { get; set; } = string.Empty;
    }
}