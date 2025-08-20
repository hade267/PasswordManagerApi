using Microsoft.EntityFrameworkCore;
using PasswordManagerApi.Models;

namespace PasswordManagerApi.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            // set long text for MySql
            modelBuilder.Entity<User>(entity =>
            {
                entity.Property(e => e.Username).HasColumnType("longtext");
                entity.Property(e => e.MasterPasswordHash).HasColumnType("longtext");
                entity.Property(e => e.EncryptedVault).HasColumnType("longtext");
                entity.Property(e => e.MFASecret).HasColumnType("longtext");
            });
        }
    }
}