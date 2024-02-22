using ASPDotNetCRUDApp.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ASPDotNetCRUDApp.Data
{
    public class AppDbContext:IdentityDbContext
    {
        public DbSet<Team> Teams { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        public AppDbContext(DbContextOptions<AppDbContext> options):base(options) 
        {
            
        }
    }
}
