using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Data;

public class ShopDbContext(DbContextOptions<ShopDbContext> options) : DbContext(options)
{
    public DbSet<Product> Products => Set<Product>();
    public DbSet<Order> Orders => Set<Order>();
    public DbSet<Customer> Customers => Set<Customer>();
}

/// <summary>Hands out connections for the repositories that talk to ADO.NET directly.</summary>
public class SqlConnectionFactory(string connectionString)
{
    private readonly string _connectionString = connectionString;

    public SqlConnection Create() => new(_connectionString);
}
