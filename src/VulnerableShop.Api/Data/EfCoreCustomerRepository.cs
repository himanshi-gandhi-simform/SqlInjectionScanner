using Microsoft.EntityFrameworkCore;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Data;

/// <summary>Customer lookups. Some paths drop to raw SQL for query-plan reasons.</summary>
public class EfCoreCustomerRepository(ShopDbContext dbContext)
{
    private readonly ShopDbContext _dbContext = dbContext;

    public async Task<Customer?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        return await _dbContext.Customers
            .FromSqlRaw("SELECT * FROM Customers WHERE Email = '" + email + "'")
            .FirstOrDefaultAsync(cancellationToken);
    }

    public async Task<List<Customer>> FindByCityAsync(string city, CancellationToken cancellationToken)
    {
        return await _dbContext.Customers
            .FromSql($"SELECT * FROM Customers WHERE City = {city}")
            .ToListAsync(cancellationToken);
    }

    public async Task<int> DeactivateByRegionAsync(string region, CancellationToken cancellationToken)
    {
        return await _dbContext.Database.ExecuteSqlRawAsync(
            $"UPDATE Customers SET IsActive = 0 WHERE Region = '{region}'",
            cancellationToken);
    }

    public async Task<List<Customer>> SearchNotesAsync(string keyword, CancellationToken cancellationToken)
    {
        var sql = "SELECT * FROM Customers WHERE Notes LIKE '%" + keyword + "%' AND IsActive = 1";

        return await _dbContext.Customers
            .FromSqlRaw(sql)
            .ToListAsync(cancellationToken);
    }
}
