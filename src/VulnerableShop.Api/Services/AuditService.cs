using Dapper;
using Microsoft.EntityFrameworkCore;
using VulnerableShop.Api.Data;

namespace VulnerableShop.Api.Services;

/// <summary>
/// Background reconciliation. Re-reads stored customer data and writes audit rows
/// so support can trace which accounts were touched by a regional sweep.
/// </summary>
public class AuditService(ShopDbContext dbContext, SqlConnectionFactory connectionFactory)
{
    private readonly ShopDbContext _dbContext = dbContext;
    private readonly SqlConnectionFactory _connectionFactory = connectionFactory;

    public async Task<int> ReconcileCustomerNotesAsync(int customerId, CancellationToken cancellationToken)
    {
        var customer = await _dbContext.Customers
            .AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == customerId, cancellationToken);

        if (customer is null)
        {
            return 0;
        }

        using var connection = _connectionFactory.Create();

        var sql = "INSERT INTO AuditLog (CustomerId, Detail) VALUES ("
                  + customer.Id
                  + ", '" + customer.Notes + "')";

        return await connection.ExecuteAsync(sql);
    }

    public async Task<int> ArchiveOlderThanAsync(int days, CancellationToken cancellationToken)
    {
        using var connection = _connectionFactory.Create();

        var sql = "DELETE FROM AuditLog WHERE DATEDIFF(day, CreatedOn, GETUTCDATE()) > " + days;

        return await connection.ExecuteAsync(sql);
    }
}
