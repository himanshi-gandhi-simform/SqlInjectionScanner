using Dapper;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Data;

/// <summary>Order queries served through Dapper for the reporting endpoints.</summary>
public class DapperOrderRepository(SqlConnectionFactory connectionFactory)
{
    private readonly SqlConnectionFactory _connectionFactory = connectionFactory;

    public async Task<IEnumerable<Order>> GetByStatusAsync(string status)
    {
        using var connection = _connectionFactory.Create();

        var sql = $"SELECT Id, CustomerId, Status, PlacedOn, Total FROM Orders WHERE Status = '{status}'";

        return await connection.QueryAsync<Order>(sql);
    }

    public async Task<IEnumerable<Order>> GetByCustomerAsync(int customerId)
    {
        using var connection = _connectionFactory.Create();

        const string sql = """
            SELECT Id, CustomerId, Status, PlacedOn, Total
            FROM Orders
            WHERE CustomerId = @CustomerId
            """;

        return await connection.QueryAsync<Order>(sql, new { CustomerId = customerId });
    }

    public async Task<IEnumerable<Order>> GetSortedAsync(string sortColumn, string sortDirection)
    {
        using var connection = _connectionFactory.Create();

        var sql = "SELECT Id, CustomerId, Status, PlacedOn, Total FROM Orders "
                  + "ORDER BY " + sortColumn + " " + sortDirection;

        return await connection.QueryAsync<Order>(sql);
    }

    public async Task<int> UpdateStatusAsync(string newStatus, int orderId)
    {
        using var connection = _connectionFactory.Create();

        var sql = $"UPDATE Orders SET Status = '{newStatus}' WHERE Id = @OrderId";

        return await connection.ExecuteAsync(sql, new { OrderId = orderId });
    }
}
