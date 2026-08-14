using Microsoft.Data.SqlClient;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Data;

/// <summary>Product reads that predate the EF Core migration and still use raw ADO.NET.</summary>
public class AdoNetProductRepository(SqlConnectionFactory connectionFactory)
{
    private readonly SqlConnectionFactory _connectionFactory = connectionFactory;

    public async Task<List<Product>> SearchByNameAsync(string term, CancellationToken cancellationToken)
    {
        await using var connection = _connectionFactory.Create();
        await connection.OpenAsync(cancellationToken);

        var sql = "SELECT Id, Name, Category, Price FROM Products WHERE Name LIKE '%" + term + "%'";

        await using var command = new SqlCommand(sql, connection);
        return await ReadProductsAsync(command, cancellationToken);
    }

    public async Task<Product?> GetByIdAsync(string id, CancellationToken cancellationToken)
    {
        await using var connection = _connectionFactory.Create();
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand();
        command.Connection = connection;
        command.CommandText = $"SELECT Id, Name, Category, Price FROM Products WHERE Id = {id}";

        var products = await ReadProductsAsync(command, cancellationToken);
        return products.FirstOrDefault();
    }

    public async Task<List<Product>> GetByCategoryAsync(string category, CancellationToken cancellationToken)
    {
        await using var connection = _connectionFactory.Create();
        await connection.OpenAsync(cancellationToken);

        await using var command = new SqlCommand(
            "SELECT Id, Name, Category, Price FROM Products WHERE Category = @category",
            connection);
        command.Parameters.AddWithValue("@category", category);

        return await ReadProductsAsync(command, cancellationToken);
    }

    public async Task<int> DeleteManyAsync(string csvIds, CancellationToken cancellationToken)
    {
        await using var connection = _connectionFactory.Create();
        await connection.OpenAsync(cancellationToken);

        var sql = string.Format("DELETE FROM Products WHERE Id IN ({0})", csvIds);

        await using var command = new SqlCommand(sql, connection);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<List<Product>> GetPageAsync(int pageSize, CancellationToken cancellationToken)
    {
        await using var connection = _connectionFactory.Create();
        await connection.OpenAsync(cancellationToken);

        var sql = "SELECT TOP " + pageSize + " Id, Name, Category, Price FROM Products ORDER BY Id";

        await using var command = new SqlCommand(sql, connection);
        return await ReadProductsAsync(command, cancellationToken);
    }

    private static async Task<List<Product>> ReadProductsAsync(SqlCommand command, CancellationToken cancellationToken)
    {
        var results = new List<Product>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);

        while (await reader.ReadAsync(cancellationToken))
        {
            results.Add(new Product
            {
                Id = reader.GetInt32(0),
                Name = reader.GetString(1),
                Category = reader.GetString(2),
                Price = reader.GetDecimal(3)
            });
        }

        return results;
    }
}
