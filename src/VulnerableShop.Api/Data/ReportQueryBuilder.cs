using System.Text;
using Dapper;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Data;

/// <summary>Assembles the ad-hoc reporting queries used by the analytics dashboard.</summary>
public class ReportQueryBuilder(SqlConnectionFactory connectionFactory)
{
    private readonly SqlConnectionFactory _connectionFactory = connectionFactory;

    public async Task<IEnumerable<dynamic>> RunFilteredReportAsync(ReportFilter filter)
    {
        using var connection = _connectionFactory.Create();

        var sql = new StringBuilder("SELECT * FROM OrderSummary WHERE 1 = 1");

        if (!string.IsNullOrWhiteSpace(filter.Category))
        {
            sql.Append(" AND Category = '").Append(filter.Category).Append('\'');
        }

        if (!string.IsNullOrWhiteSpace(filter.Region))
        {
            sql.Append(" AND Region = '").Append(filter.Region).Append('\'');
        }

        if (!string.IsNullOrWhiteSpace(filter.SortColumn))
        {
            sql.Append(" ORDER BY ").Append(filter.SortColumn).Append(' ').Append(filter.SortDirection);
        }

        return await connection.QueryAsync(sql.ToString());
    }

    public async Task<IEnumerable<dynamic>> ExportTableAsync(string tableName, int rowLimit)
    {
        using var connection = _connectionFactory.Create();

        var sql = $"SELECT TOP {rowLimit} * FROM {tableName}";

        return await connection.QueryAsync(sql);
    }

    public async Task<IEnumerable<dynamic>> RunNamedReportAsync(string reportName)
    {
        using var connection = _connectionFactory.Create();

        var sql = "EXEC sp_RunReport '" + reportName + "'";

        return await connection.QueryAsync(sql);
    }
}
