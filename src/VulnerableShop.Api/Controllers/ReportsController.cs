using Microsoft.AspNetCore.Mvc;
using VulnerableShop.Api.Data;
using VulnerableShop.Api.Models;
using VulnerableShop.Api.Services;

namespace VulnerableShop.Api.Controllers;

[ApiController]
[Route("api/reports")]
public class ReportsController(ReportQueryBuilder reports, AuditService audit) : ControllerBase
{
    [HttpPost("filtered")]
    public async Task<IActionResult> Filtered([FromBody] ReportFilter filter)
        => Ok(await reports.RunFilteredReportAsync(filter));

    [HttpGet("export")]
    public async Task<IActionResult> Export([FromQuery] string table, [FromQuery] int limit)
        => Ok(await reports.ExportTableAsync(table, limit));

    [HttpGet("named")]
    public async Task<IActionResult> Named([FromQuery] string reportName)
        => Ok(await reports.RunNamedReportAsync(reportName));

    [HttpPost("audit/reconcile/{customerId}")]
    public async Task<IActionResult> Reconcile([FromRoute] int customerId, CancellationToken cancellationToken)
        => Ok(await audit.ReconcileCustomerNotesAsync(customerId, cancellationToken));

    [HttpDelete("audit")]
    public async Task<IActionResult> Archive([FromQuery] int days, CancellationToken cancellationToken)
        => Ok(await audit.ArchiveOlderThanAsync(days, cancellationToken));
}
