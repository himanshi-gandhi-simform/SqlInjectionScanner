using Microsoft.AspNetCore.Mvc;
using VulnerableShop.Api.Data;
using VulnerableShop.Api.Models;

namespace VulnerableShop.Api.Controllers;

[ApiController]
[Route("api/catalog")]
public class CatalogController(
    AdoNetProductRepository products,
    DapperOrderRepository orders,
    EfCoreCustomerRepository customers) : ControllerBase
{
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string term, CancellationToken cancellationToken)
        => Ok(await products.SearchByNameAsync(term, cancellationToken));

    [HttpGet("products/{id}")]
    public async Task<IActionResult> GetProduct([FromRoute] string id, CancellationToken cancellationToken)
        => Ok(await products.GetByIdAsync(id, cancellationToken));

    [HttpGet("products/by-category")]
    public async Task<IActionResult> ByCategory([FromQuery] string category, CancellationToken cancellationToken)
        => Ok(await products.GetByCategoryAsync(category, cancellationToken));

    [HttpDelete("products")]
    public async Task<IActionResult> DeleteProducts([FromQuery] string ids, CancellationToken cancellationToken)
        => Ok(await products.DeleteManyAsync(ids, cancellationToken));

    [HttpGet("products/page")]
    public async Task<IActionResult> Page([FromQuery] int pageSize, CancellationToken cancellationToken)
        => Ok(await products.GetPageAsync(pageSize, cancellationToken));

    [HttpGet("orders")]
    public async Task<IActionResult> OrdersByStatus([FromQuery] string status)
        => Ok(await orders.GetByStatusAsync(status));

    [HttpGet("orders/sorted")]
    public async Task<IActionResult> OrdersSorted([FromQuery] string sortColumn, [FromQuery] string sortDirection)
        => Ok(await orders.GetSortedAsync(sortColumn, sortDirection));

    [HttpPost("orders/{id}/status")]
    public async Task<IActionResult> SetStatus([FromRoute] int id, [FromBody] string status)
        => Ok(await orders.UpdateStatusAsync(status, id));

    [HttpGet("customers/by-email")]
    public async Task<IActionResult> CustomerByEmail([FromQuery] string email, CancellationToken cancellationToken)
        => Ok(await customers.FindByEmailAsync(email, cancellationToken));

    [HttpGet("customers/by-city")]
    public async Task<IActionResult> CustomerByCity([FromQuery] string city, CancellationToken cancellationToken)
        => Ok(await customers.FindByCityAsync(city, cancellationToken));

    [HttpPost("customers/deactivate")]
    public async Task<IActionResult> Deactivate([FromBody] string region, CancellationToken cancellationToken)
        => Ok(await customers.DeactivateByRegionAsync(region, cancellationToken));

    [HttpGet("customers/notes")]
    public async Task<IActionResult> SearchNotes([FromQuery] string keyword, CancellationToken cancellationToken)
        => Ok(await customers.SearchNotesAsync(keyword, cancellationToken));
}
